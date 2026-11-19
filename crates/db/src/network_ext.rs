// SPDX-License-Identifier: Apache-2.0
//! What the bridge networks keep about containers: the address of each
//! container on each network (IPAM), the network settings of the container
//! (published ports, MAC address...) and the addresses of the pooled
//! network namespaces.
//!
//! `network_id` has no foreign key: the default network is not a row of
//! `networks`.  `network rm` removes the attachments of the network.

use super::{volatile, Database};
use rusqlite::{OptionalExtension, TransactionBehavior};
use std::net::{Ipv4Addr, Ipv6Addr};
use velarx_types::{DbError, DbResult};

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS network_attachments (
    container_id TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
    network_id TEXT NOT NULL,
    idx INTEGER NOT NULL,
    ip TEXT,
    aliases TEXT NOT NULL DEFAULT '[]',
    ip6 TEXT,
    PRIMARY KEY (container_id, network_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_network_attachments_ip ON network_attachments(network_id, ip);
CREATE INDEX IF NOT EXISTS idx_network_attachments_network ON network_attachments(network_id);
CREATE TABLE IF NOT EXISTS network_containers (
    container_id TEXT PRIMARY KEY REFERENCES containers(id) ON DELETE CASCADE,
    spec TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS netns_pool (
    slot TEXT NOT NULL,
    network_id TEXT NOT NULL,
    idx INTEGER NOT NULL,
    ip TEXT NOT NULL,
    ip6 TEXT,
    PRIMARY KEY (slot, network_id)
);
CREATE INDEX IF NOT EXISTS idx_netns_pool_ip ON netns_pool(network_id, ip);
CREATE UNIQUE INDEX IF NOT EXISTS idx_network_attachments_ip6 ON network_attachments(network_id, ip6);
-- The host ports picked for the published ports given without one (`-p 80`):
-- one container each, from the create to the removal.
CREATE TABLE IF NOT EXISTS host_ports (
    container_id TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
    host_ip TEXT NOT NULL,
    proto TEXT NOT NULL,
    port INTEGER NOT NULL,
    PRIMARY KEY (host_ip, proto, port)
);
CREATE INDEX IF NOT EXISTS idx_host_ports_container ON host_ports(container_id);
-- The last address given on a network: the next is the one after it, as in
-- podman's IPAM (`getFreeIPFromBucket` of netavark's, its `lastIP`), so
-- that the address of a container that just went is not given again while
-- the host side of its network may still be there (the kernel takes a
-- namespace down on its own time) or the neighbours still have its old
-- link address.
CREATE TABLE IF NOT EXISTS network_ipam (
    network_id TEXT PRIMARY KEY,
    last_ip TEXT,
    last_ip6 TEXT
);
";

/// A container on a network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentRow {
    pub container_id: String,
    pub network_id: String,
    /// The interface is `eth<idx>`.
    pub idx: u32,
    /// None while a pooled namespace has it.
    pub ip: Option<Ipv4Addr>,
    pub aliases: Vec<String>,
    /// On a dual-stack network.
    pub ip6: Option<Ipv6Addr>,
}

/// The addresses an allocation may pick: FIRST..=LAST but EXCLUDED, or
/// exactly REQUESTED.
#[derive(Debug, Clone)]
pub struct IpChoice {
    pub requested: Option<Ipv4Addr>,
    pub first: Ipv4Addr,
    pub last: Ipv4Addr,
    pub excluded: Vec<Ipv4Addr>,
    /// The IPv6 address too, on a dual-stack network.
    pub v6: Option<Ip6Choice>,
    /// The network is a row of `networks` (the default network of the
    /// configuration is none): the attachment is refused when it is gone.
    pub registered: bool,
}

/// The IPv6 addresses an allocation may pick: from FIRST on (at most
/// `IP6_SCAN` of them) up to LAST but EXCLUDED, or exactly REQUESTED.
#[derive(Debug, Clone)]
pub struct Ip6Choice {
    pub requested: Option<Ipv6Addr>,
    pub first: Ipv6Addr,
    pub last: Ipv6Addr,
    pub excluded: Vec<Ipv6Addr>,
}

/// How many IPv6 addresses an allocation looks at, at most.
const IP6_SCAN: u128 = 1 << 20;

/// The value `value` of the column `name` (number `col`) of a network
/// attachment that cannot be read back: the row is damaged, and reading it
/// as empty would hand its address out again.
fn corrupt(col: usize, name: &str, value: &str, e: impl std::fmt::Display) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        col,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::other(format!(
            "the database has `{value}` as the {name} of a network attachment, which is damaged: {e}"
        ))),
    )
}

/// The address in column `col` (`name`), if the row has one.
fn address<A: std::str::FromStr>(
    row: &rusqlite::Row<'_>,
    col: usize,
    name: &str,
) -> rusqlite::Result<Option<A>>
where
    A::Err: std::fmt::Display,
{
    row.get::<_, Option<String>>(col)?
        .map(|s| s.parse().map_err(|e| corrupt(col, name, &s, e)))
        .transpose()
}

fn row_to_attachment(row: &rusqlite::Row<'_>) -> rusqlite::Result<AttachmentRow> {
    let aliases: String = row.get(4)?;
    Ok(AttachmentRow {
        container_id: row.get(0)?,
        network_id: row.get(1)?,
        idx: row.get::<_, i64>(2)?.clamp(0, i64::from(u32::MAX)) as u32,
        ip: address(row, 3, "ip")?,
        aliases: serde_json::from_str(&aliases).map_err(|e| corrupt(4, "aliases", &aliases, e))?,
        ip6: address(row, 5, "ip6")?,
    })
}

const ATTACHMENT_COLUMNS: &str = "container_id, network_id, idx, ip, aliases, ip6";

/// The addresses `first..=last` as numbers, from the one after `after` (the
/// last given) on, then from the first up to it: an address is given again
/// only when all the others were.
fn from_after(first: u128, last: u128, after: Option<u128>) -> impl Iterator<Item = u128> {
    let start = after
        .filter(|a| (first..last).contains(a))
        .map_or(first, |a| a + 1);
    (start..=last).chain(first..start)
}

/// The last address given on the network, in the column `column` of its
/// row.
fn last_given<A: std::str::FromStr>(
    tx: &rusqlite::Transaction<'_>,
    network_id: &str,
    column: &'static str,
) -> rusqlite::Result<Option<A>> {
    let value: Option<Option<String>> = tx
        .query_row(
            &format!("SELECT {column} FROM network_ipam WHERE network_id = ?1"),
            [network_id],
            |r| r.get(0),
        )
        .optional()?;
    match value.flatten() {
        None => Ok(None),
        Some(text) => text
            .parse()
            .map(Some)
            .map_err(|_| corrupt(0, column, &text, "not an address")),
    }
}

/// Note `ip` as the last address given on the network.
fn remember(
    tx: &rusqlite::Transaction<'_>,
    network_id: &str,
    column: &'static str,
    ip: impl std::fmt::Display,
) -> rusqlite::Result<()> {
    tx.execute(
        &format!(
            "INSERT INTO network_ipam (network_id, {column}) VALUES (?1, ?2)
             ON CONFLICT(network_id) DO UPDATE SET {column} = excluded.{column}"
        ),
        rusqlite::params![network_id, ip.to_string()],
    )?;
    Ok(())
}

/// The first address of CHOICE after the last one given that neither an
/// attachment nor a pooled namespace of the network has.
fn pick_ip(
    tx: &rusqlite::Transaction<'_>,
    network_id: &str,
    choice: &IpChoice,
) -> rusqlite::Result<Option<Ipv4Addr>> {
    let mut used = std::collections::HashSet::new();
    let mut stmt = tx.prepare(
        "SELECT ip FROM network_attachments WHERE network_id = ?1 AND ip IS NOT NULL
         UNION SELECT ip FROM netns_pool WHERE network_id = ?1",
    )?;
    for ip in stmt.query_map([network_id], |r| address::<Ipv4Addr>(r, 0, "ip"))? {
        used.extend(ip?);
    }
    if let Some(r) = choice.requested {
        return Ok((!used.contains(&r)).then_some(r));
    }
    let after =
        last_given::<Ipv4Addr>(tx, network_id, "last_ip")?.map(|a| u128::from(u32::from(a)));
    let (first, last) = (
        u128::from(u32::from(choice.first)),
        u128::from(u32::from(choice.last)),
    );
    let ip = from_after(first, last, after)
        .map(|n| Ipv4Addr::from(n as u32))
        .find(|ip| !used.contains(ip) && !choice.excluded.contains(ip));
    if let Some(ip) = ip {
        remember(tx, network_id, "last_ip", ip)?;
    }
    Ok(ip)
}

/// The first IPv6 address of CHOICE after the last one given that no
/// attachment of the network has.
fn pick_ip6(
    tx: &rusqlite::Transaction<'_>,
    network_id: &str,
    choice: &Ip6Choice,
) -> rusqlite::Result<Option<Ipv6Addr>> {
    let mut used = std::collections::HashSet::new();
    let mut stmt = tx
        .prepare("SELECT ip6 FROM network_attachments WHERE network_id = ?1 AND ip6 IS NOT NULL")?;
    for ip in stmt.query_map([network_id], |r| address::<Ipv6Addr>(r, 0, "ip6"))? {
        used.extend(ip?);
    }
    if let Some(r) = choice.requested {
        return Ok((!used.contains(&r)).then_some(r));
    }
    let after = last_given::<Ipv6Addr>(tx, network_id, "last_ip6")?.map(u128::from);
    let first = u128::from(choice.first);
    let last = u128::from(choice.last).min(first.saturating_add(IP6_SCAN));
    let ip = from_after(first, last, after)
        .map(Ipv6Addr::from)
        .find(|ip| !used.contains(ip) && !choice.excluded.contains(ip));
    if let Some(ip) = ip {
        remember(tx, network_id, "last_ip6", ip)?;
    }
    Ok(ip)
}

fn conflict(msg: String) -> tokio_rusqlite::Error {
    tokio_rusqlite::Error::Other(Box::new(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        msg,
    )))
}

fn map_err(e: tokio_rusqlite::Error) -> DbError {
    if let tokio_rusqlite::Error::Other(ref inner) = e {
        if let Some(io) = inner.downcast_ref::<std::io::Error>() {
            if io.kind() == std::io::ErrorKind::AlreadyExists {
                return DbError::AlreadyExists(io.to_string());
            }
            if io.kind() == std::io::ErrorKind::NotFound {
                return DbError::NotFound(io.to_string());
            }
        }
    }
    DbError::Sqlite(e)
}

impl Database {
    /// Attach the container to the network with an address of CHOICE, in
    /// one transaction: two containers never get the same address.
    pub async fn net_attach(
        &self,
        container_id: &str,
        network_id: &str,
        idx: u32,
        aliases: &[String],
        choice: IpChoice,
    ) -> DbResult<(Ipv4Addr, Option<Ipv6Addr>)> {
        let (container_id, network_id) = (container_id.to_string(), network_id.to_string());
        let aliases = serde_json::to_string(aliases)
            .map_err(|e| DbError::Sqlite(tokio_rusqlite::Error::Other(Box::new(e))))?;
        self.conn
            .call(move |conn| {
                let volatile = volatile::container(conn, &container_id);
                volatile::run(conn, volatile, |conn| {
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                if choice.registered {
                    let there = tx
                        .query_row(
                            "SELECT 1 FROM networks WHERE id = ?1",
                            [&network_id],
                            |_| Ok(()),
                        )
                        .optional()?;
                    if there.is_none() {
                        return Err(tokio_rusqlite::Error::Other(Box::new(
                            std::io::Error::new(
                                std::io::ErrorKind::NotFound,
                                format!("network {network_id} was removed"),
                            ),
                        )));
                    }
                }
                let Some(ip) = pick_ip(&tx, &network_id, &choice)? else {
                    return Err(conflict(match choice.requested {
                        Some(r) => format!("the address {r} is already used"),
                        None => "no free address in the network".to_string(),
                    }));
                };
                let ip6 = match &choice.v6 {
                    None => None,
                    Some(c6) => Some(pick_ip6(&tx, &network_id, c6)?.ok_or_else(|| {
                        conflict(match c6.requested {
                            Some(r) => format!("the address {r} is already used"),
                            None => "no free IPv6 address in the network".to_string(),
                        })
                    })?),
                };
                let n = tx.execute(
                    "INSERT INTO network_attachments (container_id, network_id, idx, ip, aliases, ip6)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT DO NOTHING",
                    rusqlite::params![
                        container_id,
                        network_id,
                        idx,
                        ip.to_string(),
                        aliases,
                        ip6.map(|i| i.to_string())
                    ],
                )?;
                if n == 0 {
                    return Err(conflict("the container is already on the network".into()));
                }
                tx.commit()?;
                Ok((ip, ip6))
                })
            })
            .await
            .map_err(map_err)
    }

    /// Record the host ports `ports` (address, protocol and port, "" for
    /// every address) as picked for the container: all or none, and no port
    /// of one container is another's.  [`DbError::AlreadyExists`] when one
    /// is taken.
    pub async fn net_reserve_host_ports(
        &self,
        container_id: &str,
        ports: &[(String, String, u16)],
    ) -> DbResult<()> {
        let (container_id, ports) = (container_id.to_string(), ports.to_vec());
        self.conn
            .call(move |conn| {
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                for (ip, proto, port) in &ports {
                    // (a port on every address is taken on each of them too)
                    let every = ip.is_empty() || ip == "0.0.0.0" || ip == "::";
                    let overlaps: bool = tx.query_row(
                        "SELECT EXISTS (SELECT 1 FROM host_ports WHERE proto = ?1 AND port = ?2
                         AND (?3 OR host_ip IN ('', '0.0.0.0', '::')))",
                        rusqlite::params![proto, port, every],
                        |r| r.get(0),
                    )?;
                    if overlaps {
                        return Err(conflict(format!("the host port {port}/{proto} is taken")));
                    }
                    let n = tx.execute(
                        "INSERT INTO host_ports (container_id, host_ip, proto, port)
                         VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING",
                        rusqlite::params![container_id, ip, proto, port],
                    )?;
                    if n == 0 {
                        return Err(conflict(format!("the host port {port}/{proto} is taken")));
                    }
                }
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(map_err)
    }

    /// Give the attachment a new address of CHOICE (it gave its own to a
    /// pooled namespace).
    pub async fn net_reassign(
        &self,
        container_id: &str,
        network_id: &str,
        choice: IpChoice,
    ) -> DbResult<Ipv4Addr> {
        let (container_id, network_id) = (container_id.to_string(), network_id.to_string());
        self.conn
            .call(move |conn| {
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let ip = pick_ip(&tx, &network_id, &choice)?
                    .ok_or_else(|| conflict("no free address in the network".into()))?;
                tx.execute(
                    "UPDATE network_attachments SET ip = ?3 WHERE container_id = ?1 AND network_id = ?2",
                    rusqlite::params![container_id, network_id, ip.to_string()],
                )?;
                tx.commit()?;
                Ok(ip)
            })
            .await
            .map_err(map_err)
    }

    pub async fn net_attachments_of_container(&self, id: &str) -> DbResult<Vec<AttachmentRow>> {
        let id = id.to_string();
        self.conn
            .call(move |conn| net_attachments_of_container(conn, &id))
            .await
            .map_err(DbError::Sqlite)
    }

    /// The attachments of each of `containers` (those that have some), in
    /// one query for every 500, the interfaces of a container in order.
    pub async fn net_attachments_of_containers(
        &self,
        containers: &[String],
    ) -> DbResult<std::collections::HashMap<String, Vec<AttachmentRow>>> {
        let containers = containers.to_vec();
        self.conn
            .call(move |conn| {
                let rows = crate::query_in(
                    conn,
                    &format!(
                        "SELECT {ATTACHMENT_COLUMNS} FROM network_attachments \
                         WHERE container_id IN ({{marks}}) ORDER BY container_id, idx"
                    ),
                    &containers,
                    row_to_attachment,
                )?;
                let mut out: std::collections::HashMap<String, Vec<AttachmentRow>> =
                    std::collections::HashMap::new();
                for row in rows {
                    out.entry(row.container_id.clone()).or_default().push(row);
                }
                Ok(out)
            })
            .await
            .map_err(DbError::Sqlite)
    }

    pub async fn net_attachments_of_network(
        &self,
        network_id: &str,
    ) -> DbResult<Vec<AttachmentRow>> {
        let id = network_id.to_string();
        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {ATTACHMENT_COLUMNS} FROM network_attachments WHERE network_id = ?1 ORDER BY container_id"
                ))?;
                let rows = stmt
                    .query_map([id], row_to_attachment)?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// Remove the attachment; false if there was none.
    pub async fn net_detach(&self, container_id: &str, network_id: &str) -> DbResult<bool> {
        let (c, n) = (container_id.to_string(), network_id.to_string());
        self.conn
            .call(move |conn| {
                let volatile = volatile::container(conn, &c);
                volatile::run(conn, volatile, |conn| {
                    Ok(conn.execute(
                        "DELETE FROM network_attachments WHERE container_id = ?1 AND network_id = ?2",
                        [c, n],
                    )? > 0)
                })
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// Remove every attachment of the network and its pooled addresses.
    pub async fn net_forget_network(&self, network_id: &str) -> DbResult<()> {
        let n = network_id.to_string();
        self.conn
            .call(move |conn| {
                let tx = conn.transaction()?;
                tx.execute(
                    "DELETE FROM network_attachments WHERE network_id = ?1",
                    [&n],
                )?;
                tx.execute("DELETE FROM netns_pool WHERE network_id = ?1", [&n])?;
                tx.execute("DELETE FROM network_ipam WHERE network_id = ?1", [&n])?;
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// The network settings of a container (JSON), kept with it.
    pub async fn net_set_container_spec(&self, container_id: &str, spec: &str) -> DbResult<()> {
        let (c, s) = (container_id.to_string(), spec.to_string());
        self.conn
            .call(move |conn| {
                let volatile = volatile::container(conn, &c);
                volatile::run(conn, volatile, |conn| {
                    conn.execute(
                        "INSERT INTO network_containers (container_id, spec) VALUES (?1, ?2)
                         ON CONFLICT(container_id) DO UPDATE SET spec = excluded.spec",
                        [c, s],
                    )?;
                    Ok(())
                })
            })
            .await
            .map_err(DbError::Sqlite)
    }

    pub async fn net_container_spec(&self, container_id: &str) -> DbResult<Option<String>> {
        let c = container_id.to_string();
        self.conn
            .call(move |conn| net_container_spec(conn, &c))
            .await
            .map_err(DbError::Sqlite)
    }

    /// The network setup of each of `containers` that has one, in one query
    /// for every 500.
    pub async fn net_container_specs(
        &self,
        containers: &[String],
    ) -> DbResult<std::collections::HashMap<String, String>> {
        let containers = containers.to_vec();
        self.conn
            .call(move |conn| {
                let rows = crate::query_in(
                    conn,
                    "SELECT container_id, spec FROM network_containers \
                     WHERE container_id IN ({marks})",
                    &containers,
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
                )?;
                Ok(rows.into_iter().collect())
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// Move the addresses of the container to the pooled namespace SLOT.
    pub async fn netns_pool_put(&self, slot: &str, container_id: &str) -> DbResult<()> {
        let (slot, c) = (slot.to_string(), container_id.to_string());
        self.conn
            .call(move |conn| netns_pool_put(conn, &slot, &c))
            .await
            .map_err(map_err)
    }

    /// Give the addresses of the pooled namespace SLOT to the container if
    /// it has the same networks on the same interfaces: false otherwise.
    pub async fn netns_pool_take(&self, slot: &str, container_id: &str) -> DbResult<bool> {
        let (slot, c) = (slot.to_string(), container_id.to_string());
        self.conn
            .call(move |conn| {
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let pooled: Vec<(String, i64, String)> = tx
                    .prepare("SELECT network_id, idx, ip FROM netns_pool WHERE slot = ?1 ORDER BY network_id")?
                    .query_map([&slot], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<Result<_, _>>()?;
                let mine: Vec<(String, i64)> = tx
                    .prepare(
                        "SELECT network_id, idx FROM network_attachments WHERE container_id = ?1 ORDER BY network_id",
                    )?
                    .query_map([&c], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<Result<_, _>>()?;
                let same = pooled.len() == mine.len()
                    && pooled.iter().zip(&mine).all(|(p, m)| p.0 == m.0 && p.1 == m.1);
                if !same || pooled.is_empty() {
                    return Ok(false);
                }
                tx.execute(
                    "UPDATE network_attachments SET ip = NULL WHERE container_id = ?1",
                    [&c],
                )?;
                tx.execute("DELETE FROM netns_pool WHERE slot = ?1", [&slot])?;
                for (net, _, ip) in &pooled {
                    tx.execute(
                        "UPDATE network_attachments SET ip = ?3 WHERE container_id = ?1 AND network_id = ?2",
                        [&c, net, ip],
                    )?;
                }
                tx.commit()?;
                Ok(true)
            })
            .await
            .map_err(map_err)
    }

    pub async fn netns_pool_remove(&self, slot: &str) -> DbResult<()> {
        let slot = slot.to_string();
        self.conn
            .call(move |conn| netns_pool_remove(conn, &slot))
            .await
            .map_err(DbError::Sqlite)
    }

    /// The pooled namespaces, of the network NETWORK_ID or all.
    pub async fn netns_pool_slots(&self, network_id: Option<&str>) -> DbResult<Vec<String>> {
        let n = network_id.map(String::from);
        self.conn
            .call(move |conn| netns_pool_slots(conn, n.as_deref()))
            .await
            .map_err(DbError::Sqlite)
    }
}

/// The SQL of `Database::net_attachments_of_container`, for a connection of any kind.
pub fn net_attachments_of_container(
    conn: &mut rusqlite::Connection,
    id: &str,
) -> Result<Vec<AttachmentRow>, tokio_rusqlite::Error> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {ATTACHMENT_COLUMNS} FROM network_attachments WHERE container_id = ?1 ORDER BY idx"
    ))?;
    let rows = stmt
        .query_map([id], row_to_attachment)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// The SQL of `Database::net_container_spec`, for a connection of any kind.
pub fn net_container_spec(
    conn: &mut rusqlite::Connection,
    c: &str,
) -> Result<Option<String>, tokio_rusqlite::Error> {
    Ok(conn
        .query_row(
            "SELECT spec FROM network_containers WHERE container_id = ?1",
            [c],
            |r| r.get(0),
        )
        .optional()?)
}

/// The SQL of `Database::netns_pool_put`, for a connection of any kind.
pub fn netns_pool_put(
    conn: &mut rusqlite::Connection,
    slot: &str,
    c: &str,
) -> Result<(), tokio_rusqlite::Error> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let n = tx.execute(
        "INSERT INTO netns_pool (slot, network_id, idx, ip)
             SELECT ?1, network_id, idx, ip FROM network_attachments
             WHERE container_id = ?2 AND ip IS NOT NULL",
        [&slot, &c],
    )?;
    if n == 0 {
        return Err(conflict("the container has no address to pool".into()));
    }
    tx.execute(
        "UPDATE network_attachments SET ip = NULL WHERE container_id = ?1",
        [&c],
    )?;
    tx.commit()?;
    Ok(())
}

/// The SQL of `Database::netns_pool_remove`, for a connection of any kind.
pub fn netns_pool_remove(
    conn: &mut rusqlite::Connection,
    slot: &str,
) -> Result<(), tokio_rusqlite::Error> {
    conn.execute("DELETE FROM netns_pool WHERE slot = ?1", [slot])?;
    Ok(())
}

/// The SQL of `Database::netns_pool_slots`, for a connection of any kind.
pub fn netns_pool_slots(
    conn: &mut rusqlite::Connection,
    n: Option<&str>,
) -> Result<Vec<String>, tokio_rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT slot FROM netns_pool WHERE ?1 IS NULL OR network_id = ?1 ORDER BY slot",
    )?;
    let rows = stmt
        .query_map([n], |r| r.get(0))?
        .collect::<Result<Vec<String>, _>>()?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ContainerRecord, RecordState};

    async fn db_with(ids: &[&str]) -> Database {
        let db = Database::open_in_memory().await.unwrap();
        db.insert_image(&crate::ImageRecord {
            id: "img".into(),
            manifest_digest: velarx_types::digest::Digest::of(
                velarx_types::digest::Algorithm::Sha256,
                b"m",
            ),
            config_digest: velarx_types::digest::Digest::of(
                velarx_types::digest::Algorithm::Sha256,
                b"c",
            ),
            manifest: "{}".into(),
            config: "{}".into(),
            created_at: "now".into(),
            is_lazy: false,
        })
        .await
        .unwrap();
        for id in ids {
            db.insert_container(&ContainerRecord {
                id: id.to_string(),
                name: Some(format!("n{id}")),
                image_id: "img".into(),
                config: "{}".into(),
                state: RecordState::Created,
                created_at: "now".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        }
        db
    }

    fn range(first: &str, last: &str, excluded: &[&str]) -> IpChoice {
        IpChoice {
            requested: None,
            first: first.parse().unwrap(),
            last: last.parse().unwrap(),
            excluded: excluded.iter().map(|s| s.parse().unwrap()).collect(),
            v6: None,
            registered: false,
        }
    }

    /// A host port picked on every address is taken on each address, and
    /// one picked on an address is taken for every address; the same port
    /// of another protocol, or on another address, is free.
    #[tokio::test]
    async fn a_host_port_on_every_address_overlaps_each_address() {
        let db = db_with(&["a", "b", "c", "d"]).await;
        let p = |ip: &str, proto: &str| vec![(ip.to_string(), proto.to_string(), 40000u16)];
        db.net_reserve_host_ports("a", &p("", "tcp")).await.unwrap();
        for ip in ["127.0.0.1", "0.0.0.0", ""] {
            assert!(matches!(
                db.net_reserve_host_ports("b", &p(ip, "tcp")).await,
                Err(DbError::AlreadyExists(_))
            ));
        }
        db.net_reserve_host_ports("b", &p("", "udp")).await.unwrap();
        db.net_reserve_host_ports("c", &p("127.0.0.2", "sctp"))
            .await
            .unwrap();
        db.net_reserve_host_ports("d", &p("127.0.0.3", "sctp"))
            .await
            .unwrap();
        assert!(db
            .net_reserve_host_ports("d", &p("", "sctp"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn dual_stack_addresses_are_unique() {
        let db = db_with(&["a", "b", "c"]).await;
        let r = || {
            let mut c = range("10.0.0.2", "10.0.0.9", &[]);
            c.v6 = Some(Ip6Choice {
                requested: None,
                first: "fd00::1".parse().unwrap(),
                last: "fd00::3".parse().unwrap(),
                excluded: vec!["fd00::1".parse().unwrap()],
            });
            c
        };
        let a = db.net_attach("a", "n", 0, &[], r()).await.unwrap();
        assert_eq!(a.1, Some("fd00::2".parse().unwrap()));
        let b = db.net_attach("b", "n", 0, &[], r()).await.unwrap();
        assert_eq!(b.1, Some("fd00::3".parse().unwrap()));
        // No IPv6 address left: nothing is attached.
        assert!(matches!(
            db.net_attach("c", "n", 0, &[], r()).await,
            Err(DbError::AlreadyExists(_))
        ));
        assert_eq!(db.net_attachments_of_network("n").await.unwrap().len(), 2);
        let mut fixed = r();
        fixed.v6.as_mut().unwrap().requested = Some("fd00::2".parse().unwrap());
        assert!(db.net_attach("c", "m", 0, &[], fixed.clone()).await.is_ok());
        let rows = db.net_attachments_of_container("a").await.unwrap();
        assert_eq!(rows[0].ip6, Some("fd00::2".parse().unwrap()));
        db.delete_container("a").await.unwrap();
        fixed.v6.as_mut().unwrap().requested = None;
        assert_eq!(
            db.net_attach("c", "n", 0, &[], fixed).await.unwrap().1,
            Some("fd00::2".parse().unwrap())
        );
    }

    /// The batched reads give what the reads of one container give, for any
    /// number of containers (over the 500 of a query).
    #[tokio::test]
    async fn the_rows_of_many_containers_are_read_together() {
        let names: Vec<String> = (0..620).map(|n| format!("c{n}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let db = db_with(&refs).await;
        for (n, name) in names.iter().enumerate().filter(|(n, _)| n % 3 != 0) {
            db.net_attach(name, "n", 0, &[], range("10.0.0.2", "10.255.0.9", &[]))
                .await
                .unwrap();
            db.net_attach(name, "m", 1, &[], range("10.0.0.2", "10.255.0.9", &[]))
                .await
                .unwrap();
            db.net_set_container_spec(name, &format!("{{\"n\":{n}}}"))
                .await
                .unwrap();
        }
        let attachments = db.net_attachments_of_containers(&names).await.unwrap();
        let specs = db.net_container_specs(&names).await.unwrap();
        assert_eq!(attachments.len(), specs.len());
        for (n, name) in names.iter().enumerate() {
            if n % 3 == 0 {
                assert!(!attachments.contains_key(name) && !specs.contains_key(name));
                continue;
            }
            assert_eq!(
                attachments[name],
                db.net_attachments_of_container(name).await.unwrap()
            );
            assert_eq!(
                attachments[name].iter().map(|r| r.idx).collect::<Vec<_>>(),
                [0, 1]
            );
            assert_eq!(
                Some(&specs[name]),
                db.net_container_spec(name).await.unwrap().as_ref()
            );
        }
        assert!(db
            .net_attachments_of_containers(&[])
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn addresses_are_unique_and_freed_with_the_container() {
        let db = db_with(&["a", "b", "c", "d"]).await;
        let r = || range("10.0.0.1", "10.0.0.3", &["10.0.0.1"]);
        assert_eq!(
            db.net_attach("a", "n", 0, &[], r()).await.unwrap().0,
            Ipv4Addr::new(10, 0, 0, 2)
        );
        assert_eq!(
            db.net_attach("b", "n", 0, &["x".into()], r())
                .await
                .unwrap()
                .0,
            Ipv4Addr::new(10, 0, 0, 3)
        );
        assert!(matches!(
            db.net_attach("c", "n", 0, &[], r()).await,
            Err(DbError::AlreadyExists(_))
        ));
        // Another network has its own addresses.
        assert_eq!(
            db.net_attach("c", "m", 1, &[], r()).await.unwrap().0,
            Ipv4Addr::new(10, 0, 0, 2)
        );
        assert!(matches!(
            db.net_attach("c", "m", 1, &[], r()).await,
            Err(DbError::AlreadyExists(_))
        ));
        let mut fixed = r();
        fixed.requested = Some(Ipv4Addr::new(10, 0, 0, 3));
        assert!(db.net_attach("d", "n", 0, &[], fixed).await.is_err());

        let rows = db.net_attachments_of_network("n").await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].aliases, vec!["x".to_string()]);
        db.delete_container("a").await.unwrap();
        assert_eq!(
            db.net_attach("d", "n", 0, &[], r()).await.unwrap().0,
            Ipv4Addr::new(10, 0, 0, 2)
        );
        assert!(db.net_detach("d", "n").await.unwrap());
        assert!(!db.net_detach("d", "n").await.unwrap());
    }

    /// The address of a container that went is not given again while there
    /// is another one (the host side of its network may still be there):
    /// the next is the one after the last given, and the first again after
    /// the last of the range; an address asked for does not move that, and
    /// a network that goes forgets it.
    #[tokio::test]
    async fn a_released_address_is_given_again_after_the_others() {
        let db = db_with(&["a", "b", "c", "d", "e", "f", "g"]).await;
        let r = || {
            let mut c = range("10.0.0.1", "10.0.0.5", &["10.0.0.1"]);
            c.v6 = Some(Ip6Choice {
                requested: None,
                first: "fd00::1".parse().unwrap(),
                last: "fd00::4".parse().unwrap(),
                excluded: vec!["fd00::1".parse().unwrap()],
            });
            c
        };
        let got = |a: (Ipv4Addr, Option<Ipv6Addr>)| (a.0.octets()[3], a.1.map(|i| i.segments()[7]));
        assert_eq!(
            got(db.net_attach("a", "n", 0, &[], r()).await.unwrap()),
            (2, Some(2))
        );
        db.delete_container("a").await.unwrap();
        // (not .2 again)
        assert_eq!(
            got(db.net_attach("b", "n", 0, &[], r()).await.unwrap()),
            (3, Some(3))
        );
        db.delete_container("b").await.unwrap();
        // an address asked for is not the last given
        let mut fixed = r();
        fixed.requested = Some("10.0.0.5".parse().unwrap());
        fixed.v6.as_mut().unwrap().requested = Some("fd00::4".parse().unwrap());
        assert_eq!(
            got(db.net_attach("c", "n", 0, &[], fixed).await.unwrap()),
            (5, Some(4))
        );
        assert_eq!(
            got(db.net_attach("d", "n", 0, &[], r()).await.unwrap()),
            (4, Some(2))
        );
        db.delete_container("c").await.unwrap();
        // the end of the range: from its start again
        assert_eq!(
            got(db.net_attach("e", "n", 0, &[], r()).await.unwrap()),
            (5, Some(3))
        );
        db.delete_container("e").await.unwrap();
        assert_eq!(
            got(db.net_attach("f", "n", 0, &[], r()).await.unwrap()),
            (2, Some(4))
        );
        // a network that goes forgets the last address given
        db.delete_container("d").await.unwrap();
        db.delete_container("f").await.unwrap();
        db.net_forget_network("n").await.unwrap();
        assert_eq!(
            got(db.net_attach("g", "n", 0, &[], r()).await.unwrap()),
            (2, Some(2))
        );
    }

    /// A network that goes is forgotten with the last address given on it.
    #[tokio::test]
    async fn a_network_that_goes_takes_its_last_address_with_it() {
        let db = db_with(&["c"]).await;
        let r = || range("10.0.0.2", "10.0.0.9", &[]);
        // the network row goes, and the last address given with it, whatever
        // its driver (only a bridge network is forgotten by its engine)
        db.insert_network(&crate::NetworkRecord {
            id: "n".into(),
            name: "net".into(),
            driver: "macvlan".into(),
            subnet: None,
            gateway: None,
            options: None,
            created_at: "now".into(),
            subnet6: None,
            gateway6: None,
        })
        .await
        .unwrap();
        db.net_attach("c", "n", 0, &[], r()).await.unwrap();
        db.delete_container("c").await.unwrap();
        db.delete_network_unused("n", false).await.unwrap();
        let left: i64 = db
            .conn
            .call(|c| Ok(c.query_row("SELECT COUNT(*) FROM network_ipam", [], |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(left, 0);
    }

    /// A row that cannot be read back is an error, not an address or aliases
    /// that are not there: the address would be given out twice.
    #[tokio::test]
    async fn a_damaged_row_is_an_error() {
        let db = db_with(&["a", "b"]).await;
        let r = || range("10.0.0.2", "10.0.0.9", &[]);
        db.net_attach("a", "n", 0, &["x".into()], r())
            .await
            .unwrap();
        let damage = |column: &'static str, value: &'static str| {
            let conn = db.conn.clone();
            async move {
                conn.call(move |c| {
                    c.execute(
                        &format!("UPDATE network_attachments SET {column} = ?1"),
                        [value],
                    )?;
                    Ok(())
                })
                .await
                .unwrap();
            }
        };
        damage("aliases", "not json").await;
        assert!(db.net_attachments_of_container("a").await.is_err());
        damage("aliases", "[]").await;
        damage("ip", "10.0.0.zz").await;
        let e = db.net_attachments_of_container("a").await.unwrap_err();
        assert!(e.to_string().contains("`10.0.0.zz` as the ip"), "{e}");
        // (the address of the damaged row is not known to be free)
        assert!(db.net_attach("b", "n", 0, &[], r()).await.is_err());
    }

    #[tokio::test]
    async fn pooled_addresses_move_and_are_not_reused() {
        let db = db_with(&["a", "b", "c"]).await;
        let r = || range("10.0.0.2", "10.0.0.9", &[]);
        db.net_attach("a", "n", 0, &[], r()).await.unwrap();
        db.netns_pool_put("s1", "a").await.unwrap();
        assert_eq!(
            db.net_attachments_of_container("a").await.unwrap()[0].ip,
            None
        );
        // The pooled address is not given to another container.
        assert_eq!(
            db.net_attach("b", "n", 0, &[], r()).await.unwrap().0,
            Ipv4Addr::new(10, 0, 0, 3)
        );
        // Different networks: no take.
        db.net_attach("c", "m", 0, &[], r()).await.unwrap();
        assert!(!db.netns_pool_take("s1", "c").await.unwrap());
        assert!(db.netns_pool_take("s1", "b").await.unwrap());
        assert_eq!(
            db.net_attachments_of_container("b").await.unwrap()[0].ip,
            Some(Ipv4Addr::new(10, 0, 0, 2))
        );
        assert!(db.netns_pool_slots(None).await.unwrap().is_empty());
        // a gave its address away: it gets a new one (.3, which b left, was
        // not the last given).
        let ip = db.net_reassign("a", "n", r()).await.unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 4));
        assert!(db.netns_pool_put("s2", "c").await.is_ok());
        assert_eq!(
            db.netns_pool_slots(Some("m")).await.unwrap(),
            vec!["s2".to_string()]
        );
        db.net_forget_network("m").await.unwrap();
        assert!(db.netns_pool_slots(None).await.unwrap().is_empty());
    }

    fn network(id: &str, name: &str, subnet: &str) -> crate::NetworkRecord {
        crate::NetworkRecord {
            id: id.into(),
            name: name.into(),
            driver: "bridge".into(),
            subnet: Some(subnet.into()),
            gateway: None,
            options: None,
            created_at: "now".into(),
            subnet6: None,
            gateway6: None,
        }
    }

    /// Creations at once cannot both take a subnet: the check of each sees
    /// the networks the others inserted.
    #[tokio::test]
    async fn one_of_the_networks_created_at_once_gets_a_subnet() {
        let db = Database::open_in_memory().await.unwrap();
        let tasks: Vec<_> = (0..8)
            .map(|i| {
                let db = db.clone();
                tokio::spawn(async move {
                    let n = network(&format!("id{i}"), &format!("n{i}"), "10.90.1.0/24");
                    let subnet = n.subnet.clone();
                    db.insert_network_checked(&n, move |rows| {
                        match rows.iter().find(|r| r.subnet == subnet) {
                            Some(o) => Err(format!("the subnet is the network {}'s", o.name)),
                            None => Ok(()),
                        }
                    })
                    .await
                })
            })
            .collect();
        let mut won = 0;
        for t in tasks {
            match t.await.unwrap() {
                Ok(()) => won += 1,
                Err(DbError::AlreadyExists(_)) => {}
                Err(e) => panic!("{e}"),
            }
        }
        assert_eq!(won, 1);
        assert_eq!(db.list_networks().await.unwrap().len(), 1);
    }

    /// A network that is used is not removed, one that is removed takes no
    /// attachment; one that is not a row (the default network) does.
    #[tokio::test]
    async fn an_attachment_and_a_removal_exclude_each_other() {
        let db = db_with(&["a", "b"]).await;
        db.insert_network(&network("n", "net", "10.90.1.0/24"))
            .await
            .unwrap();
        let on = |registered| {
            let mut c = range("10.90.1.2", "10.90.1.9", &[]);
            c.registered = registered;
            c
        };
        db.net_attach("a", "n", 0, &[], on(true)).await.unwrap();
        assert!(matches!(
            db.delete_network_unused("net", false).await,
            Err(DbError::AlreadyExists(_))
        ));
        // forced: whatever uses it
        db.delete_network_unused("net", true).await.unwrap();
        assert!(matches!(
            db.net_attach("b", "n", 0, &[], on(true)).await,
            Err(DbError::NotFound(_))
        ));
        assert!(matches!(
            db.delete_network_unused("net", true).await,
            Err(DbError::NotFound(_))
        ));
        db.net_attach("b", "default", 0, &[], on(false))
            .await
            .unwrap();
    }
}
