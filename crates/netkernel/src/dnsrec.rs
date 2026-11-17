// SPDX-License-Identifier: Apache-2.0
//! The DNS records of the bridge networks: the files the setup writes and the
//! teardown removes under the network lock, which the DNS server (in the
//! runtime) reads, and the datagram that tells it to reload.
//!
//! ```text
//! <state>/dns/<bridge>/network        the gateway, `internal`
//! <state>/dns/<bridge>/servers        the DNS servers of the network
//! <state>/dns/<bridge>/<container>    {"ips": [...], "names": [...]}
//! <state>/dns/control.sock            a datagram tells the server to reload
//! ```

use crate::bridge::{BridgeContainer, NetDef};
use crate::dns::Record;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV6};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const DNS_DIR: &str = "dns";

pub const NETWORK_FILE: &str = "network";

pub const SERVERS_FILE: &str = "servers";

/// The server for the other names when the bridges live in another
/// namespace than the host's resolvers (rootless: the forwarder of pasta).
pub const UPSTREAM_FILE: &str = "upstream";

/// Use SERVER for the other names when the host has none reachable from
/// the namespace of the bridges.
pub fn set_upstream(state: &Path, server: &str) -> io::Result<()> {
    let dir = dns_dir(state);
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)?;
    write_atomic(&dir, UPSTREAM_FILE, format!("{server}\n").as_bytes())
}

pub const CONTROL: &str = "control.sock";

pub const MAX_RECORD_FILE: u64 = 64 * 1024;

pub fn dns_dir(state: &Path) -> PathBuf {
    state.join(DNS_DIR)
}

/// A record file name: a container id.
pub fn valid_record_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.starts_with('.')
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        && s != NETWORK_FILE
        && s != SERVERS_FILE
}

pub fn write_atomic(dir: &Path, name: &str, data: &[u8]) -> io::Result<()> {
    velarx_base::atomic_file::write(&dir.join(name), data, 0o600)
}

pub fn write_servers(dir: &Path, n: &NetDef) -> io::Result<()> {
    if n.dns_servers.is_empty() {
        return match fs::remove_file(dir.join(SERVERS_FILE)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
    }
    let content: String = n.dns_servers.iter().map(|s| format!("{s}\n")).collect();
    write_atomic(dir, SERVERS_FILE, content.as_bytes())
}

/// The path of the control socket, short enough for `sun_path` whatever the
/// length of the state directory.
pub fn control_path(dir: &File) -> PathBuf {
    velarx_sys::fd::proc_path(dir).join(CONTROL)
}

/// Tell the server to reload; false if there is none.
pub fn reload(state: &Path) -> bool {
    let Ok(dir) = File::open(dns_dir(state)) else {
        return false;
    };
    let Ok(sock) = UnixDatagram::unbound() else {
        return false;
    };
    // Never wait for the server: it may itself wait for the network lock
    // the caller holds.  A full queue means a reload is pending anyway.
    if sock.set_nonblocking(true).is_err() {
        return false;
    }
    match sock.send_to(b"r", control_path(&dir)) {
        Ok(_) => true,
        Err(e) => e.kind() == std::io::ErrorKind::WouldBlock,
    }
}

/// Remove the directory of a network without records.
pub fn remove_empty_network(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with('.') && name != NETWORK_FILE && name != SERVERS_FILE {
            return;
        }
    }
    let _ = fs::remove_file(dir.join(NETWORK_FILE));
    let _ = fs::remove_file(dir.join(SERVERS_FILE));
    let _ = fs::remove_dir(dir);
}

/// Remove the records of C and reload the server.  Best effort.
pub fn unregister(state: &Path, c: &BridgeContainer) {
    if !valid_record_name(&c.id) {
        return;
    }
    let mut any = false;
    for a in c.attachments.iter().filter(|a| a.net.dns) {
        let dir = dns_dir(state).join(&a.net.bridge);
        if fs::remove_file(dir.join(&c.id)).is_ok() {
            any = true;
        }
        remove_empty_network(&dir);
    }
    if any {
        reload(state);
    }
}

/// Write the DNS servers of N for its running containers and reload the
/// server.  The caller holds the network lock.
pub fn update_servers(state: &Path, n: &NetDef) -> io::Result<()> {
    let dir = dns_dir(state).join(&n.bridge);
    // No container on the network: the next setup writes the file.
    if !dir.is_dir() {
        return Ok(());
    }
    write_servers(&dir, n)?;
    reload(state);
    Ok(())
}

/// Remove the records of the network on BRIDGE.  Best effort.
pub fn remove_network(state: &Path, bridge: &str) {
    let dir = dns_dir(state).join(bridge);
    let mut any = false;
    if let Ok(entries) = fs::read_dir(&dir) {
        for e in entries.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy().into_owned();
            if fs::remove_file(e.path()).is_ok() && name != NETWORK_FILE && name != SERVERS_FILE {
                any = true;
            }
        }
    }
    let _ = fs::remove_dir(&dir);
    if any {
        reload(state);
    }
}

pub fn read_small(path: &Path) -> Option<String> {
    velarx_base::conf::read_config_file(path, MAX_RECORD_FILE).ok()
}

/// A record file: invalid names and addresses are skipped.
pub fn parse_record(data: &str) -> Option<Record> {
    let v: serde_json::Value = serde_json::from_str(data).ok()?;
    let strs = |k: &str| -> Vec<String> {
        v.get(k)
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let ips = strs("ips").iter().filter_map(|s| s.parse().ok()).collect();
    let ips6 = strs("ips6").iter().filter_map(|s| s.parse().ok()).collect();
    let names = strs("names")
        .into_iter()
        .filter(|s| !s.is_empty() && s.len() <= 253 && !s.contains(' '))
        .map(|s| s.to_ascii_lowercase())
        .collect();
    Some(Record { names, ips, ips6 })
}

/// The `network` file: the gateway, then `internal` for an internal
/// network.
pub fn parse_network_file(s: &str) -> Option<(Ipv4Addr, bool)> {
    let mut lines = s.lines();
    let gw = lines.next()?.trim().parse().ok()?;
    Some((gw, lines.any(|l| l.trim() == "internal")))
}

/// The nameservers of a `resolv.conf`, in order, at port 53.  An IPv6
/// address may name its interface (`fe80::1%eth0`): `index` gives the number
/// of an interface by its name, and an address of an interface it does not
/// know is left out.
pub fn resolv_conf_servers(content: &str, index: impl Fn(&str) -> Option<u32>) -> Vec<SocketAddr> {
    content
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next()? == "nameserver").then_some(())?;
            let address = words.next()?;
            let (ip, scope) = match address.split_once('%') {
                Some((ip, scope)) => (ip, Some(scope)),
                None => (address, None),
            };
            match (ip.parse::<IpAddr>().ok()?, scope) {
                (ip, None) => Some(SocketAddr::new(ip, 53)),
                (IpAddr::V6(ip), Some(scope)) => {
                    let scope = scope.parse().ok().or_else(|| index(scope))?;
                    Some(SocketAddr::V6(SocketAddrV6::new(ip, 53, 0, scope)))
                }
                (IpAddr::V4(_), Some(_)) => None,
            }
        })
        .collect()
}

/// A name server of a setting or of an `upstream` file: an address, with a
/// port or without (53).
pub fn parse_upstream(text: &str) -> Option<SocketAddr> {
    let text = text.trim();
    text.parse::<SocketAddr>().ok().or_else(|| {
        text.parse::<IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, 53))
    })
}

/// Write the records of C on its DNS networks; whether it has any (then the
/// server is to be started or told to reload).  The caller holds the network
/// lock.
pub fn write_records(state: &Path, c: &BridgeContainer) -> io::Result<bool> {
    if !valid_record_name(&c.id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid container id",
        ));
    }
    let mut any = false;
    for a in c.attachments.iter().filter(|a| a.net.dns) {
        let dir = dns_dir(state).join(&a.net.bridge);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)?;
        let network = if a.net.internal {
            format!("{}\ninternal\n", a.net.gateway)
        } else {
            format!("{}\n", a.net.gateway)
        };
        write_atomic(&dir, NETWORK_FILE, network.as_bytes())?;
        write_servers(&dir, &a.net)?;
        let mut names = Vec::new();
        if !c.name.is_empty() {
            names.push(c.name.clone());
        }
        names.extend(a.aliases.iter().filter(|s| !s.is_empty()).cloned());
        let ips6: Vec<String> = a.ip6.iter().map(|i| i.to_string()).collect();
        let rec = serde_json::json!({"ips": [a.ip.to_string()], "ips6": ips6, "names": names});
        write_atomic(&dir, &c.id, rec.to_string().as_bytes())?;
        any = true;
    }
    Ok(any)
}

/// Write the records of C on its DNS networks and start or reload the
/// server.  The caller holds the network lock.
pub fn register(state: &Path, c: &BridgeContainer, exe: &Path) -> io::Result<()> {
    if !write_records(state, c)? || reload(state) {
        return Ok(());
    }
    start(state, exe)
}

pub const SERVER_LOCK: &str = "server.lock";

pub const SERVER_LOG: &str = "server.log";

/// The size the log of the server is kept under: emptied, when a server
/// starts, past it (a server says a failure of a network once).
pub const SERVER_LOG_LIMIT: u64 = 1 << 20;

/// The first line of a log that was emptied.
pub const SERVER_LOG_EMPTIED: &[u8] =
    b"the log reached its limit: what was written before is dropped\n";
pub const MAX_NETS: usize = 120;

/// Empty LOG (appended to) when it is over [`SERVER_LOG_LIMIT`].
pub fn bound_log(log: &File) -> io::Result<()> {
    if log.metadata()?.len() > SERVER_LOG_LIMIT {
        log.set_len(0)?;
        (&*log).write_all(SERVER_LOG_EMPTIED)?;
    }
    Ok(())
}

/// Start the server and wait until it holds its lock.  What the server and
/// its worker say about themselves (a network they cannot serve) is kept in
/// `<state>/dns/server.log`.
pub fn start(state: &Path, exe: &Path) -> io::Result<()> {
    let log_path = dns_dir(state).join(SERVER_LOG);
    let log = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&log_path)
        .map_err(|e| io::Error::new(e.kind(), format!("open {}: {e}", log_path.display())))?;
    bound_log(&log)?;
    let mut child = Command::new(exe)
        .arg("dns-server")
        .arg(state)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(log)
        .spawn()
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("start the DNS server {}: {e}", exe.display()),
            )
        })?;
    // The server says its pid (0: another server runs, it reloads) when it
    // holds its lock.
    let mut line = String::new();
    if let Some(out) = child.stdout.take() {
        let _ = io::BufReader::new(out.take(64)).read_line(&mut line);
    }
    // The process forks the server and exits.
    let _ = child.wait();
    match line.trim().parse::<u32>() {
        // (it lives in the namespace of the bridges: whoever looks for a
        // process there finds it)
        Ok(0) => Ok(()),
        Ok(pid) => {
            velarx_nsid::tree::register_holder(pid, "dns-server");
            Ok(())
        }
        Err(_) => Err(io::Error::other("cannot start the DNS server")),
    }
}
