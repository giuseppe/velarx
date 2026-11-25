// SPDX-License-Identifier: Apache-2.0
//! Secrets: the data in files (0600) of a private directory, the metadata
//! in the database.

use std::collections::HashMap;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;
use thiserror::Error;
use velarx_db::Database;
pub use velarx_wire::wire::SECRET_MAX_SIZE;
const SECRET_ID_LEN: usize = 25;

#[derive(Error, Debug)]
pub enum SecretError {
    #[error("no such secret: {0}")]
    NotFound(String),
    #[error("a secret named `{0}` already exists")]
    AlreadyExists(String),
    #[error("the secret `{name}` is in use by the container `{container}`")]
    InUse { name: String, container: String },
    #[error("{0}")]
    Invalid(String),
    #[error("the secret data is larger than {SECRET_MAX_SIZE} bytes")]
    TooLarge,
    #[error("database error: {0}")]
    Database(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type SecretResult<T> = Result<T, SecretError>;

fn db_err(e: impl std::fmt::Display) -> SecretError {
    SecretError::Database(e.to_string())
}

#[derive(Debug, Clone)]
pub struct SecretInfo {
    pub id: String,
    pub name: String,
    pub driver: String,
    /// The options of the driver (`--driver-opts`)
    pub driver_opts: HashMap<String, String>,
    pub labels: HashMap<String, String>,
    /// Nanoseconds since the epoch
    pub created: i64,
    pub updated: i64,
}

pub struct SecretStore {
    db: Database,
    dir: PathBuf,
}

fn valid_name(name: &str) -> bool {
    name.len() <= 253 && velarx_base::names::is_object_name(name)
}

fn row_info(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretInfo> {
    let json_map = |v: Option<String>| -> HashMap<String, String> {
        v.and_then(|l| serde_json::from_str(&l).ok())
            .unwrap_or_default()
    };
    Ok(SecretInfo {
        id: row.get(0)?,
        name: row.get(1)?,
        driver: row
            .get::<_, Option<String>>(2)?
            .unwrap_or_else(|| "file".into()),
        labels: json_map(row.get(3)?),
        created: row.get(4)?,
        updated: row.get(5)?,
        driver_opts: json_map(row.get(6)?),
    })
}

const COLUMNS: &str = "id, name, driver, labels, created, updated, driver_opts";

/// What `secret create` asks for besides the name and the data.
#[derive(Debug, Clone, Default)]
pub struct CreateSecretOptions {
    /// `file` (the default), `pass` or `shell`
    pub driver: Option<String>,
    pub driver_opts: HashMap<String, String>,
    pub labels: HashMap<String, String>,
    /// A secret of the same name is replaced (a new id)
    pub replace: bool,
    /// A secret of the same name is kept and its id answered
    pub ignore: bool,
}

/// How long a command of the `shell` driver, or gpg, may take.
const DRIVER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Where the data of a secret is, as podman's drivers: `file` in the
/// private directory of the engine, `pass` encrypted with gpg in a
/// password store, `shell` through the user's commands (`SECRET_ID` in the
/// environment, the data on stdin and stdout).
#[derive(Debug, Clone, PartialEq)]
enum Driver {
    File,
    Pass {
        root: PathBuf,
        key: String,
        homedir: Option<String>,
    },
    Shell {
        lookup: String,
        store: String,
        delete: String,
    },
}

impl Driver {
    fn new(name: &str, opts: &HashMap<String, String>) -> SecretResult<Self> {
        let invalid = |m: String| Err(SecretError::Invalid(m));
        match name {
            "file" => match opts.keys().find(|k| k.as_str() != "path") {
                // podman's file driver takes the directory of its data:
                // the engine keeps the data in its own
                Some(k) => invalid(format!("invalid file driver option `{k}`")),
                None => Ok(Driver::File),
            },
            "pass" => {
                if let Some(k) = opts
                    .keys()
                    .find(|k| !matches!(k.as_str(), "root" | "key" | "gpghomedir"))
                {
                    return invalid(format!("invalid pass driver option `{k}`"));
                }
                let root = match opts.get("root") {
                    Some(r) => PathBuf::from(r),
                    None => match std::env::var_os("HOME") {
                        Some(h) => PathBuf::from(h).join(".password-store"),
                        None => return invalid("the pass driver needs root=".into()),
                    },
                };
                if !root.is_absolute() {
                    return invalid(format!(
                        "the root of the pass driver is not absolute: {}",
                        root.display()
                    ));
                }
                // the key: given, else the .gpg-id of the store or above it
                let key = match opts.get("key") {
                    Some(k) => k.clone(),
                    None => root
                        .ancestors()
                        .find_map(|d| std::fs::read_to_string(d.join(".gpg-id")).ok())
                        .map(|k| k.trim().to_string())
                        .unwrap_or_default(),
                };
                Ok(Driver::Pass {
                    root,
                    key,
                    homedir: opts.get("gpghomedir").cloned(),
                })
            }
            "shell" => {
                let get = |k: &str| opts.get(k).filter(|v| !v.is_empty()).cloned();
                if let Some(k) = opts
                    .keys()
                    .find(|k| !matches!(k.as_str(), "list" | "lookup" | "store" | "delete"))
                {
                    return invalid(format!("invalid shell driver option `{k}`"));
                }
                match (get("list"), get("lookup"), get("store"), get("delete")) {
                    (Some(_), Some(lookup), Some(store), Some(delete)) => Ok(Driver::Shell {
                        lookup,
                        store,
                        delete,
                    }),
                    _ => invalid(
                        "the shell driver needs the list, lookup, store and delete commands".into(),
                    ),
                }
            }
            d => invalid(format!(
                "the secret driver `{d}` is not supported (file, pass, shell)"
            )),
        }
    }
}

/// Run `cmd` with `input` on its stdin; its stdout (at most
/// `SECRET_MAX_SIZE`).  Its input and its two outputs are served at once:
/// a driver that writes much to one of them while another is not served
/// would wait for ever (until the timeout).
async fn run_driver(
    mut cmd: tokio::process::Command,
    input: Option<&[u8]>,
    what: &str,
) -> SecretResult<Vec<u8>> {
    use std::process::Stdio;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    cmd.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true);
    let mut child = cmd
        .spawn()
        .map_err(|e| SecretError::Invalid(format!("{what}: {e}")))?;
    let (stdin, stdout, stderr) = (child.stdin.take(), child.stdout.take(), child.stderr.take());
    let feed = async {
        if let (Some(data), Some(mut stdin)) = (input, stdin) {
            match stdin.write_all(data).await {
                // (a driver that does not read all of it: its status tells)
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
                r => r?,
            }
        }
        Ok::<_, std::io::Error>(())
    };
    // (more than a secret: the driver is killed as the child is dropped)
    let read_out = async {
        let mut out = Vec::new();
        if let Some(stdout) = stdout {
            stdout
                .take(SECRET_MAX_SIZE as u64 + 1)
                .read_to_end(&mut out)
                .await?;
        }
        match out.len() > SECRET_MAX_SIZE {
            true => Err(std::io::ErrorKind::FileTooLarge.into()),
            false => Ok(out),
        }
    };
    // (all of it is read, its start kept for the message)
    let read_err = async {
        let mut err = Vec::new();
        if let Some(mut stderr) = stderr {
            let mut buf = vec![0u8; 4096];
            loop {
                let n = stderr.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                let room = 4096usize.saturating_sub(err.len());
                err.extend_from_slice(&buf[..n.min(room)]);
            }
        }
        Ok(err)
    };
    let run = async {
        let ((), out, err) = tokio::try_join!(feed, read_out, read_err)?;
        let status = child.wait().await?;
        Ok::<_, std::io::Error>((status, out, err))
    };
    let (status, out, err) = match tokio::time::timeout(DRIVER_TIMEOUT, run).await {
        Err(_) => return Err(SecretError::Invalid(format!("{what}: timed out"))),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::FileTooLarge => {
            return Err(SecretError::TooLarge)
        }
        Ok(r) => r?,
    };
    if !status.success() {
        let err = String::from_utf8_lossy(&err);
        return Err(SecretError::Invalid(format!(
            "{what}: {status}: {}",
            err.trim()
        )));
    }
    Ok(out)
}

fn shell(command: &str, id: &str) -> tokio::process::Command {
    let mut c = tokio::process::Command::new("/bin/sh");
    c.arg("-c").arg(command).env("SECRET_ID", id);
    c
}

fn gpg(homedir: &Option<String>) -> tokio::process::Command {
    let mut c = tokio::process::Command::new("gpg");
    c.arg("--batch").arg("--quiet");
    if let Some(h) = homedir {
        c.arg("--homedir").arg(h);
    }
    c
}

impl SecretStore {
    pub async fn new(db: Database, dir: PathBuf) -> SecretResult<Self> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)?;
        // (its tables are made with the store: velarx_db::schema)
        Ok(Self { db, dir })
    }

    fn data_path(&self, id: &str) -> PathBuf {
        self.dir.join(id)
    }

    /// Store the data of a new secret `id` with its driver.
    async fn driver_store(&self, d: &Driver, id: &str, data: &[u8]) -> SecretResult<()> {
        match d {
            Driver::File => {
                let path = self.data_path(id);
                let written = (|| {
                    let mut f = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                        .open(&path)?;
                    f.write_all(data)?;
                    f.sync_all()
                })();
                if written.is_err() {
                    let _ = std::fs::remove_file(&path);
                }
                Ok(written?)
            }
            Driver::Pass { root, key, homedir } => {
                if key.is_empty() {
                    return Err(SecretError::Invalid(
                        "the pass driver needs a gpg key (key= or a .gpg-id in its root)".into(),
                    ));
                }
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(root)?;
                let mut c = gpg(homedir);
                c.arg("--encrypt")
                    .arg("-r")
                    .arg(key)
                    .arg("-o")
                    .arg(root.join(format!("{id}.gpg")));
                run_driver(c, Some(data), "gpg --encrypt").await.map(|_| ())
            }
            Driver::Shell { store, .. } => {
                run_driver(shell(store, id), Some(data), "the store command")
                    .await
                    .map(|_| ())
            }
        }
    }

    /// The data of the secret `id`.
    async fn driver_lookup(&self, d: &Driver, id: &str) -> SecretResult<Vec<u8>> {
        let data = match d {
            Driver::File => std::fs::read(self.data_path(id))?,
            Driver::Pass { root, homedir, .. } => {
                let mut c = gpg(homedir);
                c.arg("--decrypt").arg(root.join(format!("{id}.gpg")));
                run_driver(c, None, "gpg --decrypt").await?
            }
            Driver::Shell { lookup, .. } => {
                run_driver(shell(lookup, id), None, "the lookup command").await?
            }
        };
        if data.is_empty() && !matches!(d, Driver::File) {
            return Err(SecretError::NotFound(id.to_string()));
        }
        Ok(data)
    }

    /// Remove the data of the secret `id`; data already gone is fine.
    async fn driver_delete(&self, d: &Driver, id: &str) -> SecretResult<()> {
        let gone = |r: std::io::Result<()>| match r {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(SecretError::Io(e)),
            _ => Ok(()),
        };
        match d {
            Driver::File => gone(std::fs::remove_file(self.data_path(id))),
            Driver::Pass { root, .. } => gone(std::fs::remove_file(root.join(format!("{id}.gpg")))),
            Driver::Shell { delete, .. } => {
                run_driver(shell(delete, id), None, "the delete command")
                    .await
                    .map(|_| ())
            }
        }
    }

    pub async fn create(
        &self,
        name: &str,
        opts: CreateSecretOptions,
        data: &[u8],
    ) -> SecretResult<String> {
        if !valid_name(name) {
            return Err(SecretError::Invalid(format!(
                "invalid secret name `{name}`"
            )));
        }
        if opts.replace && opts.ignore {
            return Err(SecretError::Invalid(
                "replace and ignore go not together".into(),
            ));
        }
        let driver_name = opts
            .driver
            .as_deref()
            .filter(|d| !d.is_empty())
            .unwrap_or("file");
        let driver = Driver::new(driver_name, &opts.driver_opts)?;
        if data.is_empty() {
            return Err(SecretError::Invalid("the secret data is empty".into()));
        }
        if data.len() > SECRET_MAX_SIZE {
            return Err(SecretError::TooLarge);
        }
        let old = self.lookup_exact(name).await?;
        match &old {
            Some(o) if opts.ignore => return Ok(o.id.clone()),
            Some(_) if !opts.replace => return Err(SecretError::AlreadyExists(name.to_string())),
            _ => {}
        }
        let mut id = format!(
            "{}{}",
            velarx_base::random::token(),
            velarx_base::random::token()
        );
        id.truncate(SECRET_ID_LEN);
        self.driver_store(&driver, &id, data).await?;

        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let created = old.as_ref().map_or(now, |o| o.created);
        let labels = serde_json::to_string(&opts.labels).unwrap_or_else(|_| "{}".into());
        let driver_opts = serde_json::to_string(&opts.driver_opts).unwrap_or_else(|_| "{}".into());
        let (row_id, row_name, row_driver) =
            (id.clone(), name.to_string(), driver_name.to_string());
        let old_id = old.as_ref().map(|o| o.id.clone());
        let inserted = self
            .db
            .conn()
            .call(move |conn| {
                let tx = conn.transaction()?;
                if let Some(old) = &old_id {
                    // the name goes to the new secret, and the containers
                    // that used the old one now use it ('/' is in no name)
                    tx.execute(
                        "UPDATE secrets SET name = name || '/' || id WHERE id = ?1",
                        [old],
                    )?;
                }
                tx.execute(
                    &format!("INSERT INTO secrets ({COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"),
                    rusqlite::params![
                        row_id,
                        row_name,
                        row_driver,
                        labels,
                        created,
                        now,
                        driver_opts
                    ],
                )?;
                if let Some(old) = &old_id {
                    tx.execute(
                        "UPDATE secret_users SET secret_id = ?1 WHERE secret_id = ?2",
                        [&row_id, old],
                    )?;
                    tx.execute("DELETE FROM secrets WHERE id = ?1", [old])?;
                }
                tx.commit()?;
                Ok(())
            })
            .await;
        if let Err(e) = inserted {
            let _ = self.driver_delete(&driver, &id).await;
            // a concurrent create of the same name
            return match self.lookup_exact(name).await {
                Ok(Some(_)) if old.is_none() => Err(SecretError::AlreadyExists(name.to_string())),
                _ => Err(db_err(e)),
            };
        }
        if let Some(o) = old {
            let delete = async {
                let d = Driver::new(&o.driver, &o.driver_opts)?;
                self.driver_delete(&d, &o.id).await
            };
            if let Err(e) = delete.await {
                tracing::warn!(
                    "cannot remove the data of the replaced secret `{}`: {e}",
                    o.name
                );
            }
        }
        Ok(id)
    }

    async fn lookup_exact(&self, name_or_id: &str) -> SecretResult<Option<SecretInfo>> {
        let key = name_or_id.to_string();
        self.db
            .conn()
            .call(move |conn| {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {COLUMNS} FROM secrets WHERE name = ?1 OR id = ?1"
                ))?;
                let mut rows = stmt.query_map([&key], row_info)?;
                Ok(rows.next().transpose()?)
            })
            .await
            .map_err(db_err)
    }

    /// By name, id or unique id prefix.
    pub async fn lookup(&self, name_or_id: &str) -> SecretResult<SecretInfo> {
        if let Some(s) = self.lookup_exact(name_or_id).await? {
            return Ok(s);
        }
        if name_or_id.is_empty() || !name_or_id.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(SecretError::NotFound(name_or_id.to_string()));
        }
        let prefix = format!("{name_or_id}%");
        let mut found = self
            .db
            .conn()
            .call(move |conn| {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {COLUMNS} FROM secrets WHERE id LIKE ?1 LIMIT 2"
                ))?;
                let rows = stmt
                    .query_map([&prefix], row_info)?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
            .map_err(db_err)?;
        match found.len() {
            0 => Err(SecretError::NotFound(name_or_id.to_string())),
            1 => Ok(found.remove(0)),
            _ => Err(SecretError::Invalid(format!(
                "more than one secret matches `{name_or_id}`"
            ))),
        }
    }

    pub async fn list(&self) -> SecretResult<Vec<SecretInfo>> {
        self.db
            .conn()
            .call(|conn| {
                let mut stmt =
                    conn.prepare(&format!("SELECT {COLUMNS} FROM secrets ORDER BY created"))?;
                let rows = stmt
                    .query_map([], row_info)?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
            .map_err(db_err)
    }

    /// The secret and its data.
    pub async fn data(&self, name_or_id: &str) -> SecretResult<(SecretInfo, Vec<u8>)> {
        let info = self.lookup(name_or_id).await?;
        let driver = Driver::new(&info.driver, &info.driver_opts)?;
        let data = self.driver_lookup(&driver, &info.id).await?;
        Ok((info, data))
    }

    /// Record that the container uses the secret: it cannot be removed.
    pub async fn mark_use(&self, secret_id: &str, container_id: &str) -> SecretResult<()> {
        let (s, c) = (secret_id.to_string(), container_id.to_string());
        self.db
            .conn()
            .call(move |conn| {
                conn.execute(
                    "INSERT OR IGNORE INTO secret_users (secret_id, container_id) VALUES (?1, ?2)",
                    [&s, &c],
                )?;
                Ok(())
            })
            .await
            .map_err(db_err)
    }

    /// The container is gone (or does not use secrets any more).
    pub async fn release(&self, container_id: &str) -> SecretResult<()> {
        let c = container_id.to_string();
        self.db
            .conn()
            .call(move |conn| {
                conn.execute("DELETE FROM secret_users WHERE container_id = ?1", [&c])?;
                Ok(())
            })
            .await
            .map_err(db_err)
    }

    /// A container that still exists and uses the secret.
    async fn user_of(&self, secret_id: &str) -> SecretResult<Option<String>> {
        let s = secret_id.to_string();
        self.db
            .conn()
            .call(move |conn| {
                // containers removed behind our back do not count
                conn.execute(
                    "DELETE FROM secret_users WHERE container_id NOT IN (SELECT id FROM containers)",
                    [],
                )?;
                let mut stmt = conn.prepare(
                    "SELECT container_id FROM secret_users WHERE secret_id = ?1 LIMIT 1",
                )?;
                let mut rows = stmt.query_map([&s], |r| r.get::<_, String>(0))?;
                Ok(rows.next().transpose()?)
            })
            .await
            .map_err(db_err)
    }

    pub async fn remove(&self, name_or_id: &str) -> SecretResult<SecretInfo> {
        let info = self.lookup(name_or_id).await?;
        if let Some(container) = self.user_of(&info.id).await? {
            return Err(SecretError::InUse {
                name: info.name,
                container,
            });
        }
        // as podman: the data first, a driver that fails keeps the secret
        let driver = Driver::new(&info.driver, &info.driver_opts)?;
        self.driver_delete(&driver, &info.id).await?;
        let id = info.id.clone();
        self.db
            .conn()
            .call(move |conn| {
                conn.execute("DELETE FROM secrets WHERE id = ?1", [&id])?;
                Ok(())
            })
            .await
            .map_err(db_err)?;
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_db::RecordState;

    async fn store() -> (SecretStore, tempfile::TempDir) {
        let d = tempfile::tempdir().unwrap();
        let db = Database::open_in_memory().await.unwrap();
        (
            SecretStore::new(db, d.path().join("secrets"))
                .await
                .unwrap(),
            d,
        )
    }

    #[test]
    fn a_secret_name_follows_the_rule_of_the_other_objects() {
        for ok in ["s", "db-pass_1", "a.b"] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in ["", ".", "..", "-s", ".hidden", "a/b", &"a".repeat(254)] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    #[tokio::test]
    async fn create_inspect_remove() {
        let (s, _d) = store().await;
        let labels = HashMap::from([("k".to_string(), "v".to_string())]);
        let id = s
            .create(
                "sec",
                CreateSecretOptions {
                    labels,
                    ..Default::default()
                },
                b"hunter2",
            )
            .await
            .unwrap();
        assert_eq!(id.len(), SECRET_ID_LEN);
        let (info, data) = s.data("sec").await.unwrap();
        assert_eq!(data, b"hunter2");
        assert_eq!(info.labels["k"], "v");
        assert_eq!(s.lookup(&id[..6]).await.unwrap().name, "sec");
        let mode = std::fs::metadata(s.data_path(&id)).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(mode.permissions().mode() & 0o777, 0o600);
        assert!(matches!(
            s.create("sec", CreateSecretOptions::default(), b"x").await,
            Err(SecretError::AlreadyExists(_))
        ));
        s.remove("sec").await.unwrap();
        assert!(matches!(
            s.lookup("sec").await,
            Err(SecretError::NotFound(_))
        ));
        assert!(!s.data_path(&id).exists());
    }

    /// A driver that says much on its standard error, and one that does not
    /// read its input, are answered as soon as they end.
    #[tokio::test]
    async fn a_driver_is_served_on_all_its_streams_at_once() {
        let start = std::time::Instant::now();
        let out = run_driver(
            shell("head -c 200000 /dev/zero >&2; printf secret", "id"),
            None,
            "the lookup command",
        )
        .await
        .unwrap();
        assert_eq!(out, b"secret");
        let out = run_driver(
            shell("printf kept", "id"),
            Some(&vec![b'x'; 1 << 20]),
            "the store command",
        )
        .await
        .unwrap();
        assert_eq!(out, b"kept");
        let failed = run_driver(
            shell("head -c 200000 /dev/zero >&2; exit 3", "id"),
            None,
            "the lookup command",
        )
        .await
        .unwrap_err();
        assert!(failed.to_string().contains("exit status: 3"), "{failed}");
        assert!(matches!(
            run_driver(shell("head -c 2000000 /dev/zero", "id"), None, "lookup").await,
            Err(SecretError::TooLarge)
        ));
        assert!(start.elapsed() < DRIVER_TIMEOUT / 2);
    }

    #[tokio::test]
    async fn rejects_bad_input() {
        let (s, _d) = store().await;
        for name in ["", "a/b", "x y"] {
            assert!(matches!(
                s.create(name, CreateSecretOptions::default(), b"x").await,
                Err(SecretError::Invalid(_))
            ));
        }
        assert!(matches!(
            s.create("e", CreateSecretOptions::default(), b"").await,
            Err(SecretError::Invalid(_))
        ));
        let big = vec![0u8; SECRET_MAX_SIZE + 1];
        assert!(matches!(
            s.create("big", CreateSecretOptions::default(), &big).await,
            Err(SecretError::TooLarge)
        ));
        assert!(matches!(
            s.create(
                "d",
                CreateSecretOptions {
                    driver: Some("vault".into()),
                    ..Default::default()
                },
                b"x"
            )
            .await,
            Err(SecretError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn in_use_blocks_removal() {
        let (s, _d) = store().await;
        let id = s
            .create("sec", CreateSecretOptions::default(), b"x")
            .await
            .unwrap();
        s.db.insert_image(&velarx_db::ImageRecord {
            id: "i".into(),
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
            created_at: "2026-01-01T00:00:00Z".into(),
            is_lazy: false,
        })
        .await
        .unwrap();
        s.db.insert_container(&velarx_db::ContainerRecord {
            id: "c1".into(),
            name: None,
            image_id: "i".into(),
            config: "{}".into(),
            state: RecordState::Created,
            created_at: "2026-01-01T00:00:00Z".into(),
            ..Default::default()
        })
        .await
        .unwrap();
        s.mark_use(&id, "c1").await.unwrap();
        assert!(matches!(
            s.remove("sec").await,
            Err(SecretError::InUse { .. })
        ));
        s.release("c1").await.unwrap();
        s.remove("sec").await.unwrap();
    }

    #[tokio::test]
    async fn replace_and_ignore() {
        let (s, _d) = store().await;
        let id = s
            .create("sec", CreateSecretOptions::default(), b"one")
            .await
            .unwrap();
        let ignore = CreateSecretOptions {
            ignore: true,
            ..Default::default()
        };
        assert_eq!(s.create("sec", ignore, b"two").await.unwrap(), id);
        assert_eq!(s.data("sec").await.unwrap().1, b"one");
        let replace = CreateSecretOptions {
            replace: true,
            ..Default::default()
        };
        let id2 = s.create("sec", replace, b"three").await.unwrap();
        assert_ne!(id, id2);
        let (info, data) = s.data("sec").await.unwrap();
        assert_eq!(
            (info.id.as_str(), data.as_slice()),
            (id2.as_str(), &b"three"[..])
        );
        assert!(!s.data_path(&id).exists());
        assert_eq!(s.list().await.unwrap().len(), 1);
        let both = CreateSecretOptions {
            replace: true,
            ignore: true,
            ..Default::default()
        };
        assert!(s.create("sec", both, b"x").await.is_err());
    }

    #[tokio::test]
    async fn shell_driver() {
        let (s, d) = store().await;
        let dir = d.path().join("shell");
        std::fs::create_dir(&dir).unwrap();
        let p = dir.display();
        let opts = HashMap::from([
            ("list".to_string(), format!("ls {p}")),
            ("lookup".to_string(), format!("cat {p}/$SECRET_ID")),
            ("store".to_string(), format!("cat > {p}/$SECRET_ID")),
            ("delete".to_string(), format!("rm {p}/$SECRET_ID")),
        ]);
        let o = CreateSecretOptions {
            driver: Some("shell".into()),
            driver_opts: opts.clone(),
            ..Default::default()
        };
        let id = s.create("sh", o, b"data").await.unwrap();
        assert_eq!(std::fs::read(dir.join(&id)).unwrap(), b"data");
        let (info, data) = s.data("sh").await.unwrap();
        assert_eq!(
            (info.driver.as_str(), data.as_slice()),
            ("shell", &b"data"[..])
        );
        assert_eq!(info.driver_opts, opts);
        s.remove("sh").await.unwrap();
        assert!(!dir.join(&id).exists());

        // a failing store leaves nothing; missing commands and unknown
        // options are refused
        let mut bad = opts.clone();
        bad.insert("store".into(), "exit 3".into());
        let o = CreateSecretOptions {
            driver: Some("shell".into()),
            driver_opts: bad,
            ..Default::default()
        };
        assert!(s.create("bad", o, b"x").await.is_err());
        assert!(matches!(
            s.lookup("bad").await,
            Err(SecretError::NotFound(_))
        ));
        let mut missing = opts.clone();
        missing.remove("list");
        let o = CreateSecretOptions {
            driver: Some("shell".into()),
            driver_opts: missing,
            ..Default::default()
        };
        assert!(matches!(
            s.create("m", o, b"x").await,
            Err(SecretError::Invalid(_))
        ));
        let mut extra = opts;
        extra.insert("other".into(), "x".into());
        let o = CreateSecretOptions {
            driver: Some("shell".into()),
            driver_opts: extra,
            ..Default::default()
        };
        assert!(matches!(
            s.create("e", o, b"x").await,
            Err(SecretError::Invalid(_))
        ));
        let o = CreateSecretOptions {
            driver_opts: HashMap::from([("bogus".to_string(), "x".to_string())]),
            ..Default::default()
        };
        assert!(matches!(
            s.create("f", o, b"x").await,
            Err(SecretError::Invalid(_))
        ));
    }
}
