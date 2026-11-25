// SPDX-License-Identifier: Apache-2.0
//! What a build takes from its client besides the context: the secrets
//! (`--secret`), the named contexts (`--build-context`) and the ssh agents
//! (`--ssh`), read as buildah reads them, and the broker through which the
//! engine asks the client for a new connection to one of its agents.
//!
//! The broker is a stream socket the build call carries: the engine writes
//! the index of an agent (4 bytes, big-endian), the client connects to that
//! agent and answers one byte, 0 with the connected socket (`SCM_RIGHTS`)
//! or 1 when it cannot connect.

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};

use crate::cp::{extract_with, ExtractOptions};
use crate::sbom::SbomResolve;
pub use velarx_proto::buildspec::BuildFlags;

/// What does not go together in the flags of a build.
pub trait BuildFlagsCheck {
    fn check(&self) -> Result<(), String>;
}

impl BuildFlagsCheck for BuildFlags {
    fn check(&self) -> Result<(), String> {
        if self.timestamp.is_some() && self.source_date_epoch.is_some() {
            return Err("--timestamp and --source-date-epoch cannot be used together".into());
        }
        if self.rewrite_timestamp && self.source_date_epoch.is_none() {
            return Err("--rewrite-timestamp needs --source-date-epoch".into());
        }
        self.sbom.resolve()?;
        Ok(())
    }
}

/// The largest value of a secret (BuildKit's limit).
pub const MAX_SECRET: u64 = 500 * 1024;

/// A secret of a build: its id and its value (base64 in the JSON), never
/// printed.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildSecret {
    pub id: String,
    #[serde(with = "base64_bytes")]
    pub value: Vec<u8>,
}

impl std::fmt::Debug for BuildSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuildSecret")
            .field("id", &self.id)
            .field("value", &"<redacted>")
            .finish()
    }
}

mod base64_bytes {
    use base64::Engine;
    pub fn serialize<S: serde::Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s: String = serde::Deserialize::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(serde::de::Error::custom)
    }
}

/// Where the value of a `--secret` is on the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretSource {
    /// A variable of the environment
    Env(String),
    /// A file
    File(PathBuf),
}

/// `--secret id=ID[,src=ENV_OR_FILE][,env=ENV][,type=file|env]`, by
/// buildah's rules: the source is `src` (or the id); without a type it is
/// the variable when one is named by the id, else the file.
pub fn parse_secret(
    spec: &str,
    has_env: &dyn Fn(&str) -> bool,
) -> Result<(String, SecretSource), String> {
    let syntax =
        || format!("invalid secret `{spec}`: id=ID[,src=ENV_OR_FILE][,env=ENV][,type=file|env]");
    let (mut id, mut src, mut typ) = (None, None, None);
    for token in spec.split(',') {
        let (k, v) = token.split_once('=').ok_or_else(syntax)?;
        match k {
            "id" => id = Some(v.to_string()),
            "src" | "source" => src = Some(v.to_string()),
            "env" => {
                src = Some(v.to_string());
                typ = Some("env");
            }
            "type" => {
                typ = Some(match v {
                    "file" => "file",
                    "env" => "env",
                    _ => return Err("invalid secret type, must be file or env".into()),
                })
            }
            _ => return Err(syntax()),
        }
    }
    let id = id.filter(|i| !i.is_empty()).ok_or_else(syntax)?;
    let src = src.filter(|s| !s.is_empty()).unwrap_or_else(|| id.clone());
    let typ = typ.unwrap_or(if has_env(&id) { "env" } else { "file" });
    Ok((
        id,
        if typ == "env" {
            SecretSource::Env(src)
        } else {
            SecretSource::File(PathBuf::from(src))
        },
    ))
}

/// Read a secret of the client.
pub fn read_secret(
    id: &str,
    source: &SecretSource,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<BuildSecret, String> {
    let value = match source {
        SecretSource::Env(name) => env(name)
            .ok_or_else(|| format!("the secret {id}: no variable {name}"))?
            .into_bytes(),
        SecretSource::File(path) => {
            let mut v = Vec::new();
            std::fs::File::open(path)
                .and_then(|f| f.take(MAX_SECRET + 1).read_to_end(&mut v))
                .map_err(|e| format!("could not parse secrets: {}: {e}", path.display()))?;
            v
        }
    };
    if value.len() as u64 > MAX_SECRET {
        return Err(format!("the secret {id} is larger than {MAX_SECRET} bytes"));
    }
    Ok(BuildSecret {
        id: id.to_string(),
        value,
    })
}

/// A named context of a build, as the request names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextSource {
    /// A directory the client sent at the top of the upload, under this
    /// name.
    Upload(String),
    /// An image.
    Image(String),
    /// A git repository or the URL of a tar.
    Url(String),
}

/// A named context: `--build-context NAME=VALUE`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedContextRequest {
    pub name: String,
    pub source: ContextSource,
}

/// What a `--build-context` value names: an image (`docker-image://`,
/// `container-image://`, `docker://`), a URL (http or https, a git
/// repository), else a directory of the client.
pub enum ContextValue {
    Image(String),
    Url(String),
    Dir(PathBuf),
}

/// `NAME=VALUE` of `--build-context`.
pub fn parse_build_context(spec: &str) -> Result<(String, ContextValue), String> {
    let (name, value) = spec
        .split_once('=')
        .filter(|(n, v)| !n.is_empty() && !v.is_empty())
        .ok_or_else(|| format!("invalid build context `{spec}`: NAME=VALUE"))?;
    for p in ["docker-image://", "container-image://", "docker://"] {
        if let Some(i) = value.strip_prefix(p) {
            return Ok((name.to_string(), ContextValue::Image(i.to_string())));
        }
    }
    if is_remote_context(value) {
        return Ok((name.to_string(), ContextValue::Url(value.to_string())));
    }
    if value.contains("://") {
        return Err(format!("unsupported build context `{value}`"));
    }
    Ok((name.to_string(), ContextValue::Dir(PathBuf::from(value))))
}

/// Whether a build context is fetched by the engine, not a directory of
/// the client: an http(s) or `git://` URL, `git@host:path` (buildah's
/// `TempDirForURL`) or `github.com/USER/REPO`.
pub fn is_remote_context(value: &str) -> bool {
    ["http://", "https://", "git://", "git@", "github.com/"]
        .iter()
        .any(|p| value.starts_with(p))
}

/// Whether the Containerfile `-f` names is a URL the engine fetches.
pub fn is_remote_file(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://")
}

/// `--ssh default|ID[=SOCKET]`: the id and the socket of the agent (the
/// default one is `SSH_AUTH_SOCK`).
pub fn parse_ssh(
    spec: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<(String, PathBuf), String> {
    let (id, paths) = match spec.split_once('=') {
        Some((id, p)) => (id, Some(p)),
        None => (spec, None),
    };
    if id.is_empty() {
        return Err(format!("invalid --ssh `{spec}`: default or ID[=SOCKET]"));
    }
    let path = match paths.filter(|p| !p.is_empty()) {
        Some(p) if p.contains(',') => {
            return Err(format!(
                "--ssh {spec}: velarx forwards one agent socket, not key files: load the keys in an agent (ssh-add)"
            ))
        }
        Some(p) => PathBuf::from(p),
        None => PathBuf::from(env("SSH_AUTH_SOCK").filter(|s| !s.is_empty()).ok_or_else(|| {
            format!("--ssh {spec}: SSH_AUTH_SOCK is not set: give the socket of an agent")
        })?),
    };
    use std::os::unix::fs::FileTypeExt;
    match std::fs::metadata(&path) {
        Ok(m) if m.file_type().is_socket() => Ok((id.to_string(), path)),
        Ok(_) => Err(format!(
            "--ssh {spec}: {} is not the socket of an agent (velarx forwards agents, not key files: load the keys in one with ssh-add)",
            path.display()
        )),
        Err(e) => Err(format!("--ssh {spec}: {}: {e}", path.display())),
    }
}

/// Serve the engine's asks on `broker` until it closes it: each one is a
/// connection to the agent of that index of `agents`.
pub fn serve_broker(broker: std::os::unix::net::UnixStream, agents: &[PathBuf]) {
    let mut broker = broker;
    loop {
        let mut index = [0u8; 4];
        if broker.read_exact(&mut index).is_err() {
            return;
        }
        let conn = agents
            .get(u32::from_be_bytes(index) as usize)
            .ok_or_else(|| std::io::Error::other("no such agent"))
            .and_then(std::os::unix::net::UnixStream::connect);
        let sent = match conn {
            Ok(c) => send_fd(&broker, OwnedFd::from(c).as_fd()),
            Err(_) => broker.write_all(&[1]),
        };
        if sent.is_err() {
            return;
        }
    }
}

fn send_fd(sock: &impl AsFd, fd: std::os::fd::BorrowedFd<'_>) -> std::io::Result<()> {
    use rustix::net::{sendmsg, SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
    use std::mem::MaybeUninit;
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    let fds = [fd];
    control.push(SendAncillaryMessage::ScmRights(&fds));
    let n = sendmsg(
        sock,
        &[std::io::IoSlice::new(&[0])],
        &mut control,
        SendFlags::NOSIGNAL,
    )?;
    if n != 1 {
        return Err(std::io::Error::other("the broker socket took nothing"));
    }
    Ok(())
}

/// Ask the client at the other end of `broker` for a new connection to its
/// agent `index` (blocking).
pub fn broker_connect(broker: &impl AsFd, index: u32) -> std::io::Result<OwnedFd> {
    let mut sent = 0;
    let ask = index.to_be_bytes();
    while sent < ask.len() {
        sent += rustix::io::write(broker, &ask[sent..])?;
    }
    let mut byte = [0u8; 1];
    let got = velarx_sys::scm::recv(broker, &mut byte, 1, rustix::net::RecvFlags::empty())?;
    let fd = got.fds.into_iter().next();
    match (got.bytes, byte[0], fd) {
        (1, 0, Some(fd)) => Ok(fd),
        (0, _, _) => Err(std::io::Error::other("the client of the build went away")),
        _ => Err(std::io::Error::other(
            "the client could not connect to its agent",
        )),
    }
}

/// Where `build --output` writes the files of the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Extracted into a directory
    Dir(PathBuf),
    /// A tar, to a file or (none) the standard output
    Tar(Option<PathBuf>),
}

impl Output {
    /// Write the tar of the files of the image `reader` gives where the
    /// output says: a tar file, or a directory it is extracted into.  The
    /// standard output is the caller's.  `warn` is told of what is not
    /// written.
    pub fn write(
        &self,
        mut reader: impl Read,
        warn: &mut dyn FnMut(String),
    ) -> std::io::Result<()> {
        let named = |path: &Path, e: std::io::Error| {
            std::io::Error::new(e.kind(), format!("--output {}: {e}", path.display()))
        };
        match self {
            Output::Tar(None) => Err(std::io::Error::other(
                "--output: the standard output is not a place for this",
            )),
            Output::Tar(Some(path)) => {
                let mut file = std::fs::File::create(path).map_err(|e| named(path, e))?;
                std::io::copy(&mut reader, &mut file).map_err(|e| named(path, e))?;
                Ok(())
            }
            Output::Dir(dir) => {
                std::fs::create_dir_all(dir).map_err(|e| named(dir, e))?;
                let base = std::fs::File::open(dir).map_err(|e| named(dir, e))?;
                // (an image's setuid files are not made setuid in the
                // directory of the user who asked for the files)
                let opts = ExtractOptions {
                    overwrite_dir_non_dir: true,
                    mask_setid: true,
                    ..Default::default()
                };
                let skipped = extract_with(reader, base.as_fd(), &opts, &|_, _| Ok(()))
                    .map_err(|e| named(dir, e))?;
                for (rel, kind) in skipped {
                    let what = match kind {
                        // (an unprivileged user makes no device node, nor
                        // does buildah's local output)
                        tar::EntryType::Char | tar::EntryType::Block => "the device node",
                        tar::EntryType::Fifo => "the fifo",
                        tar::EntryType::Link => "the hard link",
                        _ => "the entry",
                    };
                    warn(format!(
                        "WARNING: --output: {what} {} is not written",
                        rel.display()
                    ));
                }
                Ok(())
            }
        }
    }
}

/// `--output`: `DIR`, `-`, `type=local,dest=DIR`, `type=tar,dest=FILE|-`.
pub fn parse_output(spec: &str) -> Result<Output, String> {
    if spec == "-" {
        return Ok(Output::Tar(None));
    }
    if !spec.contains('=') {
        return Ok(Output::Dir(PathBuf::from(spec)));
    }
    let (mut kind, mut dest) = (None, None);
    for token in spec.split(',') {
        match token.split_once('=') {
            Some(("type", v)) => kind = Some(v),
            Some(("dest", v)) => dest = Some(v),
            _ => {
                return Err(format!(
                    "invalid --output `{spec}`: type=local|tar,dest=PATH"
                ))
            }
        }
    }
    let dest = dest
        .filter(|d| !d.is_empty())
        .ok_or_else(|| format!("--output `{spec}` needs a dest"))?;
    match kind.unwrap_or("local") {
        "local" => Ok(Output::Dir(PathBuf::from(dest))),
        "tar" if dest == "-" => Ok(Output::Tar(None)),
        "tar" => Ok(Output::Tar(Some(PathBuf::from(dest)))),
        t => Err(format!(
            "failed to parse build output {spec:?}: invalid type {t:?} selected for build output options {spec:?}"
        )),
    }
}

/// The name a directory context has at the top of the upload.
pub fn upload_name(index: usize) -> String {
    format!(".velarx-context-{}-{index}", std::process::id())
}

/// Whether `name` is one [`upload_name`] makes (one component, nothing to
/// follow).
pub fn is_upload_name(name: &str) -> bool {
    name.starts_with(".velarx-context-") && !name.contains('/') && name != ".." && name != "."
}

/// A directory of a context exists and is one.
pub fn context_dir(path: &Path) -> Result<PathBuf, String> {
    let abs = path
        .canonicalize()
        .map_err(|e| format!("the build context {}: {e}", path.display()))?;
    if !abs.is_dir() {
        return Err(format!(
            "the build context {} is not a directory",
            path.display()
        ));
    }
    Ok(abs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_identity_label_follows_buildahs_rules() {
        let flags = |label, timestamp, epoch| BuildFlags {
            identity_label: label,
            timestamp,
            source_date_epoch: epoch,
            ..Default::default()
        };
        assert!(flags(None, None, None).identity());
        assert!(!flags(None, Some(0), None).identity());
        assert!(!flags(None, None, Some(5)).identity());
        assert!(flags(Some(true), Some(0), None).identity());
        assert!(flags(Some(true), None, Some(5)).identity());
        assert!(!flags(Some(false), None, None).identity());
    }

    #[test]
    fn a_directory_output_has_no_setuid_and_nothing_outside() {
        use std::os::unix::fs::PermissionsExt;
        let mut b = tar::Builder::new(Vec::new());
        let file = |b: &mut tar::Builder<Vec<u8>>, path: &str, mode, kind, link: &str| {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(kind);
            h.set_mode(mode);
            h.set_size(if kind == tar::EntryType::Regular {
                1
            } else {
                0
            });
            if !link.is_empty() {
                h.set_link_name(link).unwrap();
            }
            b.append_data(&mut h, path, &b"x"[..kind.is_file() as usize])
                .unwrap();
        };
        let reg = tar::EntryType::Regular;
        file(&mut b, "suid", 0o4755, reg, "");
        file(&mut b, "sgid", 0o2755, reg, "");
        file(&mut b, "esc", 0o777, tar::EntryType::Symlink, "../outside");
        file(&mut b, "esc/pwned", 0o644, reg, "");
        let d = tempfile::tempdir().unwrap();
        let out = d.path().join("out");
        // (the entry below the link is refused)
        assert!(Output::Dir(out.clone())
            .write(&b.into_inner().unwrap()[..], &mut |w| panic!("{w}"))
            .is_err());
        let mode = |n: &str| std::fs::metadata(out.join(n)).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode("suid"), 0o755);
        assert_eq!(mode("sgid"), 0o755);
        assert!(!d.path().join("outside").exists());
        assert!(!d.path().join("pwned").exists());
    }

    /// What a directory output does not make is told: a device node, a
    /// fifo.
    #[test]
    fn a_directory_output_tells_what_it_does_not_write() {
        let mut b = tar::Builder::new(Vec::new());
        for (path, kind) in [
            ("dev/null", tar::EntryType::Char),
            ("fifo", tar::EntryType::Fifo),
            ("file", tar::EntryType::Regular),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(kind);
            h.set_mode(0o644);
            h.set_size(0);
            b.append_data(&mut h, path, &b""[..]).unwrap();
        }
        let d = tempfile::tempdir().unwrap();
        let mut told = Vec::new();
        Output::Dir(d.path().to_path_buf())
            .write(&b.into_inner().unwrap()[..], &mut |w| told.push(w))
            .unwrap();
        assert_eq!(
            told,
            [
                "WARNING: --output: the device node dev/null is not written",
                "WARNING: --output: the fifo fifo is not written",
            ]
        );
        assert!(d.path().join("file").is_file());
        assert!(!d.path().join("dev/null").exists());
        assert!(!d.path().join("fifo").exists());
    }

    #[test]
    fn secrets_as_buildah_reads_them() {
        let has = |n: &str| n == "TOKEN";
        assert_eq!(
            parse_secret("id=TOKEN", &has).unwrap(),
            ("TOKEN".into(), SecretSource::Env("TOKEN".into()))
        );
        assert_eq!(
            parse_secret("id=a", &has).unwrap(),
            ("a".into(), SecretSource::File("a".into()))
        );
        assert_eq!(
            parse_secret("id=a,src=/f", &has).unwrap().1,
            SecretSource::File("/f".into())
        );
        assert_eq!(
            parse_secret("id=a,env=X", &has).unwrap().1,
            SecretSource::Env("X".into())
        );
        assert_eq!(
            parse_secret("id=a,src=X,type=env", &has).unwrap().1,
            SecretSource::Env("X".into())
        );
        for bad in ["src=x", "id=", "id=a,type=pipe", "id=a,what=1", "a"] {
            assert!(parse_secret(bad, &has).is_err(), "{bad}");
        }
        let s = read_secret("a", &SecretSource::Env("V".into()), &|_| Some("v".into())).unwrap();
        assert_eq!(s.value, b"v");
        assert!(!format!("{s:?}").contains("\"v\""));
        assert!(format!("{s:?}").contains("<redacted>"));
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<BuildSecret>(&json).unwrap(), s);
        assert!(read_secret("a", &SecretSource::Env("V".into()), &|_| None).is_err());
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("big"), vec![b'x'; MAX_SECRET as usize + 1]).unwrap();
        assert!(read_secret("a", &SecretSource::File(d.path().join("big")), &|_| None).is_err());
    }

    #[test]
    fn build_contexts_and_agents() {
        assert!(matches!(
            parse_build_context("a=docker-image://alpine").unwrap().1,
            ContextValue::Image(i) if i == "alpine"
        ));
        assert!(matches!(
            parse_build_context("a=https://x/y.tar").unwrap().1,
            ContextValue::Url(_)
        ));
        assert!(matches!(
            parse_build_context("a=../dir").unwrap().1,
            ContextValue::Dir(_)
        ));
        for bad in ["a", "=x", "a=", "a=ftp://x"] {
            assert!(parse_build_context(bad).is_err(), "{bad}");
        }
        for url in [
            "https://h/x.tar",
            "git://h/r",
            "git@h:r.git",
            "github.com/o/r",
        ] {
            assert!(is_remote_context(url), "{url}");
            assert!(parse_build_context(&format!("n={url}")).is_ok(), "{url}");
        }
        assert!(!is_remote_context("./github.com/o/r") && !is_remote_context("-"));
        assert!(is_remote_file("https://h/Containerfile") && !is_remote_file("git://h/x"));
        assert!(is_upload_name(&upload_name(3)));
        assert!(!is_upload_name("../x") && !is_upload_name(".velarx-context-1/x"));

        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("agent");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let env = |_: &str| Some(sock.to_string_lossy().into_owned());
        assert_eq!(
            parse_ssh("default", &env).unwrap(),
            ("default".into(), sock.clone())
        );
        let spec = format!("k={}", sock.display());
        assert_eq!(parse_ssh(&spec, &|_| None).unwrap().0, "k");
        std::fs::write(d.path().join("key"), "k").unwrap();
        let key = format!("k={}", d.path().join("key").display());
        assert!(parse_ssh(&key, &|_| None).unwrap_err().contains("ssh-add"));
        assert!(parse_ssh("default", &|_| None).is_err());

        // the broker gives a connection to the agent
        let (engine, client) = std::os::unix::net::UnixStream::pair().unwrap();
        let agents = vec![sock.clone()];
        let served = std::thread::spawn(move || serve_broker(client, &agents));
        let fd = broker_connect(&engine, 0).unwrap();
        let mut conn = std::os::unix::net::UnixStream::from(fd);
        let (mut accepted, _) = listener.accept().unwrap();
        conn.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        accepted.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        assert!(broker_connect(&engine, 7).is_err());
        drop(engine);
        served.join().unwrap();
    }
}
