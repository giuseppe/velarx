// SPDX-License-Identifier: Apache-2.0
//! What `container run` and `container create` do around the request:
//! pulling the image by policy and the file with the container id.

use super::{ClientError, ClientResult, EngineClient, PullOptions};
use crate::cli::PullPolicy;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Whether to pull, given the policy and whether the image is present.
pub fn needs_pull(policy: PullPolicy, present: bool) -> bool {
    match policy {
        PullPolicy::Always => true,
        PullPolicy::Missing | PullPolicy::Newer => !present,
        PullPolicy::Never => false,
    }
}

/// Whether the registry serves another image than the store has for
/// `image`: false when it serves the same, and when it cannot be asked
/// (the image of the store is used, as podman's).
pub fn newer_in_registry(client: &EngineClient, image: &str, pull: &PullOptions<'_>) -> bool {
    client
        .remote_digest(image, pull.tls_verify, pull.platform, pull.access)
        .is_ok_and(|d| d.local.as_deref() != Some(d.remote.as_str()))
}

/// How a failed pull or push is tried again (`--retry`, `--retry-delay`):
/// the engine does it, 3 times by default as podman's.
pub fn retry_of(
    count: Option<u32>,
    delay: Option<&str>,
) -> Result<velarx_proto::retry::Retry, String> {
    Ok(velarx_proto::retry::Retry {
        count: count.unwrap_or(3),
        delay_ms: delay
            .map(parse_duration)
            .transpose()?
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
    })
}

/// A duration as podman takes it (Go's: `500ms`, `10s`, `1m30s`), or
/// seconds.
pub fn parse_duration(s: &str) -> Result<std::time::Duration, String> {
    let s = s.trim();
    match s.parse::<f64>() {
        Ok(secs) => std::time::Duration::try_from_secs_f64(secs).ok(),
        Err(_) => velarx_proto::duration::parse_go_duration(s),
    }
    .ok_or_else(|| format!("invalid duration `{s}`"))
}

/// How a pull is shown to a user (the progress bars of a terminal).
pub type ShowPull = dyn Fn(&EngineClient, &str, &PullOptions<'_>, bool) -> ClientResult<()>;

/// What [`ensure_image_with`] makes sure of.
#[derive(Clone, Copy)]
pub struct EnsureImage<'a> {
    pub image: &'a str,
    pub policy: PullPolicy,
    pub pull: PullOptions<'a>,
    pub quiet: bool,
    pub show: Option<&'a ShowPull>,
    /// Pull lazily (`run --lazy`)
    pub lazy: bool,
}

/// Make sure the image is there as the pull policy says, pulling it when it
/// is not (the engine tries a failed pull again as `pull.retry` says);
/// `quiet`: with nothing said of the pull; `show`: how the pull is shown
/// (the progress bars of a terminal); `lazy`: pulled lazily.  A pull in
/// progress of the image is there for `--pull=never`: the engine runs on
/// it (`--lazy`) or completes it first.
pub fn ensure_image_with(client: &EngineClient, ask: &EnsureImage<'_>) -> ClientResult<()> {
    let EnsureImage {
        image,
        policy,
        pull,
        ..
    } = *ask;
    let present = match policy {
        PullPolicy::Always => false,
        PullPolicy::Missing | PullPolicy::Never | PullPolicy::Newer => {
            match client.inspect_image(image) {
                // (an image of another platform is not the one asked for)
                Ok(info) => {
                    pull.platform.is_none_or(|p| platform_matches(&info, p))
                        && (policy != PullPolicy::Newer || !newer_in_registry(client, image, &pull))
                }
                // (a reference podman refuses is not an image to pull)
                Err(e) if e.is_not_found() && !crate::cli::report::refused_image(&e) => {
                    policy == PullPolicy::Never && client.image_pulling(image)?
                }
                Err(e) => return Err(e),
            }
        }
    };
    if policy == PullPolicy::Never && !present {
        // podman's words
        return Err(crate::client::ClientError::refused(
            velarx_proto::engine::Condition::NoSuchImage,
            format!("{image}: image not known"),
        ));
    }
    if needs_pull(policy, present) {
        pull_with(client, ask)?;
    }
    Ok(())
}

/// Pull the image of `ask` now, as its `quiet`, `show` and `lazy` say:
/// for an image the engine just said it does not have.
pub fn pull_with(client: &EngineClient, ask: &EnsureImage<'_>) -> ClientResult<()> {
    let EnsureImage {
        image,
        pull,
        quiet,
        show,
        lazy,
        ..
    } = *ask;
    if !quiet {
        eprintln!("Trying to pull {image}...");
    }
    match show {
        _ if lazy => {
            client.pull_image_lazy(image, &pull)?;
        }
        Some(show) => show(client, image, &pull, quiet)?,
        None => {
            client.pull_image(image, &pull)?;
        }
    }
    Ok(())
}

/// Whether the image (its inspect) is for `OS/ARCH[/VARIANT]`.
fn platform_matches(info: &velarx_proto::workload::ImageRecord, platform: &str) -> bool {
    let mut parts = platform.split('/');
    let (os, arch, variant) = (parts.next(), parts.next(), parts.next());
    os.is_none_or(|o| o == info.os)
        && arch.is_none_or(|a| a == info.architecture)
        && variant.is_none_or(|v| v == info.variant)
}

/// The file `--cidfile` names: opened when the command starts, so that a
/// path it cannot write fails before the container is made, filled with the
/// id (what it had is replaced, as podman's), and removed again if the
/// container is not created and the command made the file.
pub struct CidFile {
    file: Option<std::fs::File>,
    path: PathBuf,
    made: bool,
    written: bool,
}

impl CidFile {
    pub fn create_at(path: &str) -> ClientResult<Self> {
        Self::create(Path::new(path))
    }

    /// The file for the container ID: made, or opened as it is if it is
    /// there (it is emptied when the ID is written).
    pub fn create(path: &Path) -> ClientResult<Self> {
        let open = |new: bool| {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(new)
                .mode(0o644)
                .open(path)
        };
        let (file, made) = match open(true) {
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (open(false), false),
            r => (r, true),
        };
        let file = file
            .map_err(|e| ClientError::Request(format!("cannot create {}: {e}", path.display())))?;
        Ok(Self {
            file: Some(file),
            path: path.to_path_buf(),
            made,
            written: false,
        })
    }

    pub fn write(&mut self, id: &str) -> ClientResult<()> {
        if let Some(mut f) = self.file.take() {
            f.set_len(0)
                .and_then(|()| f.write_all(id.as_bytes()))
                .map_err(|e| {
                    ClientError::Request(format!("cannot write {}: {e}", self.path.display()))
                })?;
            self.written = true;
        }
        Ok(())
    }
}

impl Drop for CidFile {
    fn drop(&mut self) {
        if self.made && !self.written {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn durations_and_waits_of_retries() {
        use std::time::Duration;
        assert_eq!(parse_duration("10s"), Ok(Duration::from_secs(10)));
        assert_eq!(parse_duration("500ms"), Ok(Duration::from_millis(500)));
        assert_eq!(parse_duration("2m"), Ok(Duration::from_secs(120)));
        assert_eq!(parse_duration("3"), Ok(Duration::from_secs(3)));
        assert_eq!(parse_duration("1m30s"), Ok(Duration::from_secs(90)));
        assert!(parse_duration("-1").is_err());
        assert!(parse_duration("x").is_err());
        assert!(parse_duration("1d").is_err());
        assert_eq!(
            retry_of(Some(3), None).unwrap().wait(),
            Duration::from_secs(1)
        );
        let r = retry_of(Some(1), Some("5s")).unwrap();
        assert_eq!((r.count, r.delay_ms), (1, Some(5000)));
        assert_eq!(retry_of(None, None).unwrap().count, 3);
        assert_eq!(retry_of(Some(0), None).unwrap(), Default::default());
    }

    use super::*;

    #[test]
    fn pull_policies() {
        use PullPolicy::*;
        assert!(needs_pull(Always, true));
        // (newer: present is false when the registry has another image)
        assert!(needs_pull(Newer, false));
        assert!(!needs_pull(Newer, true));
        assert!(needs_pull(Missing, false));
        assert!(!needs_pull(Missing, true));
        assert!(!needs_pull(Never, false));
    }

    #[test]
    fn pull_policy_names() {
        use crate::cli::parse_pull_policy as p;
        assert_eq!(p("always"), Ok(PullPolicy::Always));
        assert_eq!(p("true"), Ok(PullPolicy::Always));
        assert_eq!(p("false"), Ok(PullPolicy::Never));
        assert_eq!(p("missing"), Ok(PullPolicy::Missing));
        assert_eq!(p("newer"), Ok(PullPolicy::Newer));
        assert_eq!(
            p("sometimes"),
            Err("unsupported pull policy \"sometimes\"".into())
        );
    }

    #[test]
    fn cidfile_is_replaced_and_removed_unless_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cid");
        std::fs::write(&path, "old content of a longer file").unwrap();
        // (a container that is not made leaves the file that was there)
        drop(CidFile::create(&path).unwrap());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "old content of a longer file"
        );
        let mut a = CidFile::create(&path).unwrap();
        a.write("abc").unwrap();
        drop(a);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "abc");

        let other = dir.path().join("other");
        drop(CidFile::create(&other).unwrap());
        assert!(!other.exists());
    }
}
