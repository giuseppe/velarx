// SPDX-License-Identifier: Apache-2.0
//! The transports of the image names of the command line (`pull`, `push`,
//! `run`, `create`): `docker://` and a plain name are a registry's, and
//! `oci:`, `oci-archive:`, `docker-archive:`, `dir:` and `rootfs:` are pulled
//! from a path — or written from the store, for the OCI ones, by a push —
//! and `docker-daemon:` from the socket of a Docker daemon, which the engine
//! connects to.  The
//! syntax is `velarx_types::transport`'s.
//!
//! The command opens the path and the engine pulls from it, as from any
//! origin: `velarx-dir` reads it, confined, and the engine checks what it
//! says.  An OCI layout or archive that is read must hold the one image that
//! the name selects (`oci:PATH:TAG` is the entry whose
//! `org.opencontainers.image.ref.name` is `TAG`); a `dir:` holds one manifest
//! and its blobs.  A docker-archive (`docker save`) is read with podman's
//! selector: `:REF` the first image whose `RepoTags` has `REF`, `:@N` the
//! N-th entry of its `manifest.json`, and none at all is the one image the
//! archive must hold.  Docker schema 2 is read as everywhere; schema 1 and
//! foreign layers are refused.  Writing the docker-archive is refused (`save`
//! writes OCI only).

use crate::client::EngineClient;
use anyhow::{anyhow, bail};
use std::path::{Path, PathBuf};
use velarx_types::transport::ImageLocation;

/// What a name with a transport is for a command that pulls.
pub enum Source {
    /// An image of a registry: the name to pull.
    Name(String),
    /// An image of the store: the name to use.
    Local(String),
    /// Images read into the store.
    Imported(Vec<velarx_proto::workload::PulledImage>),
}

/// A name that only a registry has (`docker://` or no transport).
pub fn registry(spec: &str, what: &str) -> anyhow::Result<String> {
    Ok(ImageLocation::registry(spec, what)?)
}

/// Where the pull of `spec` gets its image: a registry (or the store) by
/// name, a transport of `[[transports]]` by its text, or a layout, an archive
/// or a directory, which is opened here and pulled by the engine now.
pub fn pull(client: &EngineClient, spec: &str, platform: Option<&str>) -> anyhow::Result<Source> {
    if ImageLocation::external(spec)?.is_some() {
        return Ok(Source::Name(spec.to_string()));
    }
    let (path, directory) = match ImageLocation::parse(spec)? {
        ImageLocation::Registry(name) => return Ok(Source::Name(name)),
        ImageLocation::Storage(name) => return Ok(Source::Local(name)),
        ImageLocation::DockerDaemon { .. } => return Ok(Source::Name(spec.to_string())),
        ImageLocation::OciLayout { path, .. }
        | ImageLocation::Dir { path }
        | ImageLocation::Rootfs { path } => (path, true),
        ImageLocation::OciArchive { path, .. } | ImageLocation::DockerArchive { path, .. } => {
            (path, false)
        }
    };
    let source = open_source(spec, Path::new(&path), directory)?;
    Ok(Source::Imported(source.pull(client, spec, platform, None)?))
}

/// The path of a pull, opened for the engine: a directory, a file, or a
/// stream.
pub fn open_source(spec: &str, path: &Path, directory: bool) -> anyhow::Result<PathSource> {
    let file = std::fs::File::open(path)
        .map_err(|e| anyhow!("{spec}: cannot open `{}`: {e}", path.display()))?;
    let meta = file.metadata()?;
    match (directory, meta.is_dir(), meta.is_file()) {
        (true, true, _) | (false, _, true) => Ok(PathSource::Fd(file.into())),
        (true, false, _) => bail!("{spec}: `{}` is not a directory", path.display()),
        (false, true, _) => bail!("{spec}: `{}` is a directory", path.display()),
        (false, false, false) => Ok(PathSource::Stream(file)),
    }
}

/// The image a command that runs or creates a container uses for `spec`:
/// a name, or the image that was read.
pub fn image_for_run(
    client: &EngineClient,
    spec: &str,
    platform: Option<&str>,
) -> anyhow::Result<String> {
    match pull(client, spec, platform)? {
        Source::Name(name) | Source::Local(name) => Ok(name),
        Source::Imported(images) => Ok(one_image(spec, &images)?.id.clone()),
    }
}

/// The one image that a read of `spec` made.
pub fn one_image<'a>(
    spec: &str,
    images: &'a [velarx_proto::workload::PulledImage],
) -> anyhow::Result<&'a velarx_proto::workload::PulledImage> {
    match images {
        [one] => Ok(one),
        _ => bail!("{spec}: {} images were read, one is expected", images.len()),
    }
}

/// The destination of a push that is a path, opened here for the engine:
/// the pusher writes beneath it and nothing else.
pub struct Opened {
    /// The directory, or the file of an archive, open for writing
    pub fd: std::sync::Arc<std::os::fd::OwnedFd>,
    /// An archive is written to a file next to its name, which replaces it
    /// once the push succeeded (a failure leaves the archive that was there)
    replace: Option<(tempfile::NamedTempFile, PathBuf)>,
}

impl Opened {
    /// The push succeeded: an archive takes its name.
    pub fn finish(self) -> anyhow::Result<()> {
        if let Some((file, path)) = self.replace {
            file.persist(&path)
                .map_err(|e| anyhow!("cannot write `{}`: {}", path.display(), e.error))?;
        }
        Ok(())
    }
}

/// The name of the registry a push to `destination` goes to; an error for
/// the destinations that cannot be pushed to.
pub fn registry_destination(destination: &ImageLocation) -> anyhow::Result<Option<String>> {
    match destination {
        ImageLocation::Registry(name) => Ok(Some(name.clone())),
        ImageLocation::Storage(_) => bail!(
            "pushing to containers-storage: is not supported: the image is in the store already, `tag` gives it a name"
        ),
        ImageLocation::DockerArchive { .. } => {
            Err(anyhow!("{}", velarx_types::docker::archive_refusal()))
        }
        ImageLocation::DockerDaemon { .. } | ImageLocation::Rootfs { .. } => bail!(
            "{} is a source of a pull, not a destination",
            destination.transport()
        ),
        _ => Ok(None),
    }
}

/// Open the layout, the archive or the directory `destination` names, for a
/// push: none for a registry.  `compress`: the layers of a `dir:` are
/// compressed with gzip (`push --compress`), refused for the others.
pub fn open_destination(
    destination: &ImageLocation,
    compress: bool,
) -> anyhow::Result<Option<Opened>> {
    use velarx_base::push_path::{check_destination, Mode};
    if compress && !matches!(destination, ImageLocation::Dir { .. }) {
        bail!("--compress is for the destinations of the dir: transport");
    }
    let directory = |path: &str, mode: Mode| -> anyhow::Result<Option<Opened>> {
        std::fs::create_dir_all(path).map_err(|e| anyhow!("cannot create `{path}`: {e}"))?;
        let dir = std::fs::File::open(path).map_err(|e| anyhow!("cannot open `{path}`: {e}"))?;
        check_destination(&dir, mode).map_err(|why| anyhow!("`{path}`: {why}"))?;
        Ok(Some(Opened {
            fd: std::sync::Arc::new(dir.into()),
            replace: None,
        }))
    };
    match destination {
        ImageLocation::OciLayout { path, .. } => directory(path, Mode::Layout),
        ImageLocation::Dir { path } => directory(path, Mode::Dir),
        ImageLocation::OciArchive { path, .. } => {
            let file = temporary_next_to(Path::new(path))
                .map_err(|e| anyhow!("cannot create `{path}`: {e}"))?;
            let fd = file.as_file().try_clone()?;
            Ok(Some(Opened {
                fd: std::sync::Arc::new(fd.into()),
                replace: Some((file, PathBuf::from(path))),
            }))
        }
        _ => Ok(None),
    }
}

/// A file in the directory of `path`, to be renamed to it once complete.
fn temporary_next_to(path: &Path) -> std::io::Result<tempfile::NamedTempFile> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let file = tempfile::Builder::new()
        .prefix(".velarx-")
        .tempfile_in(parent)?;
    // (the mode of the file it replaces, else 0644: not the 0600 of a
    // temporary file)
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path).map_or(0o644, |m| m.permissions().mode() & 0o7777);
    file.as_file()
        .set_permissions(std::fs::Permissions::from_mode(mode))?;
    Ok(file)
}

/// What the command opened for the engine to pull from: a file or a
/// directory the engine reads where it is, or a stream (a FIFO, the
/// `/dev/fd/N` of a pipe, the standard input) it is sent as the frames of an
/// upload.
pub enum PathSource {
    Fd(std::os::fd::OwnedFd),
    Stream(std::fs::File),
}

impl PathSource {
    /// Pull what `spec` names from it; the progress of the layers told to `on`.
    pub fn pull(
        self,
        client: &EngineClient,
        spec: &str,
        platform: Option<&str>,
        on: Option<crate::client::Progress<'_>>,
    ) -> crate::client::ClientResult<Vec<velarx_proto::workload::PulledImage>> {
        match self {
            PathSource::Fd(fd) => client.pull_path(spec, fd, platform, on),
            PathSource::Stream(mut file) => client.pull_upload(
                spec,
                platform,
                Box::new(move |w| std::io::copy(&mut file, w).map(|_| ())),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_is_read_where_it_is_and_a_stream_is_sent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.tar");
        std::fs::write(&path, b"archive bytes").unwrap();
        assert!(matches!(
            open_source("oci-archive:a", &path, false).unwrap(),
            PathSource::Fd(_)
        ));
        assert!(matches!(
            open_source("oci:a", dir.path(), true).unwrap(),
            PathSource::Fd(_)
        ));
        // a FIFO is a stream
        let fifo = dir.path().join("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        let writer = {
            let fifo = fifo.clone();
            std::thread::spawn(move || std::fs::write(fifo, b"through a pipe").unwrap())
        };
        let opened = open_source("oci-archive:f", &fifo, false).unwrap();
        let PathSource::Stream(mut file) = opened else {
            panic!("a FIFO is a stream");
        };
        let mut got = String::new();
        std::io::Read::read_to_string(&mut file, &mut got).unwrap();
        writer.join().unwrap();
        assert_eq!(got, "through a pipe");
        assert!(open_source("oci-archive:n", &dir.path().join("none"), false).is_err());
    }
}
