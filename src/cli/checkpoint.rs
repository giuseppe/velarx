// SPDX-License-Identifier: Apache-2.0
//! `container checkpoint` and `container restore`, as podman's: the
//! engine checkpoints through the runtime and restores in a new monitor.

use crate::client::{ClientError, EngineClient};
use clap::Args;
use velarx_proto::engine::Condition;
use velarx_proto::workload::{CheckpointReport, RestoreReport};
use velarx_wire::wire::{CheckpointOptions, RestoreOptions};

#[derive(Args, Clone, Debug, Default)]
pub struct CheckpointArgs {
    /// Checkpoint all running containers
    #[arg(long, short)]
    pub all: bool,
    /// Leave the container running after the checkpoint
    #[arg(long, short = 'R')]
    pub leave_running: bool,
    /// Checkpoint established TCP connections
    #[arg(long)]
    pub tcp_established: bool,
    /// Checkpoint file locks
    #[arg(long)]
    pub file_locks: bool,
    /// Keep the checkpoint files after a restore
    #[arg(long, short)]
    pub keep: bool,
    /// Export the checkpoint to a tar archive
    #[arg(long, short)]
    pub export: Option<std::path::PathBuf>,
    /// Leave the changes of the root file system out of the export
    #[arg(long)]
    pub ignore_rootfs: bool,
    /// Leave the volumes out of the export
    #[arg(long)]
    pub ignore_volumes: bool,
    /// The compression of the export: zstd, gzip or none
    #[arg(long, short)]
    pub compress: Option<String>,
    /// Share the exported archive with the peers (with --export): its
    /// reference is printed, for `restore --import-from-peers` on another
    /// node
    #[arg(long)]
    pub share: bool,
    /// Stop sharing the checkpoint of this reference (or of its manifest,
    /// `sha256:HEX`): as --import-from-peers, `-`, `@FILE` or `env:NAME`
    #[arg(long, value_name = "REFERENCE")]
    pub unshare: Option<String>,
    /// Display checkpoint statistics
    #[arg(long)]
    pub print_stats: bool,
    /// Dump the memory only, leave the container running
    #[arg(long, short = 'P')]
    pub pre_checkpoint: bool,
    /// Checkpoint on top of the pre-checkpoint
    #[arg(long)]
    pub with_previous: bool,
    /// Make an image of this name of the checkpoint, to restore with
    /// `container restore NAME`
    #[arg(long)]
    pub create_image: Option<String>,
    /// Act on the latest container
    #[arg(long, short)]
    pub latest: bool,
    /// The containers
    pub containers: Vec<String>,
}

#[derive(Args, Clone, Debug, Default)]
pub struct RestoreArgs {
    /// Restore all checkpointed containers
    #[arg(long, short)]
    pub all: bool,
    /// Keep the checkpoint files after the restore
    #[arg(long, short)]
    pub keep: bool,
    /// Restore established TCP connections
    #[arg(long)]
    pub tcp_established: bool,
    /// Restore with the established TCP connections closed
    #[arg(long)]
    pub tcp_close: bool,
    /// Restore file locks
    #[arg(long)]
    pub file_locks: bool,
    /// Restore from a checkpoint archive (`checkpoint --export`).  The
    /// process images of the archive are restored as they are: restore only
    /// archives that you made or that come from a source you trust
    #[arg(long, short)]
    pub import: Option<std::path::PathBuf>,
    /// Restore from the archive a node shares (`checkpoint --share`), by
    /// its reference: from the content sources (the peers).  The reference
    /// holds the key of the archive: `-` reads it from the standard input,
    /// `@FILE` from a file, `env:NAME` from a variable, so that it is not
    /// in the command line of the process
    #[arg(long, value_name = "REFERENCE", conflicts_with = "import")]
    pub import_from_peers: Option<String>,
    /// The name of the container restored from an archive
    #[arg(long, short)]
    pub name: Option<String>,
    /// Leave the changes of the root file system of the archive out
    #[arg(long)]
    pub ignore_rootfs: bool,
    /// Leave the volumes of the archive out
    #[arg(long)]
    pub ignore_volumes: bool,
    /// Do not take the static IP addresses of the archive
    #[arg(long)]
    pub ignore_static_ip: bool,
    /// Do not take the static MAC addresses of the archive
    #[arg(long)]
    pub ignore_static_mac: bool,
    /// Display restore statistics
    #[arg(long)]
    pub print_stats: bool,
    /// The digest (sha256:... or sha512:...) of the image the container is made from, of
    /// an image mounted in it too (repeat): the restore holds the images to
    /// it, as `start --verify-image` does
    #[arg(long, value_name = "DIGEST")]
    pub verify_image: Vec<String>,
    /// The archive of a pre-checkpoint (`checkpoint --pre-checkpoint
    /// --export`) the archive of --import or --import-from-peers builds on
    #[arg(long)]
    pub import_previous: Option<std::path::PathBuf>,
    /// Restore into this pod (with --import)
    #[arg(long)]
    pub pod: Option<String>,
    /// Publish these ports instead of those of the archive (with --import)
    #[arg(long, short, value_delimiter = ',')]
    pub publish: Vec<String>,
    /// Act on the latest container
    #[arg(long, short)]
    pub latest: bool,
    /// The containers (or, with --import, none)
    pub containers: Vec<String>,
}

/// A path the engine takes: absolute, from the current directory.
fn absolute(p: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
    Ok(std::path::absolute(p)?)
}

fn unsupported(flag: &str, what: &str) -> anyhow::Error {
    anyhow::anyhow!("{flag} is not supported: {what}")
}

impl CheckpointArgs {
    /// The options CRIU and the runtime take; what has no equivalent is
    /// refused here, by name.
    pub fn options(&self) -> anyhow::Result<CheckpointOptions> {
        if self.create_image.is_some() {
            if self.export.is_some() {
                anyhow::bail!("--create-image can not be used with --export");
            }
            if self.pre_checkpoint || self.with_previous {
                return Err(unsupported(
                    "--create-image",
                    "not with --pre-checkpoint or --with-previous: an image holds one checkpoint",
                ));
            }
        }
        if self.export.is_none()
            && (self.ignore_rootfs || self.ignore_volumes || self.compress.is_some())
        {
            anyhow::bail!("--ignore-rootfs, --ignore-volumes and --compress go with --export");
        }
        if self.with_previous && self.pre_checkpoint {
            anyhow::bail!("--with-previous can not be used with --pre-checkpoint");
        }
        if self.all && self.latest {
            anyhow::bail!("--all and --latest cannot be used together");
        }
        if (self.all || self.latest) && !self.containers.is_empty() {
            anyhow::bail!("--all or --latest and containers cannot be used together");
        }
        if !self.all && !self.latest && self.containers.is_empty() {
            anyhow::bail!("you must provide at least one name or id");
        }
        if self.export.is_some()
            && self.containers.len() + usize::from(self.all || self.latest) != 1
        {
            anyhow::bail!("--export takes one container");
        }
        Ok(CheckpointOptions {
            leave_running: self.leave_running,
            create_image: self.create_image.clone(),
            tcp_established: self.tcp_established,
            file_locks: self.file_locks,
            export: self.export.as_deref().map(absolute).transpose()?,
            compress: self.compress.clone(),
            ignore_rootfs: self.ignore_rootfs,
            ignore_volumes: self.ignore_volumes,
            keep: self.keep,
            print_stats: self.print_stats,
            pre_checkpoint: self.pre_checkpoint,
            with_previous: self.with_previous,
        })
    }
}

impl RestoreArgs {
    pub fn options(&self) -> anyhow::Result<RestoreOptions> {
        if self.all && !self.verify_image.is_empty() {
            anyhow::bail!(
                "--verify-image: the digests are of the images of one container: name it, without --all"
            );
        }
        if self.name.is_some() && self.tcp_established {
            // (two containers would have the connections)
            anyhow::bail!("--tcp-established cannot be used with --name");
        }
        let importing = self.import.is_some() || self.import_from_peers.is_some();
        if !importing && self.import_previous.is_some() {
            anyhow::bail!("--import-previous can only be used with --import");
        }
        if importing {
            if self.all || self.latest {
                anyhow::bail!("cannot use --import with --all or --latest");
            }
            if !self.containers.is_empty() {
                anyhow::bail!("cannot use --import with positional arguments");
            }
        } else {
            if (self.all || self.latest) && !self.containers.is_empty() {
                anyhow::bail!("--all or --latest and containers cannot be used together");
            }
            if !self.all && !self.latest && self.containers.is_empty() {
                anyhow::bail!("you must provide at least one name or id");
            }
        }
        Ok(RestoreOptions {
            tcp_established: self.tcp_established,
            tcp_close: self.tcp_close,
            file_locks: self.file_locks,
            keep: self.keep,
            import: self.import.as_deref().map(absolute).transpose()?,
            import_previous: self.import_previous.as_deref().map(absolute).transpose()?,
            name: self.name.clone(),
            ignore_rootfs: self.ignore_rootfs,
            ignore_static_ip: self.ignore_static_ip,
            ignore_static_mac: self.ignore_static_mac,
            pod: self.pod.clone(),
            publish: self.publish.clone(),
            print_stats: self.print_stats,
            verify_image: self.verify_image.clone(),
        })
    }
}

/// `container checkpoint`: each container, then its name as given; the
/// first error ends with status 125 after the others were tried.
pub fn checkpoint(client: &EngineClient, args: &CheckpointArgs) -> anyhow::Result<()> {
    let began = std::time::Instant::now();
    if let Some(r) = &args.unshare {
        if args.all || !args.containers.is_empty() || args.export.is_some() {
            anyhow::bail!("--unshare takes a reference alone");
        }
        client.unshare_checkpoint(&reference_arg(r)?)?;
        return Ok(());
    }
    if args.share && args.export.is_none() {
        anyhow::bail!("--share shares the archive of --export");
    }
    let opts = args.options()?;
    let targets = if args.all {
        client
            .list_containers(false, &[], false, false)?
            .into_iter()
            .map(|c| c.id)
            .collect()
    } else {
        let named = crate::cli::run::named_or_latest(client, args.latest, args.containers.clone())?;
        all_exist(client, &named, false, |n| {
            client.checkpoint_container(n, &opts, None).map(drop)
        })?;
        named
    };
    if let Some(path) = &opts.export {
        let [c] = targets.as_slice() else {
            anyhow::bail!("--export takes one container");
        };
        let report = export(client, c, &opts, path)?;
        if opts.print_stats {
            print_json(&CheckpointStatistics {
                podman_checkpoint_duration: began.elapsed().as_micros() as i64,
                container_statistics: Some(vec![report]),
            })?;
        } else {
            println!("{c}");
        }
        if args.share {
            let reference = client.share_checkpoint(path)?;
            println!("Shared as {reference}");
        }
        return Ok(());
    }
    let mut reports = Vec::new();
    let done = each(&targets, |c| {
        let report = client.checkpoint_container(c, &opts, None)?;
        // (--print-stats: the report instead of the name)
        if opts.print_stats {
            reports.push(report);
        }
        Ok(!opts.print_stats)
    });
    if opts.print_stats {
        print_json(&CheckpointStatistics {
            podman_checkpoint_duration: began.elapsed().as_micros() as i64,
            container_statistics: Some(reports).filter(|r| !r.is_empty()),
        })?;
    }
    done
}

/// What `checkpoint --print-stats` prints (podman's document).
#[derive(serde::Serialize)]
struct CheckpointStatistics {
    podman_checkpoint_duration: i64,
    container_statistics: Option<Vec<CheckpointReport>>,
}

/// What `restore --print-stats` prints.
#[derive(serde::Serialize)]
struct RestoreStatistics {
    podman_restore_duration: i64,
    container_statistics: Option<Vec<RestoreReport>>,
}

/// A document indented by four spaces, as podman writes them.
fn print_json(v: &impl serde::Serialize) -> anyhow::Result<()> {
    let mut out = Vec::new();
    let format = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    v.serialize(&mut serde_json::Serializer::with_formatter(
        &mut out, format,
    ))?;
    println!("{}", String::from_utf8_lossy(&out));
    Ok(())
}

/// A reference given as itself, `-` (the first line of the standard
/// input), `@FILE` (its first line) or `env:NAME` (a variable): the key it
/// holds need not be in the command line.
fn reference_arg(arg: &str) -> anyhow::Result<String> {
    let first_line = |text: String| text.lines().next().unwrap_or_default().trim().to_string();
    let r = if arg == "-" {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        first_line(line)
    } else if let Some(path) = arg.strip_prefix('@') {
        first_line(std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("{path}: {e}"))?)
    } else if let Some(name) = arg.strip_prefix("env:") {
        first_line(std::env::var(name).map_err(|_| anyhow::anyhow!("no variable {name}"))?)
    } else {
        arg.to_string()
    };
    if r.is_empty() {
        anyhow::bail!("no reference in `{arg}`");
    }
    Ok(r)
}

/// The archive of `checkpoint --export`, streamed by the engine and
/// written here: a new file next to `path` (0600: it holds process
/// memory), renamed over it once complete, so that nothing is written
/// through a link or into a file of someone else's.
fn export(
    client: &EngineClient,
    container: &str,
    opts: &CheckpointOptions,
    path: &std::path::Path,
) -> anyhow::Result<CheckpointReport> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => std::path::Path::new("."),
    };
    // (tempfile: O_CREAT | O_EXCL, 0600)
    let tmp = tempfile::Builder::new()
        .prefix(".velarx-checkpoint-")
        .tempfile_in(dir)?;
    let report = client.checkpoint_container(container, opts, Some(tmp.as_file()))?;
    tmp.as_file().sync_all()?;
    tmp.persist(path)
        .map_err(|e| anyhow::anyhow!("{}: {}", path.display(), e.error))?;
    Ok(report)
}

/// An archive to restore, opened here, as the user, and streamed: a regular
/// file only (O_NONBLOCK: a fifo does not block the open; nothing to a file).
fn open_archive(path: &std::path::Path) -> anyhow::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    if !file.metadata()?.is_file() {
        anyhow::bail!("{} is not a regular file", path.display());
    }
    Ok(file)
}

/// `container restore`.
pub fn restore(client: &EngineClient, args: &RestoreArgs) -> anyhow::Result<()> {
    let began = std::time::Instant::now();
    let opts = args.options()?;
    let mut reports = Vec::new();
    let done = restore_all(client, args, &opts, &mut reports);
    if opts.print_stats {
        print_json(&RestoreStatistics {
            podman_restore_duration: began.elapsed().as_micros() as i64,
            container_statistics: Some(reports).filter(|r| !r.is_empty()),
        })?;
    }
    done
}

/// The restores of `container restore`: the names (or, with --print-stats,
/// the reports) of those that were restored.
fn restore_all(
    client: &EngineClient,
    args: &RestoreArgs,
    opts: &RestoreOptions,
    reports: &mut Vec<RestoreReport>,
) -> anyhow::Result<()> {
    // (an import is told by the id of the container it made)
    let mut show = |r: RestoreReport| {
        if opts.print_stats {
            reports.push(r);
        } else {
            println!("{}", r.id);
        }
    };
    let previous = opts
        .import_previous
        .as_deref()
        .map(open_archive)
        .transpose()?;
    if let Some(reference) = &args.import_from_peers {
        show(client.restore_from_peers(opts, &reference_arg(reference)?, previous.as_ref())?);
        return Ok(());
    }
    if let Some(path) = &opts.import {
        show(client.restore_import(opts, &open_archive(path)?, previous.as_ref())?);
        return Ok(());
    }
    let targets = if args.all {
        client
            .list_containers(true, &[], false, false)?
            .into_iter()
            .filter(|c| c.state != velarx_proto::workload::RunState::Running)
            .map(|c| c.id)
            .collect()
    } else {
        let named = crate::cli::run::named_or_latest(client, args.latest, args.containers.clone())?;
        all_exist(client, &named, true, |n| {
            client.restore_container(n, opts).map(drop)
        })?;
        named
    };
    each(&targets, |c| match client.restore_container(c, opts) {
        // (--all: those without a checkpoint are not restored)
        Err(e) if args.all && e.is(Condition::NoCheckpoint) => Ok(false),
        Ok(r) if opts.print_stats => {
            show(r);
            Ok(false)
        }
        other => other.map(|_| true),
    })
}

/// podman looks all the containers up before it acts on the first: one
/// that is not there fails the command with nothing done.
/// `images`: a name may be that of a checkpoint image (a restore's).
/// `act`: the command, on a name that is not there: what it says before
/// that (a rootless engine needs root) is said, as podman's.
fn all_exist(
    client: &EngineClient,
    names: &[String],
    images: bool,
    act: impl Fn(&str) -> Result<(), ClientError>,
) -> anyhow::Result<()> {
    for n in names {
        if client.exists(crate::client::Kind::Container, n)?
            || (images && client.exists(crate::client::Kind::Image, n)?)
        {
            continue;
        }
        match act(n) {
            Err(e) if !e.is_not_found() => return Err(e.into()),
            _ if images => anyhow::bail!("no such container or image: {n}"),
            _ => anyhow::bail!("no container with name or ID \"{n}\" found: no such container"),
        }
    }
    Ok(())
}

/// The errors are said as podman's `PrintErrors` does: all but the last one
/// here, the last one as the error of the command.
fn each(
    targets: &[String],
    mut f: impl FnMut(&str) -> Result<bool, ClientError>,
) -> anyhow::Result<()> {
    let mut errors: Vec<ClientError> = Vec::new();
    crate::cli::run::each_item(
        targets,
        |t| {
            if f(t)? {
                println!("{t}");
            }
            Ok(())
        },
        |_, e| errors.push(e),
    )?;
    let Some(last) = errors.pop() else {
        return Ok(());
    };
    for e in &errors {
        eprintln!("Error: {e}");
    }
    Err(last.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_are_mapped_or_refused_by_name() {
        let a = CheckpointArgs {
            containers: vec!["c".into()],
            leave_running: true,
            tcp_established: true,
            file_locks: true,
            ..Default::default()
        };
        let o = a.options().unwrap();
        assert!(o.leave_running && o.tcp_established && o.file_locks);
        for (bad, flag) in [
            (
                CheckpointArgs {
                    with_previous: true,
                    pre_checkpoint: true,
                    ..a.clone()
                },
                "can not be used with",
            ),
            (
                CheckpointArgs {
                    create_image: Some("i".into()),
                    export: Some("/x".into()),
                    ..a.clone()
                },
                "--create-image",
            ),
            (
                CheckpointArgs {
                    ignore_rootfs: true,
                    ..a.clone()
                },
                "--export",
            ),
        ] {
            assert!(
                bad.options().unwrap_err().to_string().contains(flag),
                "{flag}"
            );
        }
        let o = CheckpointArgs {
            print_stats: true,
            pre_checkpoint: true,
            ..a.clone()
        }
        .options()
        .unwrap();
        assert!(o.print_stats && o.pre_checkpoint && !o.with_previous);
        assert!(
            CheckpointArgs {
                with_previous: true,
                ..a.clone()
            }
            .options()
            .unwrap()
            .with_previous
        );
        assert!(CheckpointArgs::default().options().is_err());
        let image = CheckpointArgs {
            create_image: Some("i".into()),
            ..a.clone()
        };
        assert_eq!(image.options().unwrap().create_image.as_deref(), Some("i"));
        assert!(CheckpointArgs {
            latest: true,
            containers: vec![],
            ..a.clone()
        }
        .options()
        .is_ok());
        let r = RestoreArgs {
            containers: vec!["c".into()],
            keep: true,
            ..Default::default()
        };
        assert!(r.options().unwrap().keep);
        assert!(
            RestoreArgs {
                print_stats: true,
                ..r.clone()
            }
            .options()
            .unwrap()
            .print_stats
        );
        for (bad, flag) in [
            (
                RestoreArgs {
                    import_previous: Some("x".into()),
                    ..r.clone()
                },
                "--import-previous",
            ),
            (
                RestoreArgs {
                    name: Some("n".into()),
                    tcp_established: true,
                    ..r.clone()
                },
                "--tcp-established",
            ),
        ] {
            assert!(
                bad.options().unwrap_err().to_string().contains(flag),
                "{flag}"
            );
        }
    }
}

#[cfg(test)]
mod statistics_tests {
    use super::*;
    use velarx_proto::workload::CriuStatistics;

    /// The document is podman's: four spaces, the keys in its order, the
    /// statistics without their zeros.
    #[test]
    fn the_statistics_are_podmans_document() {
        let mut out = Vec::new();
        let format = serde_json::ser::PrettyFormatter::with_indent(b"    ");
        let doc = CheckpointStatistics {
            podman_checkpoint_duration: 9,
            container_statistics: Some(vec![CheckpointReport {
                id: "abc".into(),
                runtime_checkpoint_duration: 7,
                criu_statistics: Some(CriuStatistics {
                    freezing_time: 1,
                    pages_written: 3,
                    ..Default::default()
                }),
            }]),
        };
        serde::Serialize::serialize(
            &doc,
            &mut serde_json::Serializer::with_formatter(&mut out, format),
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            r#"{
    "podman_checkpoint_duration": 9,
    "container_statistics": [
        {
            "Id": "abc",
            "runtime_checkpoint_duration": 7,
            "criu_statistics": {
                "freezing_time": 1,
                "pages_written": 3
            }
        }
    ]
}"#
        );
        let none = RestoreStatistics {
            podman_restore_duration: 1,
            container_statistics: None,
        };
        assert_eq!(
            serde_json::to_string(&none).unwrap(),
            r#"{"podman_restore_duration":1,"container_statistics":null}"#
        );
    }
}

#[cfg(test)]
mod reference_tests {
    use super::reference_arg;

    #[test]
    fn references_come_from_files_and_variables() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("ref");
        std::fs::write(&f, "sha256:abc:1:key\nmore\n").unwrap();
        assert_eq!(
            reference_arg(&format!("@{}", f.display())).unwrap(),
            "sha256:abc:1:key"
        );
        // (a variable every process has: the environment is not changed)
        let path = std::env::var("PATH").unwrap();
        assert_eq!(
            reference_arg("env:PATH").unwrap(),
            path.lines().next().unwrap().trim()
        );
        assert!(reference_arg("env:VELARX_TEST_NO_SUCH").is_err());
        assert_eq!(reference_arg("sha256:x:1:k").unwrap(), "sha256:x:1:k");
        std::fs::write(&f, "").unwrap();
        assert!(reference_arg(&format!("@{}", f.display())).is_err());
    }
}
