// SPDX-License-Identifier: Apache-2.0
//! `velarx cp`: copies between the host and a container with podman's
//! rules, through the archive endpoints of the daemon.  The daemon reads
//! and writes only in the root of the container; the host side is done
//! here, as the user, and a tar from the container is extracted with the
//! rules of [`velarx_wire::cp::extract`] (nothing written through a link or above
//! the destination).

use crate::client::{ArchivePut, ArchiveStat, EngineClient};
use anyhow::{anyhow, bail, Context};
use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{fstat, mkdir, openat, FileType, Mode, OFlags};
use std::collections::HashMap;
use std::io;
use std::path::Path;
use velarx_wire::cp::{self, ExtractOptions, TreeWriter};

/// `CONTAINER:PATH` split, `None` for a host path.
fn container_part(arg: &str) -> Option<(&str, &str)> {
    if arg.starts_with('/') || arg.starts_with('.') {
        return None;
    }
    let (c, p) = arg.split_once(':')?;
    (!c.is_empty() && !c.contains('/')).then_some((c, p))
}

/// The directory contents are copied, not the directory (`DIR/.`).
fn wants_contents(path: &str) -> bool {
    path == "." || path.ends_with("/.")
}

pub fn run(client: &EngineClient, src: &str, dest: &str, put: &ArchivePut) -> anyhow::Result<()> {
    match (container_part(src), container_part(dest)) {
        (Some((a, ap)), Some((b, bp))) => {
            let (ar, br) = (in_container(client, a, ap)?, in_container(client, b, bp)?);
            copy_between(client, a, &ar, b, &br, put)
                .map_err(|e| as_given(e, &[(&ar, ap), (&br, bp)]))
        }
        (None, None) => bail!("one of the source and the destination must be CONTAINER:PATH"),
        (Some((id, path)), None) => {
            let r = in_container(client, id, path)?;
            copy_out(client, id, &r, dest, put).map_err(|e| as_given(e, &[(&r, path)]))
        }
        (None, Some((id, path))) => {
            let r = in_container(client, id, path)?;
            copy_in(client, src, id, &r, put).map_err(|e| as_given(e, &[(&r, path)]))
        }
    }
}

/// An error that names a path of a container as it was given (podman's),
/// not as it was resolved in the working directory.
fn as_given(e: anyhow::Error, paths: &[(&str, &str)]) -> anyhow::Error {
    let mut text = e.to_string();
    for (resolved, given) in paths {
        if resolved != given {
            text = text.replace(&format!("\"{resolved}\""), &format!("\"{given}\""));
        }
    }
    anyhow!(text)
}

/// podman's words for a directory copied onto a file.
const DIR_ON_FILE: &str = "destination must be a directory when copying a directory";

/// A path of a container as podman takes it: a relative one is in the
/// working directory of the container.
fn in_container(client: &EngineClient, id: &str, path: &str) -> anyhow::Result<String> {
    if path.starts_with('/') {
        return Ok(path.to_string());
    }
    let info = client.inspect_container(id)?;
    let wd = Some(info.process.work_dir.as_str())
        .filter(|w| w.starts_with('/'))
        .unwrap_or("/");
    let wd = wd.trim_end_matches('/');
    Ok(match path {
        "" => format!("{wd}/"),
        p => format!("{wd}/{p}"),
    })
}

/// podman's words for a path of a container that is not there.
fn missing_in(id: &str, path: &str) -> anyhow::Error {
    anyhow!("\"{path}\" could not be found on container {id}: no such file or directory")
}

/// From a container to another: the tar of the one, extracted in the
/// other, with the rules of `copy_in` for the destination.
fn copy_between(
    client: &EngineClient,
    from: &str,
    src: &str,
    to: &str,
    path: &str,
    put: &ArchivePut,
) -> anyhow::Result<()> {
    let clean_src = cp::clean_path(src);
    let st = stat_in(client, from, &clean_src)?.ok_or_else(|| missing_in(from, src))?;
    let contents = st.is_dir && (clean_src == "/" || wants_contents(src));
    let (_, name) = cp::split_path(&clean_src);
    let clean = cp::clean_path(path);
    let mut rename = HashMap::new();
    let into = match stat_in(client, to, &clean)? {
        Some(dst) if dst.is_dir => dst.link_target,
        Some(dst) => {
            if st.is_dir {
                bail!(DIR_ON_FILE);
            }
            let (dir, base) = cp::split_path(&dst.link_target);
            rename.insert(name.clone(), base);
            dir
        }
        None => {
            if path.ends_with('/') && !st.is_dir {
                return Err(missing_in(to, path));
            }
            let (dir, base) = cp::split_path(&clean);
            let parent = stat_in(client, to, &dir)?
                .filter(|d| d.is_dir)
                .ok_or_else(|| missing_in(to, &dir))?;
            // the directory made under the new name, with what it has
            rename.insert(name.clone(), base);
            let asked = clean_src.clone();
            let mut tar = client
                .archive_get(from, &asked)
                .map_err(|e| anyhow!("{e}"))?;
            return client
                .archive_put(
                    to,
                    &parent.link_target,
                    &ArchivePut {
                        rename,
                        ..put.clone()
                    },
                    Box::new(|w| io::copy(&mut tar, w).map(|_| ())),
                )
                .map_err(|e| anyhow!("{e}"));
        }
    };
    let asked = if contents {
        format!("{clean_src}/.")
    } else {
        clean_src
    };
    let mut tar = client
        .archive_get(from, &asked)
        .map_err(|e| anyhow!("{e}"))?;
    client
        .archive_put(
            to,
            &into,
            &ArchivePut {
                rename,
                ..put.clone()
            },
            Box::new(|w| io::copy(&mut tar, w).map(|_| ())),
        )
        .map_err(|e| anyhow!("{e}"))
}

fn open_host(path: &str, flags: OFlags) -> anyhow::Result<OwnedFd> {
    openat(
        rustix::fs::CWD,
        path,
        flags | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("`{path}`"))
}

fn stat_in(client: &EngineClient, id: &str, path: &str) -> anyhow::Result<Option<ArchiveStat>> {
    client.archive_stat(id, path).map_err(|e| anyhow!("{e}"))
}

/// The name of the host file `path` in an archive.
fn host_name(path: &str) -> anyhow::Result<String> {
    let p = Path::new(path.trim_end_matches("/."));
    let name = match p.file_name() {
        Some(n) => n.to_os_string(),
        None => std::fs::canonicalize(p)
            .with_context(|| format!("`{path}`"))?
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_else(|| ".".into()),
    };
    name.into_string()
        .map_err(|_| anyhow!("the name of `{path}` is not valid UTF-8"))
}

/// The error of a copy from stdin: what the engine says is not a tar
/// archive, by its condition and not by its words.
fn stdin_error(e: crate::client::ClientError) -> anyhow::Error {
    if e.is(velarx_proto::engine::Condition::InvalidArchive) {
        anyhow!("source must be a (compressed) tar archive when copying from stdin")
    } else {
        anyhow!(e.to_string())
    }
}

fn copy_in(
    client: &EngineClient,
    src: &str,
    id: &str,
    path: &str,
    put: &ArchivePut,
) -> anyhow::Result<()> {
    let clean = cp::clean_path(path);
    if src == "-" {
        let st = stat_in(client, id, &clean)?
            .filter(|st| st.is_dir)
            .ok_or_else(|| anyhow!("destination must be a directory when copying from stdin"))?;
        return client
            .archive_put(
                id,
                &st.link_target,
                put,
                Box::new(|w| io::copy(&mut io::stdin().lock(), w).map(|_| ())),
            )
            .map_err(stdin_error);
    }
    // the source is the user's: a link to it is followed
    let node = openat(
        rustix::fs::CWD,
        src,
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| match e {
        rustix::io::Errno::NOENT => anyhow!("\"{src}\" could not be found on the host"),
        e => anyhow!("`{src}`: {e}"),
    })?;
    let src_is_dir = FileType::from_raw_mode(fstat(&node)?.st_mode) == FileType::Directory;
    let name = host_name(src)?;
    let mut contents = wants_contents(src) && src_is_dir;
    let mut rename = HashMap::new();
    let into = match stat_in(client, id, &clean)? {
        Some(st) if st.is_dir => st.link_target,
        Some(st) => {
            if src_is_dir {
                bail!(DIR_ON_FILE);
            }
            if path.ends_with('/') {
                bail!("`{path}` is not a directory in the container");
            }
            let (dir, base) = cp::split_path(&st.link_target);
            rename.insert(name.clone(), base);
            dir
        }
        None => {
            if path.ends_with('/') && !src_is_dir {
                return Err(missing_in(id, path));
            }
            let (dir, base) = cp::split_path(&clean);
            let parent = stat_in(client, id, &dir)?
                .filter(|st| st.is_dir)
                .ok_or_else(|| missing_in(id, &dir))?;
            // the directory itself, under the new name
            contents = false;
            rename.insert(name.clone(), base);
            parent.link_target
        }
    };
    client
        .archive_put(
            id,
            &into,
            &ArchivePut {
                rename,
                ..put.clone()
            },
            Box::new(|w| {
                let mut b = tar::Builder::new(w);
                b.mode(tar::HeaderMode::Complete);
                TreeWriter {
                    builder: &mut b,
                    ids: None,
                }
                .add_tree(node, Path::new(&name), contents)?;
                b.finish()
            }),
        )
        .map_err(|e| anyhow!("{e}"))
}

fn copy_out(
    client: &EngineClient,
    id: &str,
    path: &str,
    dest: &str,
    put: &ArchivePut,
) -> anyhow::Result<()> {
    // (a device or a pipe is no place for a file)
    if dest != "-" && std::fs::metadata(dest).is_ok_and(|m| !m.is_dir() && !m.is_file()) {
        bail!("invalid destination: \"{dest}\" must be a directory or a regular file");
    }
    let clean = cp::clean_path(path);
    let st = stat_in(client, id, &clean)?.ok_or_else(|| missing_in(id, path))?;
    let contents = st.is_dir && (clean == "/" || wants_contents(path));
    if dest == "-" {
        let asked = if contents {
            format!("{clean}/.")
        } else {
            clean
        };
        let mut tar = client.archive_get(id, &asked).map_err(|e| anyhow!("{e}"))?;
        return super::commands::to_stdout(&mut tar, "copying to the standard output");
    }
    let (_, top) = cp::split_path(&clean);
    let mut opts = ExtractOptions {
        overwrite_dir_non_dir: put.overwrite,
        ..Default::default()
    };
    let into = match std::fs::metadata(dest) {
        Ok(m) if m.is_dir() => dest.to_string(),
        Ok(_) => {
            if st.is_dir {
                bail!(DIR_ON_FILE);
            }
            opts.rename.insert(top.clone(), host_name(dest)?);
            parent_of(dest)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if dest.ends_with('/') && !st.is_dir {
                bail!("the directory `{dest}` does not exist");
            }
            if contents {
                mkdir(dest, Mode::from_raw_mode(0o755)).with_context(|| format!("`{dest}`"))?;
                dest.to_string()
            } else {
                opts.rename.insert(top.clone(), host_name(dest)?);
                parent_of(dest)
            }
        }
        Err(e) => return Err(e).with_context(|| format!("`{dest}`")),
    };
    let base = open_host(&into, OFlags::RDONLY | OFlags::DIRECTORY)?;
    let asked = if contents {
        format!("{clean}/.")
    } else {
        clean
    };
    let tar = client.archive_get(id, &asked).map_err(|e| anyhow!("{e}"))?;
    cp::extract(tar, base.as_fd(), &opts).map_err(|e| anyhow!("copying to `{dest}`: {e}"))
}

fn parent_of(path: &str) -> String {
    match Path::new(path).parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_string_lossy().into_owned(),
        _ => ".".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use velarx_proto::engine::Condition;

    #[test]
    fn a_stdin_that_is_no_tar_is_known_by_the_condition_not_the_words() {
        use crate::client::ClientError;
        let said = |c, words: &str| stdin_error(ClientError::refused(c, words.into())).to_string();
        assert_eq!(
            said(Condition::InvalidArchive, "any words at all"),
            "source must be a (compressed) tar archive when copying from stdin"
        );
        // (the words of the tar crate, said of another condition)
        assert_eq!(
            said(Condition::InvalidArgument, "failed to read entire block"),
            "failed to read entire block"
        );
    }
    use super::*;

    #[test]
    fn container_paths() {
        assert_eq!(container_part("c:/tmp"), Some(("c", "/tmp")));
        assert_eq!(container_part("c:"), Some(("c", "")));
        assert_eq!(container_part("/a:b"), None);
        assert_eq!(container_part("./a:b"), None);
        assert_eq!(container_part("a/b:c"), None);
        assert_eq!(container_part(":x"), None);
        assert_eq!(container_part("plain"), None);
    }

    #[test]
    fn host_names() {
        assert_eq!(host_name("/a/b").unwrap(), "b");
        assert_eq!(host_name("/a/b/").unwrap(), "b");
        assert_eq!(host_name("/a/b/.").unwrap(), "b");
        assert_eq!(parent_of("f"), ".");
        assert_eq!(parent_of("/a/f"), "/a");
        assert!(wants_contents("/a/."));
        assert!(!wants_contents("/a/"));
    }
}
