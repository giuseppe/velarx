// SPDX-License-Identifier: Apache-2.0
//! A build context the engine fetches: a git repository (cloned by the
//! confined helper), a tar of an http(s) URL (downloaded by the registry
//! fetcher, extracted by a confined worker), `github.com/USER/REPO` (the
//! tar of its master branch, as buildah) or the Containerfile of an http(s)
//! URL alone, which is then the whole context (buildah's `TempDirForURL`).

use super::{copy, git, BuildError, BuildResult, BuildService, ContextDir};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use velarx_wire::redact;

/// The largest Containerfile `-f URL` fetches.
const MAX_CONTAINERFILE: u64 = 1024 * 1024;

/// `dir` and the components of `subdir` below it, each a directory and no
/// link.
pub(super) fn subdir(dir: &Path, subdir: &str) -> BuildResult<PathBuf> {
    let mut path = dir.to_path_buf();
    for c in subdir.split('/').filter(|c| !c.is_empty()) {
        path.push(c);
        let m = std::fs::symlink_metadata(&path)
            .map_err(|e| BuildError::Parse(format!("the subdirectory {subdir}: {e}")))?;
        if !m.is_dir() {
            return Err(BuildError::Parse(format!(
                "the subdirectory {subdir} is not a directory"
            )));
        }
    }
    Ok(path)
}

/// `USER/REPO` of `github.com/USER/REPO`: two names of the characters
/// GitHub allows.
fn github_repo(path: &str) -> Option<&str> {
    let mut parts = path.split('/');
    let (user, repo) = (parts.next()?, parts.next()?);
    let name = |n: &str| {
        !n.is_empty()
            && !n.starts_with('.')
            && n.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    };
    (parts.next().is_none() && name(user) && name(repo)).then_some(repo)
}

impl BuildService {
    /// Fetch the context `remote` names into the empty directory `dir`,
    /// whose room `ctx` accounts: the directory of the context.
    pub async fn fetch_context(
        &self,
        remote: &str,
        ctx: &mut ContextDir,
        dir: &Path,
    ) -> BuildResult<PathBuf> {
        if let Some(g) = git::parse(remote) {
            let g = g.map_err(BuildError::Parse)?;
            let root = self.clone_context(&g, dir).await;
            // (what the clone takes of the room of the builds)
            ctx.reservation.set(super::disk_usage(dir)?)?;
            return root;
        }
        if let Some(path) = remote.strip_prefix("github.com/") {
            let repo = github_repo(path).ok_or_else(|| {
                BuildError::Parse(format!("invalid GitHub repository `{remote}`: USER/REPO"))
            })?;
            self.download_context(&format!("https://{remote}/archive/master.tar.gz"), ctx, dir)
                .await?;
            return subdir(dir, &format!("{repo}-master"));
        }
        if remote.starts_with("https://") || remote.starts_with("http://") {
            self.download_context(remote, ctx, dir).await?;
            return Ok(dir.to_path_buf());
        }
        Err(BuildError::Parse(format!(
            "unsupported remote context `{}`: a git repository, `github.com/USER/REPO` or an http(s) URL",
            redact::urls(remote)
        )))
    }

    /// The body of `url` (at most `limit` bytes) in a file of the context's
    /// room, rewound.
    async fn download(
        &self,
        url: &str,
        limit: u64,
        ctx: &mut ContextDir,
    ) -> BuildResult<std::fs::File> {
        let mut spool = tempfile::tempfile_in(ctx.path())?;
        let mut out = std::io::BufWriter::new(spool.try_clone()?);
        let reservation = &mut ctx.reservation;
        self.fetcher
            .fetch(url, limit, &mut |chunk| {
                reservation.grow(chunk.len() as u64)?;
                out.write_all(chunk)
            })
            .await
            .map_err(|e| BuildError::Parse(redact::urls(&format!("downloading {url}: {e}"))))?;
        out.flush()?;
        drop(out);
        std::io::Seek::rewind(&mut spool)?;
        Ok(spool)
    }

    /// Download the tar of a remote context (http or https) and extract it
    /// into the empty directory `dir`; what is no archive is a Containerfile,
    /// the only file of the context (as buildah).
    pub async fn download_context(
        &self,
        url: &str,
        ctx: &mut ContextDir,
        dir: &Path,
    ) -> BuildResult<()> {
        let mut spool = self.download(url, self.limits.max_bytes, ctx).await?;
        let mut head = Vec::with_capacity(512);
        (&mut spool).take(512).read_to_end(&mut head)?;
        if head.is_empty() {
            return Err(BuildError::Parse(redact::urls(&format!(
                "no contents in {url}"
            ))));
        }
        std::io::Seek::rewind(&mut spool)?;
        if copy::archive_kind(&head).is_some() {
            return self.unpack_context(spool, ctx, dir).await;
        }
        let mut file = std::fs::File::create_new(dir.join("Dockerfile"))?;
        std::io::copy(&mut spool, &mut file)?;
        Ok(())
    }

    /// The Containerfile of the http(s) URL `url` (`-f URL`).
    pub async fn download_containerfile(
        &self,
        url: &str,
        ctx: &mut ContextDir,
    ) -> BuildResult<String> {
        let mut spool = self.download(url, MAX_CONTAINERFILE, ctx).await?;
        let mut text = String::new();
        spool.read_to_string(&mut text).map_err(|e| {
            BuildError::Parse(redact::urls(&format!("the Containerfile {url}: {e}")))
        })?;
        if text.is_empty() {
            return Err(BuildError::Parse(redact::urls(&format!(
                "no contents in {url}"
            ))));
        }
        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_repositories() {
        assert_eq!(github_repo("o/r"), Some("r"));
        assert_eq!(github_repo("o-1/r.x_y"), Some("r.x_y"));
        for bad in [
            "", "o", "o/", "/r", "o/r/x", "o/..", "o/.r", "o/r?x", "o/r#x", "o /r",
        ] {
            assert_eq!(github_repo(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_subdirectory_has_no_links() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("a/b")).unwrap();
        std::os::unix::fs::symlink("/", d.path().join("l")).unwrap();
        std::fs::write(d.path().join("f"), "").unwrap();
        assert_eq!(subdir(d.path(), "").unwrap(), d.path());
        assert_eq!(subdir(d.path(), "a/b").unwrap(), d.path().join("a/b"));
        for bad in ["l", "f", "a/x", "l/etc"] {
            assert!(subdir(d.path(), bad).is_err(), "{bad}");
        }
    }
}
