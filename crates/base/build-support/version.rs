// SPDX-License-Identifier: Apache-2.0
// What `--version` and the server information say of the build: the
// commit and the time.  The build scripts of the packages that make
// binaries `include!` this file and print `directives`; the unit tests of
// `velarx-base` include it too.
//
// The commit, in this order:
//   1. `VELARX_GIT_COMMIT` (a build without the repository, packagers);
//   2. line 1 of `.git-commit` at the source root (what `make dist` puts in
//      the tarball);
//   3. `git describe --always --dirty`, only when the repository is the
//      one of this source tree (a tarball unpacked inside another
//      checkout must not take that checkout's commit);
//   4. `unknown`.
//
// `-dirty` is evaluated when the script runs: it watches the commit and
// the sources (see `watched_sources`), not the documents, so an edit of a
// document does not make the next build say `-dirty`.
//
// The time (RFC 3339, UTC): `SOURCE_DATE_EPOCH`, else line 2 of
// `.git-commit`, else the commit time; the clock is never read, so two
// builds of the same source are the same.

use std::path::{Path, PathBuf};
use std::process::Command;

const COMMIT_FILE: &str = ".git-commit";

/// The source root: the closest directory above `dir` (or `dir`) that has
/// the `Cargo.lock` of the workspace.
fn source_root(dir: &Path) -> PathBuf {
    dir.ancestors()
        .find(|d| d.join("Cargo.lock").is_file())
        .unwrap_or(dir)
        .to_path_buf()
}

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

/// Whether the repository `root` is inside is the one of the source tree.
fn own_repository(root: &Path) -> bool {
    let Some(top) = git(root, &["rev-parse", "--show-toplevel"]) else {
        return false;
    };
    match (Path::new(&top).canonicalize(), root.canonicalize()) {
        (Ok(top), Ok(root)) => top == root,
        _ => false,
    }
}

fn git_path(root: &Path, name: &str) -> Option<PathBuf> {
    git(root, &["rev-parse", "--git-path", name]).map(|p| root.join(p))
}

/// The files a commit changes: `HEAD` (per worktree), and the file of the
/// branch it names.  Not `packed-refs` while the branch has a loose file:
/// other branches rewrite it.  A branch that is only packed gets its loose
/// file at the next commit, and cargo reruns a build script on every build
/// while a file it watches is missing: the closest directory above it that
/// exists then.
fn watched(root: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = git_path(root, "HEAD").into_iter().collect();
    if git(root, &["rev-parse", "--show-ref-format"]).as_deref() == Some("reftable") {
        paths.extend(git_path(root, "reftable/tables.list"));
        return paths;
    }
    let Some(branch) = git(root, &["symbolic-ref", "-q", "HEAD"]) else {
        return paths;
    };
    let Some(file) = git_path(root, &branch) else {
        return paths;
    };
    if file.is_file() {
        paths.push(file);
    } else {
        paths.extend(git_path(root, "packed-refs").filter(|p| p.is_file()));
        paths.extend(
            file.ancestors()
                .skip(1)
                .find(|d| d.is_dir())
                .map(Path::to_path_buf),
        );
    }
    paths
}

/// What the `-dirty` of `git describe` is about, as far as a binary is: the
/// sources and the manifests.  Cargo scans a directory it is told to watch
/// for newer files, so an edit after a clean build reruns the script (the
/// cost is a `git describe` and the link of the binaries) and a revert of
/// it makes the commit clean again.  Not the index (an edit does not touch
/// it) and not the whole tree (`target`, the documents).  A path that does
/// not exist would rerun the script on every build.
fn watched_sources(root: &Path) -> Vec<PathBuf> {
    ["src", "crates", "Cargo.toml", "Cargo.lock"]
        .iter()
        .map(|p| root.join(p))
        .filter(|p| p.exists())
        .collect()
}

/// The two lines of `.git-commit`: the commit and the time in seconds.
fn parse_commit_file(text: &str) -> (Option<String>, Option<u64>) {
    let mut lines = text.lines().map(str::trim);
    let commit = lines.next().filter(|l| !l.is_empty()).map(str::to_string);
    let epoch = lines.next().and_then(|l| l.parse().ok());
    (commit, epoch)
}

/// `1700000000` as `2023-11-14T22:13:20Z`.
fn rfc3339(epoch: u64) -> String {
    let (days, secs) = (epoch / 86400, epoch % 86400);
    // civil date from days since 1970-01-01 (Howard Hinnant's algorithm)
    let z = days as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// The lines a build script prints for the package at `manifest_dir`.
/// `var` reads the environment.
fn directives(manifest_dir: &Path, var: &dyn Fn(&str) -> Option<String>) -> Vec<String> {
    let root = source_root(manifest_dir);
    let mut out = vec![
        "cargo:rerun-if-env-changed=VELARX_GIT_COMMIT".to_string(),
        "cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH".to_string(),
    ];
    let file = root.join(COMMIT_FILE);
    let (file_commit, file_epoch) = match std::fs::read_to_string(&file) {
        Ok(text) => {
            out.push(format!("cargo:rerun-if-changed={}", file.display()));
            parse_commit_file(&text)
        }
        Err(_) => (None, None),
    };
    let in_git = file_commit.is_none() && own_repository(&root);
    if in_git {
        for p in watched(&root).into_iter().chain(watched_sources(&root)) {
            out.push(format!("cargo:rerun-if-changed={}", p.display()));
        }
    }
    let commit = var("VELARX_GIT_COMMIT")
        .filter(|c| !c.is_empty())
        .or(file_commit)
        .or_else(|| {
            in_git
                .then(|| git(&root, &["describe", "--always", "--dirty"]))
                .flatten()
        })
        .unwrap_or_else(|| "unknown".to_string());
    let epoch = var("SOURCE_DATE_EPOCH")
        .and_then(|e| e.trim().parse().ok())
        .or(file_epoch)
        .or_else(|| {
            in_git
                .then(|| git(&root, &["log", "-1", "--format=%ct"]))
                .flatten()
                .and_then(|e| e.parse().ok())
        });
    out.push(format!("cargo:rustc-env=VELARX_GIT_COMMIT={commit}"));
    out.push(format!(
        "cargo:rustc-env=VELARX_BUILD_TIME={}",
        epoch.map_or_else(|| "unknown".to_string(), rfc3339)
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| pairs.iter().find(|p| p.0 == k).map(|p| p.1.to_string())
    }

    fn value(lines: &[String], name: &str) -> String {
        let prefix = format!("cargo:rustc-env={name}=");
        lines
            .iter()
            .find_map(|l| l.strip_prefix(&prefix))
            .unwrap()
            .to_string()
    }

    fn git_in(dir: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
            .args(["-c", "commit.gpgsign=false"])
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    }

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.lock"), "").unwrap();
        dir
    }

    #[test]
    fn rfc3339_dates() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1700000000), "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339(951782400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1709164799), "2024-02-28T23:59:59Z");
    }

    #[test]
    fn commit_file_lines() {
        assert_eq!(
            parse_commit_file("v1.2.3\n1700000000\n"),
            (Some("v1.2.3".into()), Some(1700000000))
        );
        assert_eq!(parse_commit_file("abc\n"), (Some("abc".into()), None));
        assert_eq!(parse_commit_file(""), (None, None));
    }

    #[test]
    fn not_a_checkout_is_unknown() {
        let dir = tree();
        let lines = directives(dir.path(), &env(&[]));
        assert_eq!(value(&lines, "VELARX_GIT_COMMIT"), "unknown");
        assert_eq!(value(&lines, "VELARX_BUILD_TIME"), "unknown");
    }

    #[test]
    fn environment_overrides_and_source_date_epoch() {
        let dir = tree();
        std::fs::write(dir.path().join(COMMIT_FILE), "fromfile\n5\n").unwrap();
        let lines = directives(
            dir.path(),
            &env(&[
                ("VELARX_GIT_COMMIT", "v9-1-gabc"),
                ("SOURCE_DATE_EPOCH", "1700000000"),
            ]),
        );
        assert_eq!(value(&lines, "VELARX_GIT_COMMIT"), "v9-1-gabc");
        assert_eq!(value(&lines, "VELARX_BUILD_TIME"), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn tarball_file() {
        let dir = tree();
        std::fs::write(dir.path().join(COMMIT_FILE), "v1.0.0\n1700000000\n").unwrap();
        let lines = directives(dir.path(), &env(&[]));
        assert_eq!(value(&lines, "VELARX_GIT_COMMIT"), "v1.0.0");
        assert_eq!(value(&lines, "VELARX_BUILD_TIME"), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn git_checkout_and_dirty() {
        let dir = tree();
        git_in(dir.path(), &["init", "-q"]);
        git_in(dir.path(), &["add", "Cargo.lock"]);
        git_in(dir.path(), &["commit", "-q", "-m", "x"]);
        let sub = dir.path().join("crates/x");
        std::fs::create_dir_all(&sub).unwrap();
        let lines = directives(&sub, &env(&[]));
        let commit = value(&lines, "VELARX_GIT_COMMIT");
        assert!(!commit.contains("dirty") && commit.len() >= 7, "{commit}");
        assert_ne!(value(&lines, "VELARX_BUILD_TIME"), "unknown");
        assert!(lines
            .iter()
            .any(|l| l.starts_with("cargo:rerun-if-changed=")));
        // the sources are watched, so that an edit is seen
        let watches = |lines: &[String], name: &str| {
            lines
                .iter()
                .any(|l| l.starts_with("cargo:rerun-if-changed=") && l.ends_with(name))
        };
        assert!(watches(&lines, "Cargo.lock") && watches(&lines, "crates"));
        assert!(
            !watches(&lines, "src"),
            "a path that is missing reruns every build"
        );
        std::fs::write(dir.path().join("Cargo.lock"), "changed").unwrap();
        let lines = directives(&sub, &env(&[]));
        assert_eq!(
            value(&lines, "VELARX_GIT_COMMIT"),
            format!("{commit}-dirty")
        );
    }

    #[test]
    fn watched_refs() {
        let dir = tree();
        // (the config, not `--ref-format=files`: a git before 2.45 rejects it)
        git_in(
            dir.path(),
            &["-c", "init.defaultRefFormat=files", "init", "-q"],
        );
        git_in(dir.path(), &["commit", "-q", "--allow-empty", "-m", "x"]);
        let root = dir.path().canonicalize().unwrap();
        let rel = |p: &PathBuf| p.strip_prefix(&root).unwrap().to_path_buf();
        let names = || watched(&root).iter().map(rel).collect::<Vec<_>>();
        let branch = git(&root, &["symbolic-ref", "-q", "HEAD"]).unwrap();
        let loose = Path::new(".git").join(&branch);
        assert_eq!(
            names(),
            [Path::new(".git/HEAD").to_path_buf(), loose.clone()]
        );
        git_in(&root, &["pack-refs", "--all"]);
        assert!(!root.join(&loose).exists());
        assert_eq!(
            names(),
            [
                Path::new(".git/HEAD").to_path_buf(),
                Path::new(".git/packed-refs").to_path_buf(),
                loose.parent().unwrap().to_path_buf()
            ]
        );
        git_in(&root, &["checkout", "-q", "--detach"]);
        assert_eq!(names(), [Path::new(".git/HEAD").to_path_buf()]);
    }

    #[test]
    fn tree_inside_another_checkout_is_unknown() {
        let outer = tempfile::tempdir().unwrap();
        git_in(outer.path(), &["init", "-q"]);
        git_in(outer.path(), &["commit", "-q", "--allow-empty", "-m", "x"]);
        let inner = outer.path().join("unpacked");
        std::fs::create_dir(&inner).unwrap();
        std::fs::write(inner.join("Cargo.lock"), "").unwrap();
        let lines = directives(&inner, &env(&[]));
        assert_eq!(value(&lines, "VELARX_GIT_COMMIT"), "unknown");
    }
}
