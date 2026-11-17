// SPDX-License-Identifier: Apache-2.0
//! Where the configuration files of the registries and the signature
//! policy are read from.

use std::path::PathBuf;

/// Read a configuration file of at most `max` bytes: only a regular file
/// (a FIFO or a device in its place would hang or never end), refused if
/// it is larger.
pub fn read_config_file(path: &std::path::Path, max: u64) -> std::io::Result<String> {
    String::from_utf8(read_bounded(path, max)?)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// The content of the file `path`, at most `max` bytes: only a regular file
/// (a FIFO or a device in its place would hang or never end; it is opened
/// without blocking), refused if it is larger.  Links are followed.
pub fn read_bounded(path: &std::path::Path, max: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("`{}` is not a regular file", path.display()),
        ));
    }
    let mut data = Vec::new();
    file.take(max.saturating_add(1)).read_to_end(&mut data)?;
    if data.len() as u64 > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("`{}` is larger than {max} bytes", path.display()),
        ));
    }
    Ok(data)
}

/// The user's configuration directory: `$XDG_CONFIG_HOME` or `~/.config`;
/// root of the host has none (the `$HOME` `sudo` leaves is not its own).
pub fn user_config_dir() -> Result<Option<PathBuf>, crate::ids::IdsError> {
    if crate::ids::rootful()? {
        return Ok(None);
    }
    Ok(match std::env::var_os("XDG_CONFIG_HOME") {
        Some(x) if !x.is_empty() => Some(PathBuf::from(x)),
        _ => std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .map(|h| PathBuf::from(h).join(".config")),
    })
}

/// Whether the process uses the configuration of its user (rootless), not
/// only the system's: it is not root, or it is root of a user namespace.
pub fn rootless() -> Result<bool, crate::ids::IdsError> {
    Ok(!crate::ids::rootful()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_files_are_capped_and_regular() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("f");
        std::fs::write(&f, "12345").unwrap();
        assert_eq!(read_config_file(&f, 5).unwrap(), "12345");
        assert!(read_config_file(&f, 4).is_err());
        let fifo = d.path().join("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        assert!(read_config_file(&fifo, 10).is_err());
        assert!(read_config_file(d.path(), 10).is_err());
    }

    #[test]
    fn a_fifo_is_refused_not_waited_for() {
        let d = tempfile::tempdir().unwrap();
        let fifo = d.path().join("fifo");
        crate::testing::make_fifo(&fifo);
        let r = crate::testing::returns_within(std::time::Duration::from_secs(10), move || {
            read_bounded(&fifo, 10)
        });
        assert!(r.is_err());
    }
}

/// True the first time `what` is given in this process: a warning about a
/// file setting is printed once, however many times the file is read.
pub fn first_time(what: &str) -> bool {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};
    static SEEN: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    SEEN.get_or_init(Mutex::default)
        .lock()
        .map(|mut s| s.insert(what.to_string()))
        .unwrap_or(false)
}

/// The key of `known` closest to `key`, if it is within an edit distance
/// of 2 (a typo of it).
pub fn closest<'a>(key: &str, known: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    known
        .into_iter()
        .map(|k| (edit_distance(key, k), k))
        .filter(|(d, _)| (1..=2).contains(d))
        .min_by_key(|(d, _)| *d)
        .map(|(_, k)| k)
}

/// ` (did you mean `x`?)` for the closest of `known`, else nothing.
pub fn did_you_mean<'a>(key: &str, known: impl IntoIterator<Item = &'a str>) -> String {
    closest(key, known)
        .map(|k| format!(" (did you mean `{k}`?)"))
        .unwrap_or_default()
}

fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut prev = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cur = row[j + 1];
            row[j + 1] = (prev + usize::from(ca != *cb)).min(row[j] + 1).min(cur + 1);
            prev = cur;
        }
    }
    row[b.len()]
}

#[cfg(test)]
mod closest_tests {
    use super::*;

    #[test]
    fn a_typo_within_two_edits_is_suggested() {
        let known = ["blocked", "insecure", "location"];
        assert_eq!(closest("blokced", known), Some("blocked"));
        assert_eq!(closest("insecur", known), Some("insecure"));
        assert_eq!(closest("blocked", known), None);
        assert_eq!(closest("something", known), None);
        assert_eq!(
            did_you_mean("locaton", known),
            " (did you mean `location`?)"
        );
    }

    #[test]
    fn a_warning_is_given_once() {
        assert!(first_time("conf-test: a"));
        assert!(!first_time("conf-test: a"));
    }
}
