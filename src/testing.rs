// SPDX-License-Identifier: Apache-2.0
//! Helpers of the unit tests.  The tests of the library run as threads of
//! one process: what a test does to the whole process (signals, the
//! environment, the working directory, resource limits, mounts) reaches
//! all the others running at the time.  Such a test runs its body in a
//! child process (`velarx_base::testing::in_child`), and a test of this
//! module fails when one does it outside.

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    /// What a test must not do to the process it shares with the others,
    /// unless it runs in a child (`in_child`) and says so with a
    /// `// child-only` comment on the line or the one before.
    const PROCESS_WIDE: [&str; 9] = [
        "libc::raise(",
        "kill(getpid",
        "kill(libc::getpid",
        "pthread_kill(",
        "libc::umask(",
        "env::set_var(",
        "env::remove_var(",
        "set_current_dir(",
        "libc::setrlimit(",
    ];

    fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries {
            let p = e.unwrap().path();
            if p.is_dir() {
                sources(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }

    /// Data travels in real files only: no memory file in the code that
    /// fetches, serves or hands over content.  (The owner of the project
    /// decided it: a file has a size the client can bound and an owner that
    /// is the asker's, and the quota of the asker covers it.)
    #[test]
    fn no_memory_file_carries_data() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files: Vec<String> = ["fetch_client", "mod", "proto"]
            .iter()
            .map(|f| format!("crates/content/src/fetcher/{f}.rs"))
            .collect();
        files.extend(
            [
                "crates/content/src/list.rs",
                "crates/content/src/serve_fetch.rs",
            ]
            .map(String::from),
        );
        files.push("crates/registry-lib/src/registry.rs".into());
        files.extend(
            [
                "crates/core/src/store_service.rs",
                "crates/runtime/src/monitor/lazy.rs",
                // the client of a storage driver: object bytes travel on a
                // pipe (`ReadObjects`) and into the driver's own files
                // (`Fetch`), never in a memory file of the engine's
                "crates/storage-client/src/conn.rs",
                "crates/storage-client/src/driver.rs",
                "crates/storage-client/src/feed.rs",
            ]
            .map(String::from),
        );
        let needles = [
            concat!("memfd", "_create"),
            "MemfdFlags",
            "sealed_memfd",
            "MFD_",
        ];
        for name in files {
            let text = std::fs::read_to_string(root.join(&name)).unwrap();
            for needle in needles {
                assert!(!text.contains(needle), "{name} uses {needle}");
            }
            // (the exceptions, decisions of the owner: the credentials of a
            // call, a secret that must not be on a disk, in the sealed memory
            // file of `Access::new` (fetch_client.rs); for a storage driver, what the engine
            // makes and hands over that is no content: the table of contents
            // and tar-split of `Index` of the feed (one call for both), the
            // keep set of `Collect`)
            // (remote.rs has its tests in a file of their own)
            let remote = name.ends_with("fetcher/remote.rs");
            let allowed = usize::from(
                name.ends_with("fetcher/fetch_client.rs")
                    || name.ends_with("storage-client/src/feed.rs")
                    || name.ends_with("storage-client/src/driver.rs"),
            );
            let code = match remote {
                true => &text,
                false => text.split("#[cfg(test)]").next().unwrap(),
            };
            let sealed = code.matches("sealed_memory(").count();
            assert_eq!(sealed, allowed, "{name} makes a memory file");
        }
    }

    /// The files of a pull are made durable by one `syncfs` of the whole
    /// session, after fs-verity: no file is synced on its own; and nothing
    /// of the staging area of lazy pulls is synced (a lazy pull is made
    /// durable when it is complete).
    #[test]
    fn no_file_of_a_pull_is_synced_on_its_own() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        for file in [
            "crates/content/src/pull/session.rs",
            "crates/content/src/pull/stream.rs",
            "crates/content/src/pull/chunked/mod.rs",
            "crates/content/src/pull/staged_fetch.rs",
            "crates/content/src/pull/staged.rs",
            "crates/content/src/stager.rs",
            "crates/registry-lib/src/registry_fetch.rs",
            "crates/content/src/dir_fetch.rs",
            "crates/p2p/src/staging.rs",
            "crates/content/src/pull/lazy.rs",
            "crates/core/src/services/image/lazy_fetch.rs",
            "crates/core/src/services/image/lazy.rs",
            "crates/core/src/services/image/pull.rs",
        ] {
            let text = std::fs::read_to_string(root.join(file)).unwrap();
            let code = text.split("#[cfg(test)]").next().unwrap();
            for call in [
                ".sync_all(",
                ".sync_data(",
                "fsync(",
                "fdatasync(",
                "syncfs(",
            ] {
                assert!(!code.contains(call), "{file} syncs a file: {call}");
            }
        }
    }

    /// The directories of the packages of the workspace: the root, `crates/*`
    /// and the packages of the binaries of the frontends, `crates/*/bin`.
    fn workspace_packages(root: &Path) -> Vec<PathBuf> {
        let mut packages = vec![root.to_path_buf()];
        for e in std::fs::read_dir(root.join("crates")).into_iter().flatten() {
            let dir = e.unwrap().path();
            let bins = dir.join("bin");
            packages.push(dir);
            if bins.join("Cargo.toml").is_file() {
                packages.push(bins);
            }
        }
        packages
    }

    /// The test code of the workspace: each file with its text and the
    /// number of its first line of test code.  In a file of a library only
    /// what follows its first test module is test code; the files of
    /// `tests/` and the test modules in files of their own (`tests.rs`,
    /// `*_tests.rs`) are all test code.
    fn test_code(root: &Path) -> Vec<(PathBuf, String, usize)> {
        let mut files = Vec::new();
        let packages = workspace_packages(root);
        for p in &packages {
            sources(&p.join("src"), &mut files);
            sources(&p.join("tests"), &mut files);
        }
        let mut out = Vec::new();
        for f in files {
            let text = std::fs::read_to_string(&f).unwrap();
            let stem = f.file_stem().unwrap_or_default().to_string_lossy();
            let test_file = stem == "tests" || stem.ends_with("_tests");
            let library = packages.iter().any(|p| f.starts_with(p.join("src")));
            let from = if library && !test_file {
                match text.lines().position(|l| l.trim() == "#[cfg(test)]") {
                    Some(n) => n,
                    None => continue,
                }
            } else {
                0
            };
            out.push((f, text, from));
        }
        out
    }

    /// Whether line `n` ends with the comment `marker`, or the line before
    /// is that comment alone (the text of a string that names the marker
    /// does not count).
    fn marked(lines: &[&str], n: usize, marker: &str) -> bool {
        lines[n].trim_end().ends_with(marker) || (n > 0 && lines[n - 1].trim() == marker)
    }

    #[test]
    fn no_test_acts_on_the_whole_process_outside_a_child() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut found = Vec::new();
        for (f, text, from) in test_code(root) {
            let lines: Vec<&str> = text.lines().collect();
            for (n, l) in lines.iter().enumerate().skip(from) {
                let code = l.split("//").next().unwrap_or_default();
                let allowed = marked(&lines, n, "// child-only");
                if !allowed && PROCESS_WIDE.iter().any(|p| code.contains(p)) {
                    found.push(format!("{}:{}: {}", f.display(), n + 1, l.trim()));
                }
            }
        }
        // (this file names them above)
        let this = root.join("src/testing.rs");
        found.retain(|l| !l.starts_with(&format!("{}:", this.display())));
        assert!(
            found.is_empty(),
            "a test acts on the process it shares with the others: run it \
             in a child (testing::in_child) and mark the line `// child-only`:\n{}",
            found.join("\n")
        );
    }

    /// A test that runs a script writes it with `testing::write_script`
    /// (`write_runtime` for a runtime), by a process of its own: the file
    /// of a test of this process that is open for writing while another
    /// test forks stays open in the child until its exec, and the exec of
    /// the script fails with ETXTBSY (`in_child` is no exception: the
    /// helper costs nothing there either).  Any `#!` in the code of a test
    /// but an inner attribute is taken for a script it writes itself (in a
    /// string of any kind, a line of a string that goes on, with or without
    /// the path): it is allowed only on a line that ends with the comment
    /// `// not executed`, or follows that comment alone, for a file that is
    /// never run (the review of a new marker checks that).  Comment lines
    /// are not code; a trailing comment that names a shebang is.
    /// Whether line `n` of test code has a shebang that is not marked as
    /// never run (see the test below).
    fn writes_a_script(lines: &[&str], n: usize) -> bool {
        let l = lines[n];
        !l.trim_start().starts_with("//")
            && !marked(lines, n, "// not executed")
            && l.match_indices("#!")
                .any(|(i, _)| !l[i + 2..].starts_with('['))
    }

    #[test]
    fn no_test_writes_a_script_to_run_in_its_own_process() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        // (the helper writes the script, in the process it makes; this file
        // names shebangs in its messages)
        let exempt = [
            root.join("crates/base/src/testing.rs"),
            root.join("src/testing.rs"),
        ];
        let mut found = Vec::new();
        for (f, text, from) in test_code(root) {
            if exempt.contains(&f) {
                continue;
            }
            let lines: Vec<&str> = text.lines().collect();
            for (n, l) in lines.iter().enumerate().skip(from) {
                if writes_a_script(&lines, n) {
                    found.push(format!("{}:{}: {}", f.display(), n + 1, l.trim()));
                }
            }
        }
        assert!(
            found.is_empty(),
            "a test writes a script itself: use velarx_base::testing::write_script \
             (or mark the line `// not executed` for a file that is never run):\n{}",
            found.join("\n")
        );
    }

    /// The lint above finds a shebang however a test spells it, and lets
    /// through only the lines marked as never run.
    #[test]
    fn the_script_lint_finds_every_spelling_of_a_shebang() {
        let hit = |text: &str| {
            let lines: Vec<&str> = text.lines().collect();
            (0..lines.len()).any(|n| writes_a_script(&lines, n))
        };
        let bang = "#!";
        for found in [
            format!("write(&p, \"{bang}/bin/sh\\n\")"),
            format!("write(&p, r\"{bang}/bin/sh\")"),
            format!("write(&p, r#\"{bang}/bin/sh\"#)"),
            format!("write_all(b\"{bang}\")"),
            format!("write(&p, format!(\"{bang}{{}}\\n\", sh))"),
            format!("let s = \"\\\n{bang}/bin/sh\n\";"),
            format!("f(\"http://x\", \"{bang}/bin/sh\")"),
            format!("write(&p, \"{bang}/bin/sh\"); // not executed, it says"),
            format!("// not executed (why)\nwrite(&p, \"{bang}/bin/sh\");"),
            format!("let s = \"// not executed\"; write(&p, \"{bang}/bin/sh\");"),
        ] {
            assert!(hit(&found), "not found: {found}");
        }
        for allowed in [
            format!("{bang}[allow(dead_code)]"),
            format!("// writes {bang}/bin/sh"),
            format!("/// {bang}/bin/sh"),
            format!("write(&p, \"{bang}/bin/sh\"); // not executed"),
            format!("// not executed\nwrite(&p, \"{bang}/bin/sh\");"),
        ] {
            assert!(!hit(&allowed), "found: {allowed}");
        }
    }

    /// velarx has no older version in the field: its formats and schemas
    /// change in place and nothing migrates, converts or reads what an
    /// earlier build left (AGENTS.md).  These words in the code say that it
    /// is coming back.
    const FORBIDDEN: [&str; 11] = [
        "migrat",
        "legacy",
        "backward",
        "back-compat",
        "old format",
        "older version",
        "older velarx",
        "earlier version",
        "older store",
        "compat shim",
        "older build",
    ];

    /// The lines that may hold them: interoperability with other tools or
    /// systems (file, text of the line, why).
    const ALLOWED: [(&str, &str, &str); 6] = [
        (
            "src/cli/layout.rs",
            "\"migrate\"",
            "podman's `system migrate`, refused with why",
        ),
        (
            "crates/registry/src/auth.rs",
            "legacy Docker form",
            "docker's config.json entries keyed by a URL with a path",
        ),
        (
            "crates/core/src/services/image/changes.rs",
            "legacy",
            "the Dockerfile `ENV KEY VALUE` form that buildah accepts",
        ),
        (
            "crates/signature/src/openpgp.rs",
            "LEGACY",
            "OpenPGP's legacy EdDSA (algorithm 22), still used by keys of gpg",
        ),
        (
            "crates/signature/src/openpgp.rs",
            "// old format",
            "RFC 4880 old-format packet headers of the keys of gpg",
        ),
        (
            "crates/proto/src/request.rs",
            "the legacy `:`",
            "podman's `--security-opt label:disable` form",
        ),
    ];

    /// The options of the command line that a handler takes and drops
    /// (`name: _` in the pattern of its command): each is accepted on
    /// purpose, for what it would do is done anyway or is nothing here, and
    /// says so.  A new one must be refused (`anyhow::bail!("--x is not
    /// supported ...")`) or used; one that is truly harmless goes here with
    /// its reason.
    const DROPPED_OPTIONS: [(&str, &str, &str); 20] = [
        (
            "commands/image.rs",
            "quiet",
            "`save` shows no progress: an archive is written by the pusher to the file it was handed",
        ),
        (
            "commands/image.rs",
            "disable_compression",
            "as podman's local storage: the layers of the store follow --compression-format",
        ),
        (
            "commands/image.rs",
            "runtime_flag",
            "taken as the global --runtime-flag (src/cli/mod.rs)",
        ),
        (
            "commands/image.rs",
            "hooks_dir",
            "taken as the global --hooks-dir (src/cli/mod.rs)",
        ),
        ("commands/pod.rs", "all", "`pod list` lists all the pods"),
        (
            "commands/volume.rs",
            "all",
            "`volume list` lists all the volumes",
        ),
        (
            "commands/image.rs",
            "no_prune",
            "there are no untagged parents to keep",
        ),
        (
            "commands/image.rs",
            "multi_image_archive",
            "an archive holds all its images",
        ),
        (
            "commands/image.rs",
            "force_rm",
            "the containers of a build are always removed",
        ),
        (
            "commands/image.rs",
            "compress",
            "no effect in podman's build either",
        ),
        (
            "commands/image.rs",
            "disable_content_trust",
            "no effect in podman's build, push and pull either (Docker's content trust)",
        ),
        (
            "commands/image.rs",
            "force_compression",
            "a push compresses as asked: velarx knows of no other variant of a layer to take",
        ),
        (
            "commands/image.rs",
            "remove_signatures",
            "a push copies no signature",
        ),
        (
            "commands/image.rs",
            "external",
            "no container of another tool uses an image of the store: prune finds them all without it",
        ),
        (
            "commands/image.rs",
            "uncompressed",
            "`save` writes the layers uncompressed always",
        ),
        (
            "manifest.rs",
            "remove_signatures",
            "a push copies no signature",
        ),
        (
            "manifest.rs",
            "force_compression",
            "a push compresses as asked: velarx knows of no other variant of a layer to take",
        ),
        (
            "commands/container.rs",
            "external",
            "the store has no containers of other tools: they are all found without it",
        ),
        (
            "run.rs",
            "disable_content_trust",
            "no effect in podman either (it is for Docker's content trust)",
        ),
        (
            "commands/container.rs",
            "force",
            "the mounts of a container are not counted: unmount always unmounts",
        ),
    ];

    #[test]
    fn no_option_of_the_command_line_is_taken_and_dropped() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        sources(&root.join("src/cli"), &mut files);
        let mut found = Vec::new();
        let mut used = std::collections::HashSet::new();
        for f in files {
            let rel = f
                .strip_prefix(root.join("src/cli"))
                .unwrap()
                .to_string_lossy()
                .to_string();
            let text = std::fs::read_to_string(&f).unwrap();
            for (n, line) in text.lines().enumerate() {
                for (at, _) in line.match_indices(": _") {
                    let rest = &line[at + 3..];
                    let ends = rest.starts_with(',') || rest.trim_start().starts_with('}');
                    let name: String = line[..at]
                        .chars()
                        .rev()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect();
                    if !ends || name.is_empty() {
                        continue;
                    }
                    match DROPPED_OPTIONS
                        .iter()
                        .position(|(file, n, _)| *file == rel && *n == name)
                    {
                        Some(i) => {
                            used.insert(i);
                        }
                        None => found.push(format!("src/cli/{rel}:{}: `{name}: _`", n + 1)),
                    }
                }
            }
        }
        assert!(
            found.is_empty(),
            "options taken and dropped (refuse them, or list them in DROPPED_OPTIONS):\n{}",
            found.join("\n")
        );
        for (i, (file, name, _)) in DROPPED_OPTIONS.iter().enumerate() {
            assert!(
                used.contains(&i),
                "DROPPED_OPTIONS: {file} {name} is not dropped any more"
            );
        }
    }

    /// The clients of the engine (the command line, the thin client, the
    /// API service, the CRI service) call it through the typed proxy:
    /// parameters of the type of the method, a
    /// reply decoded as its type, a missing member an error.  A call by the
    /// name of its method with a JSON value, and a reply read member by
    /// member, are how a member that is missing became an empty string.
    #[test]
    fn no_call_of_the_client_is_by_name() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        for dir in ["src/client", "src/cli", "crates/api/src", "crates/cri/src"] {
            sources(&root.join(dir), &mut files);
        }
        assert!(files.len() >= 4, "{files:?}");
        let by_name = [
            [".call", "(\""].concat(),
            [".call_", "raw("].concat(),
            [".call_", "bare("].concat(),
            [".call", "(&"].concat(),
            ["parse_", "reply("].concat(),
            [".call_", "list("].concat(),
            [".call_", "each("].concat(),
            [".call_", "value("].concat(),
            ["fn call", "(&self, method"].concat(),
            ["invoke", "("].concat(),
            ["send_", "call("].concat(),
            ["call_", "method("].concat(),
            ["receive_", "reply"].concat(),
            ["varlink::", "Conn"].concat(),
            ["fn str_", "member("].concat(),
        ];
        // (the text without its white space, so that a call that rustfmt
        // put on several lines is one: the line of each character kept)
        let by_name: Vec<String> = by_name.iter().map(|w| w.replace(' ', "")).collect();
        let mut found = Vec::new();
        for f in files {
            let rel = f.strip_prefix(root).unwrap().to_string_lossy().to_string();
            let text = std::fs::read_to_string(&f).unwrap();
            let (mut squeezed, mut lines) = (String::new(), Vec::new());
            for (n, l) in text.lines().enumerate() {
                for c in l.chars().filter(|c| !c.is_whitespace()) {
                    squeezed.push(c);
                    lines.extend(std::iter::repeat_n(n, c.len_utf8()));
                }
            }
            for w in &by_name {
                for (at, _) in squeezed.match_indices(w.as_str()) {
                    let n = lines[at];
                    found.push(format!(
                        "{rel}:{}: {}",
                        n + 1,
                        text.lines().nth(n).unwrap().trim()
                    ));
                }
            }
        }
        assert!(
            found.is_empty(),
            "the client calls the engine by the name of a method: use the typed proxy \
             (`EngineProxy`):\n{}",
            found.join("\n")
        );
    }

    /// The command line, the thin client and the frontends never open the
    /// socket of a monitor: a session is the engine's (`ContainerAttach`,
    /// `ExecStart`, `ContainerLogs`), and the monitor is spoken to by the
    /// core and the runtime only.
    #[test]
    fn no_monitor_socket_is_opened_outside_the_engine() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        for dir in ["src/client", "src/cli", "crates/api/src", "crates/cri/src"] {
            sources(&root.join(dir), &mut files);
        }
        assert!(files.len() >= 4, "{files:?}");
        let words = ["monitor::client", "monitor.sock", "proto::SOCKET"];
        let mut found = Vec::new();
        for f in files {
            let rel = f.strip_prefix(root).unwrap().to_string_lossy().to_string();
            for (n, l) in std::fs::read_to_string(&f).unwrap().lines().enumerate() {
                if words.iter().any(|w| l.contains(w)) {
                    found.push(format!("{rel}:{}: {}", n + 1, l.trim()));
                }
            }
        }
        assert!(
            found.is_empty(),
            "a client of the engine talks to a monitor: use the engine's calls:\n{}",
            found.join("\n")
        );
    }

    #[test]
    fn the_code_has_no_migration_or_compatibility_with_older_versions() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let packages = workspace_packages(root);
        let allowed: Vec<_> = ALLOWED.iter().collect();
        let mut used = vec![false; allowed.len()];
        let mut found = Vec::new();
        for p in &packages {
            let mut files = Vec::new();
            sources(&p.join("src"), &mut files);
            for f in files {
                let rel = f.strip_prefix(root).unwrap().to_string_lossy().to_string();
                // (this file names the words)
                if rel == "src/testing.rs" {
                    continue;
                }
                let text = std::fs::read_to_string(&f).unwrap();
                for (n, l) in text.lines().enumerate() {
                    let lower = l.to_lowercase();
                    if !FORBIDDEN.iter().any(|w| lower.contains(w)) {
                        continue;
                    }
                    let entry = allowed
                        .iter()
                        .position(|(file, line, _)| rel == *file && l.contains(line));
                    match entry {
                        Some(i) => used[i] = true,
                        None => found.push(format!("{rel}:{}: {}", n + 1, l.trim())),
                    }
                }
            }
        }
        assert!(
            found.is_empty(),
            "velarx has nothing older to be compatible with: remove the code, or \
             if it is interoperability with another tool add the line to ALLOWED \
             (src/testing.rs) with the reason:\n{}",
            found.join("\n")
        );
        let stale: Vec<_> = allowed
            .iter()
            .zip(&used)
            .filter(|(_, u)| !**u)
            .map(|(e, _)| format!("{}: {}", e.0, e.1))
            .collect();
        assert!(stale.is_empty(), "ALLOWED lines that are gone: {stale:?}");
    }

    /// The code of `line` without its trailing comment and without the
    /// text of its string literals.
    fn code_of(line: &str) -> String {
        let mut out = String::new();
        let mut chars = line.chars().peekable();
        let mut in_string = false;
        while let Some(c) = chars.next() {
            match c {
                '\\' if in_string => {
                    chars.next();
                }
                '"' => in_string = !in_string,
                '/' if !in_string && chars.peek() == Some(&'/') => break,
                _ if in_string => {}
                _ => out.push(c),
            }
        }
        out
    }

    fn opens_unsafe(code: &str) -> bool {
        let mut rest = code;
        while let Some(i) = rest.find("unsafe") {
            let before = rest[..i].chars().next_back();
            let after = &rest[i + "unsafe".len()..];
            let word = !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
                && !after.starts_with(|c: char| c.is_alphanumeric() || c == '_');
            let after = after.trim_start();
            if word
                && ["{", "fn ", "impl", "extern", "trait"]
                    .iter()
                    .any(|k| after.starts_with(k))
            {
                return true;
            }
            rest = &rest[i + "unsafe".len()..];
        }
        false
    }

    /// Whether the `unsafe` on line `n` is explained: a `// SAFETY:`
    /// comment on the line, in the comment block right above it or above
    /// the statement it is a part of (or, for an `unsafe fn`, a `# Safety`
    /// section in its documentation).
    fn explained(lines: &[&str], n: usize) -> bool {
        if lines[n].contains("SAFETY:") {
            return true;
        }
        for line in lines[..n].iter().rev() {
            let t = line.trim();
            if t.starts_with("//") || t.starts_with("#[") {
                if t.contains("SAFETY:") || t.contains("# Safety") {
                    return true;
                }
                continue;
            }
            if t.is_empty() || t.ends_with([';', '{', '}', ',']) {
                return false;
            }
        }
        false
    }

    /// Every `unsafe` block, fn, impl and trait says why it is sound: a
    /// `// SAFETY:` comment states the invariant (clippy's
    /// `undocumented_unsafe_blocks` checks the blocks too, but only where
    /// clippy runs).
    #[test]
    fn every_unsafe_has_a_safety_comment() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        for d in ["src", "tests", "crates", "fuzz", "tools"] {
            sources(&root.join(d), &mut files);
        }
        files.retain(|f| !f.components().any(|c| c.as_os_str() == "target"));
        assert!(files.len() > 100, "the walk found {} files", files.len());
        let mut found = Vec::new();
        let mut sites = 0;
        for f in files {
            let rel = f.strip_prefix(root).unwrap().to_string_lossy().to_string();
            if rel == "src/testing.rs" {
                continue;
            }
            let text = std::fs::read_to_string(&f).unwrap();
            let lines: Vec<_> = text.lines().collect();
            for (n, l) in lines.iter().enumerate() {
                if opens_unsafe(&code_of(l)) {
                    sites += 1;
                    if !explained(&lines, n) {
                        found.push(format!("{rel}:{}: {}", n + 1, l.trim()));
                    }
                }
            }
        }
        assert!(sites > 50, "the walk found {sites} unsafe sites");
        assert!(
            found.is_empty(),
            "an unsafe without a `// SAFETY:` comment that states why it is \
             sound (above it, or above its statement):\n{}",
            found.join("\n")
        );
    }

    fn package_of(rel: &str) -> String {
        match rel.strip_prefix("crates/") {
            Some(rest) => format!("crates/{}", rest.split('/').next().unwrap()),
            None => ".".to_string(),
        }
    }

    /// `vendor/` is not walked by the checks of the sources: it holds copies
    /// of crates of crates.io with a change (`[patch.crates-io]`), whose code
    /// (and `unsafe`) is theirs like that of any other dependency.  Each is
    /// in NOTICE, which says what was changed.
    #[test]
    fn every_vendored_crate_is_in_the_notice() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let notice = std::fs::read_to_string(root.join("NOTICE")).unwrap();
        for e in std::fs::read_dir(root.join("vendor")).into_iter().flatten() {
            let name = e.unwrap().file_name().to_string_lossy().to_string();
            assert!(
                notice.lines().any(|l| l == format!("vendor/{name}")),
                "vendor/{name} is not in NOTICE"
            );
        }
    }

    /// `unsafe` is the business of `velarx-sys` alone.
    #[test]
    fn unsafe_code_is_only_in_the_sys_package() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        for d in ["src", "tests", "crates", "fuzz", "tools"] {
            sources(&root.join(d), &mut files);
        }
        let mut with_unsafe = std::collections::BTreeSet::new();
        for f in files {
            let rel = f.strip_prefix(root).unwrap().to_string_lossy().to_string();
            if rel == "src/testing.rs" || rel.starts_with("crates/sys/") || rel.starts_with("fuzz/")
            {
                continue;
            }
            let text = std::fs::read_to_string(&f).unwrap();
            if text.lines().any(|l| opens_unsafe(&code_of(l))) {
                with_unsafe.insert(package_of(&rel));
            }
        }
        assert!(
            with_unsafe.is_empty(),
            "{with_unsafe:?}: the packages with `unsafe` outside velarx-sys: `unsafe` belongs in \
             crates/sys, as a safe function with a `// SAFETY:` comment"
        );
    }

    const SPDX: &str = "SPDX-License-Identifier:";
    const CODE_LICENSE: &str = "Apache-2.0";

    /// The sections of the configuration, as velarx.conf(5) tells of them
    /// (man/velarx.conf.5): each one of config.toml.example has a `.TP`
    /// entry of its own, so a knob that moves sections or a section that is
    /// added shows up here before the pages drift apart.
    #[test]
    fn the_conf_man_page_names_every_section() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let example = std::fs::read_to_string(root.join("config.toml.example")).unwrap();
        let page = std::fs::read_to_string(root.join("man/velarx.conf.5")).unwrap();
        // the top-level section of every table ([network.bridge] is network):
        // the page tells of a section and its subsections in one entry
        let sections: Vec<String> = example
            .lines()
            .filter(|l| l.starts_with('['))
            .filter_map(|l| {
                l.trim_matches(|c| c == '[' || c == ']')
                    .split('.')
                    .next()
                    .map(str::to_owned)
            })
            .collect();
        let sections: std::collections::BTreeSet<_> = sections.into_iter().collect();
        assert!(sections.len() > 8, "config.toml.example has no sections");
        let missing: Vec<_> = sections
            .iter()
            .filter(|name| !page.contains(&format!(".B {name}\n")))
            .cloned()
            .collect();
        assert!(
            missing.is_empty(),
            "man/velarx.conf.5 has no entry for the section(s) {missing:?} \
             of config.toml.example"
        );
    }

    /// The comment prefix of the SPDX line of a file, by its name: `None`
    /// for what carries no header (data, fixtures, the license texts).
    fn comment_of(rel: &str) -> Option<&'static str> {
        let name = rel.rsplit('/').next().unwrap_or(rel);
        let ext = name.rsplit_once('.').map(|(_, e)| e);
        match (name, ext) {
            (_, Some("rs")) => Some("//"),
            (_, Some("md")) => Some("<!--"),
            ("Makefile" | "velarx-generator", _) => Some("#"),
            (
                _,
                Some(
                    "sh" | "py" | "service" | "socket" | "timer" | "conf" | "toml" | "allow"
                    | "example",
                ),
            ) => Some("#"),
            _ => None,
        }
    }

    /// Where the text `p2p` may be outside the package of the service of
    /// the peers (`crates/` + that name): the file, the part of a line that
    /// makes it allowed, and why.  Everything else in the engine knows the
    /// service as a source or a provider named in the configuration.
    const MAY_NAME_THE_SERVICE: [(&str, &str, &str); 6] = [
        ("Cargo.toml", "crates/p2p", "the workspace member"),
        (
            "Cargo.toml",
            "velarx-p2p",
            "the comment on how the packages that are not built by default are built",
        ),
        (
            "deny.toml",
            "libp2p",
            "the names of the crates of the dependency",
        ),
        (
            "deny.toml",
            "velarx-p2p",
            "the package whose dependency graph it is about",
        ),
        (
            "config.toml.example",
            "p2p-fetcher.sock",
            "the socket of one source, the example of [[sources.external]]",
        ),
        (
            "config.toml.example",
            "p2p-network.sock",
            "the socket of one provider, the example of [[network.providers]]",
        ),
    ];

    fn sources_and_manifests(dir: &Path, root: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries {
            let p = e.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            if p.is_dir() {
                let rel = p.strip_prefix(root).unwrap();
                if !matches!(name.as_str(), "target" | "fixtures" | "corpus")
                    && !name.starts_with('.')
                    && rel != Path::new("crates/p2p")
                {
                    sources_and_manifests(&p, root, out);
                }
            } else if name == "config.toml.example"
                || p.extension().is_some_and(|x| x == "rs" || x == "toml")
            {
                out.push(p);
            }
        }
    }

    /// The engine, the command line and the libraries know no p2p: the
    /// peers are a source of the pulls (`[[sources.external]]`, the
    /// interface `org.velarx.Fetcher`), the store a service
    /// (`org.velarx.Store`), the overlay network a network provider
    /// (`org.velarx.Network`).  Only `crates/p2p` has the word.
    #[test]
    fn nothing_but_the_p2p_package_knows_p2p() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        sources_and_manifests(root, root, &mut files);
        let mut found = Vec::new();
        for f in files {
            let rel = f.strip_prefix(root).unwrap().to_string_lossy().to_string();
            // this file holds the rule and its list
            if rel == "src/testing.rs" {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&f) else {
                continue;
            };
            for (n, line) in text.lines().enumerate() {
                if !line.to_ascii_lowercase().contains("p2p") {
                    continue;
                }
                let allowed = MAY_NAME_THE_SERVICE
                    .iter()
                    .any(|(file, part, _)| *file == rel && line.contains(part));
                if !allowed {
                    found.push(format!("{rel}:{}: {}", n + 1, line.trim()));
                }
            }
        }
        assert!(
            found.is_empty(),
            "the word is for crates/p2p (or MAY_NAME_THE_SERVICE, with a reason):\n{}",
            found.join("\n")
        );
    }

    /// The crates of the peers (libp2p, QUIC) are in the dependency graph of
    /// `velarx-p2p` only: `cargo metadata` of the workspace, with every
    /// feature, for each package.
    #[test]
    fn only_the_p2p_package_links_the_network_of_peers() {
        const OF_PEERS: [&str; 2] = ["libp2p", "quinn"];
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let out = std::process::Command::new(std::env::var_os("CARGO").unwrap_or("cargo".into()))
            .args(["metadata", "--format-version", "1", "--locked", "--offline"])
            .current_dir(root)
            .output()
            .expect("cargo metadata");
        assert!(
            out.status.success(),
            "cargo metadata: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let meta: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let mut name_of = std::collections::HashMap::new();
        for p in meta["packages"].as_array().unwrap() {
            name_of.insert(p["id"].as_str().unwrap(), p["name"].as_str().unwrap());
        }
        let nodes: std::collections::HashMap<&str, Vec<&str>> = meta["resolve"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| {
                (
                    n["id"].as_str().unwrap(),
                    n["dependencies"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|d| d.as_str().unwrap())
                        .collect(),
                )
            })
            .collect();
        let mut leaks = Vec::new();
        let mut service_links = false;
        for member in meta["workspace_members"].as_array().unwrap() {
            let member = member.as_str().unwrap();
            let is_service = name_of[member].starts_with("velarx-p2p");
            let mut seen = std::collections::HashSet::new();
            let mut todo = vec![member];
            while let Some(id) = todo.pop() {
                if !seen.insert(id) {
                    continue;
                }
                let name = name_of[id];
                if OF_PEERS.iter().any(|p| name.starts_with(p)) {
                    if is_service {
                        service_links = true;
                    } else {
                        leaks.push(format!("{} links {name}", name_of[member]));
                    }
                }
                todo.extend(nodes[id].iter().copied());
            }
        }
        assert!(
            service_links,
            "the check does not see the service's own crates"
        );
        assert!(leaks.is_empty(), "{leaks:#?}");
    }

    fn licensed_files(dir: &Path, root: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries {
            let p = e.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            if p.is_dir() {
                if !matches!(name.as_str(), "target" | "fixtures" | "corpus")
                    && !name.starts_with('.')
                {
                    licensed_files(&p, root, out);
                }
            } else if comment_of(&p.strip_prefix(root).unwrap().to_string_lossy()).is_some() {
                out.push(p);
            }
        }
    }

    /// A unit's `Documentation=` names installed man pages: the address of a
    /// web page would send `systemctl status` of every user wherever it
    /// points on the day.
    #[test]
    fn the_units_document_with_man_pages() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("systemd");
        let mut n = 0;
        for dir in ["system", "user"] {
            for e in std::fs::read_dir(root.join(dir)).unwrap() {
                let p = e.unwrap().path();
                let Ok(text) = std::fs::read_to_string(&p) else {
                    continue;
                };
                for line in text.lines() {
                    let Some(v) = line.strip_prefix("Documentation=") else {
                        continue;
                    };
                    n += 1;
                    assert!(
                        v.split_whitespace().all(|d| d.starts_with("man:")),
                        "{}: Documentation={v}: only man: pages",
                        p.display()
                    );
                }
            }
        }
        assert!(n > 20, "{n} Documentation= lines");
    }

    /// The tracked files link no project page that is not the project's (a
    /// GitHub account of that name belongs to someone else), and no workflow
    /// calls the API of the repository: the fuzz workflow opens no issue (a
    /// crashing input is kept as an artifact only).
    #[test]
    fn the_tree_links_no_foreign_page_and_no_workflow_calls_the_api() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let out = std::process::Command::new("git")
            .args(["ls-files", "-z"])
            .current_dir(root)
            .output();
        let Ok(out) = out else { return };
        if !out.status.success() {
            return;
        }
        // written in pieces: this file is scanned too
        let forbidden = [["github.com/", "velarx"].concat()];
        let mut bad = Vec::new();
        for f in String::from_utf8_lossy(&out.stdout).split('\0') {
            if f.is_empty() || f.starts_with("vendor/") || f.starts_with("fuzz/corpus/") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(root.join(f)) else {
                continue;
            };
            for w in &forbidden {
                if text.contains(w.as_str()) {
                    bad.push(format!("{f}: {w}"));
                }
            }
            if f.starts_with(".github/workflows/") && text.contains(concat!("api/v1", "/repos")) {
                bad.push(format!(
                    "{f}: a workflow that calls the API of the repository"
                ));
            }
        }
        assert!(bad.is_empty(), "{bad:#?}");
    }

    /// The store and fetcher services, which handle what peers and
    /// registries send, keep their hardening: a unit that loses one of these
    /// options is caught here, not in a review.  (The units of the service of
    /// the peers are checked by its own package.)
    #[test]
    fn the_store_and_fetcher_units_are_hardened() {
        const ALL: [&str; 8] = [
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "PrivateDevices=yes",
            "ProtectKernelTunables=yes",
            "ProtectKernelModules=yes",
            "RestrictRealtime=yes",
            "LockPersonality=yes",
            "SystemCallArchitectures=native",
        ];
        const NO_CODE_OR_PRIVILEGE: [&str; 6] = [
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
            "MemoryDenyWriteExecute=yes",
            "RestrictNamespaces=yes",
            "RestrictSUIDSGID=yes",
            "SystemCallFilter=@system-service",
        ];
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("systemd");
        let units = [
            ("system/velarx-store.service", true),
            ("user/velarx-store.service", true),
        ];
        let mut missing = Vec::new();
        for (unit, strict) in units {
            let text = std::fs::read_to_string(root.join(unit)).unwrap();
            let lines: Vec<&str> = text.lines().map(str::trim).collect();
            let wanted = ALL.iter().chain(
                strict
                    .then_some(&NO_CODE_OR_PRIVILEGE)
                    .into_iter()
                    .flatten(),
            );
            for option in wanted {
                if !lines.contains(option) {
                    missing.push(format!("{unit}: {option}"));
                }
            }
        }
        assert!(
            missing.is_empty(),
            "options missing from the units: {missing:#?}"
        );
        // the store service and its peers have no network of their own
        // (the store one has none at all)
        for unit in ["system/velarx-store.service", "user/velarx-store.service"] {
            let text = std::fs::read_to_string(root.join(unit)).unwrap();
            assert!(
                text.lines().any(|l| l.trim() == "PrivateNetwork=yes"),
                "{unit}"
            );
            assert!(
                text.lines()
                    .any(|l| l.trim() == "RestrictAddressFamilies=AF_UNIX"),
                "{unit}"
            );
        }
    }

    /// Types that `types_that_hold_secrets_do_not_derive_debug` would stop
    /// and that may be printed with `{:?}`: the type and why it holds no
    /// secret.
    const DEBUG_HOLDS_NO_SECRET: [(&str, &str); 18] = [
        ("AuthConfig", "the paths of the auth files"),
        ("AuthFile", "the path of an auth file"),
        (
            "AuthRequest",
            "the registry and the scope a token is asked for",
        ),
        ("Auth", "the scheme and the realm a registry asks for"),
        (
            "CreateSecretOptions",
            "the name, driver and labels of a secret",
        ),
        ("FileCredentials", "the path of a credentials file"),
        (
            "SecretCreate",
            "the name and the options, the data is in a pipe",
        ),
        ("SecretError", "the name of a secret"),
        ("SecretInfo", "the name and the metadata of a secret"),
        (
            "SecretInspected",
            "a SecretRecord, whose Debug leaves the data out",
        ),
        (
            "SecretListed",
            "a SecretRecord, whose Debug leaves the data out",
        ),
        ("SecretRef", "the name and the target of a secret"),
        (
            "BuildUnsupported",
            "the names of build options velarx refuses",
        ),
        (
            "BuildOptions",
            "the ids of its secrets: their values (SecretValue) print redacted",
        ),
        (
            "SecretSource",
            "the name of a variable or the path of a file, not the value",
        ),
        ("PolicyRequirement", "public keys and certificates"),
        ("RegistriesConfig", "the names of the credential helpers"),
        ("ConfFile", "the names of the credential helpers"),
    ];

    /// A field named for a secret.
    fn secret_field(name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        matches!(name.as_str(), "auth" | "creds" | "secrets")
            || [
                "password",
                "token",
                "secret_data",
                "credential",
                "private_key",
                "key_data",
                "registry_auth",
            ]
            .iter()
            .any(|w| name.contains(w))
    }

    /// A type that holds credentials, tokens or the data of a secret in a
    /// string (by its name, or by the name of a field) does not derive
    /// `Debug` (a `{:?}` of a call, a request or an error would write them
    /// to the logs): it implements it by hand and leaves them out.
    #[test]
    fn types_that_hold_secrets_do_not_derive_debug() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        sources(&root.join("src"), &mut files);
        sources(&root.join("crates"), &mut files);
        let mut found = Vec::new();
        let mut checked = 0;
        let stringly =
            |ty: &str| ty.contains("String") || ty.contains("Vec<u8>") || ty.contains("str");
        for f in files {
            let rel = f.strip_prefix(root).unwrap().to_string_lossy().to_string();
            if rel.contains("/tests/") || rel.ends_with("_tests.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&f).unwrap();
            let lines: Vec<&str> = text.lines().collect();
            for (n, line) in lines.iter().enumerate() {
                let t = line.trim_start();
                let Some(rest) = t
                    .strip_prefix("pub struct ")
                    .or_else(|| t.strip_prefix("pub(crate) struct "))
                    .or_else(|| t.strip_prefix("pub(super) struct "))
                    .or_else(|| t.strip_prefix("struct "))
                    .or_else(|| t.strip_prefix("pub enum "))
                    .or_else(|| t.strip_prefix("pub(crate) enum "))
                    .or_else(|| t.strip_prefix("pub(super) enum "))
                    .or_else(|| t.strip_prefix("enum "))
                else {
                    continue;
                };
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                // The attributes and the comments above, up to the item
                // before (a `derive` may span lines).
                let mut attrs = String::new();
                let mut k = n;
                while k > 0 {
                    k -= 1;
                    let a = lines[k].trim();
                    if a.is_empty() || a.ends_with('}') || a.ends_with(';') || a.ends_with('{') {
                        break;
                    }
                    attrs.insert_str(0, a);
                }
                let derives = attrs.split("derive(").skip(1).any(|d| {
                    d.split(')')
                        .next()
                        .unwrap_or("")
                        .split(',')
                        .any(|w| w.trim() == "Debug")
                });
                if !derives {
                    continue;
                }
                checked += 1;
                let indent = line.len() - t.len();
                let mut body = String::new();
                let mut fields = Vec::new();
                for l in &lines[n..] {
                    body.push_str(l);
                    body.push('\n');
                    let f = l.trim();
                    let f = f
                        .strip_prefix("pub(crate) ")
                        .or_else(|| f.strip_prefix("pub "))
                        .unwrap_or(f);
                    if let Some((field, ty)) = f.split_once(':') {
                        if !field.is_empty()
                            && field.chars().all(|c| c.is_alphanumeric() || c == '_')
                        {
                            fields.push((field.to_string(), ty.to_string()));
                        }
                    }
                    let end = l.trim_end();
                    if end.ends_with(';')
                        || (l.len() - l.trim_start().len() == indent && end.ends_with('}'))
                    {
                        break;
                    }
                }
                let named = ["Auth", "Credential", "Secret", "Password", "Token"]
                    .iter()
                    .any(|w| name.contains(w));
                let holds = if named {
                    stringly(&body)
                } else {
                    fields
                        .iter()
                        .any(|(field, ty)| secret_field(field) && stringly(ty))
                };
                if holds && !DEBUG_HOLDS_NO_SECRET.iter().any(|(n, _)| *n == name) {
                    found.push(format!("{rel}:{}: {name}", n + 1));
                }
            }
        }
        assert!(
            checked >= 500,
            "the walk found {checked} types that derive Debug"
        );
        assert!(
            found.is_empty(),
            "these types hold secrets in strings and derive Debug: implement \
             Debug by hand without the secrets, or list the type and why it holds \
             none in DEBUG_HOLDS_NO_SECRET:\n{}",
            found.join("\n")
        );
    }

    /// The vendored varlink library logs the direction and the size of a
    /// message at trace level, never the message: a call carries
    /// credentials.
    #[test]
    fn zlink_does_not_log_the_messages() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("vendor/zlink-core/src");
        for f in [
            "connection/read_connection.rs",
            "connection/write_connection.rs",
        ] {
            let text = std::fs::read_to_string(root.join(f)).unwrap();
            for (n, line) in text.lines().enumerate() {
                let t = line.trim();
                if t.starts_with("trace!(\"connection {}: ") || t.starts_with("debug!(") {
                    assert!(
                        !t.contains("{:?}\", self.id,") && !t.contains("from_utf8"),
                        "{f}:{}: a message is logged: {t}",
                        n + 1
                    );
                }
            }
            assert!(!text.contains("from_utf8_unchecked"), "{f}");
        }
    }

    /// Every source file says under which license it is: the line
    /// `SPDX-License-Identifier: Apache-2.0`, once, in its first lines, and
    /// so does every `license` of a Cargo.toml.
    #[test]
    fn every_file_has_the_spdx_line_of_the_license() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        for top in ["src", "crates", "tests", "fuzz", "systemd", "docs"] {
            licensed_files(&root.join(top), root, &mut files);
        }
        for f in [
            "build.rs",
            "Makefile",
            "Cargo.toml",
            "config.toml.example",
            "deny.toml",
            "README.md",
            "AGENTS.md",
        ] {
            if root.join(f).exists() {
                files.push(root.join(f));
            }
        }
        assert!(files.len() > 100, "the walk found {} files", files.len());
        let mut found = Vec::new();
        for f in &files {
            let rel = f.strip_prefix(root).unwrap().to_string_lossy().to_string();
            let comment = comment_of(&rel).unwrap();
            let close = if comment == "<!--" { " -->" } else { "" };
            let want = format!("{comment} {SPDX} {CODE_LICENSE}{close}");
            let text = std::fs::read_to_string(f).unwrap();
            let lines: Vec<_> = text.lines().collect();
            let spdx: Vec<_> = lines
                .iter()
                .enumerate()
                .filter(|(_, l)| l.starts_with(&format!("{comment} {SPDX}")))
                .collect();
            let ok = matches!(spdx.as_slice(), [(n, l)] if **l == want && *n < 2);
            if !ok {
                found.push(format!("{rel}: expected `{want}` as the first line (the second after a `#!` line), found {:?}", spdx.iter().map(|(n, l)| format!("{}: {l}", n + 1)).collect::<Vec<_>>()));
            }
        }
        // The interface definitions too (programs in other languages use
        // them).
        let interfaces = root.join("interfaces");
        let mut definitions = 0;
        for e in std::fs::read_dir(&interfaces).into_iter().flatten() {
            let p = e.unwrap().path();
            if p.extension().is_some_and(|x| x == "varlink") {
                definitions += 1;
                let want = format!("# {SPDX} {CODE_LICENSE}");
                let text = std::fs::read_to_string(&p).unwrap();
                if text.lines().next() != Some(want.as_str()) {
                    found.push(format!(
                        "{}: expected `{want}` as the first line",
                        p.strip_prefix(root).unwrap().display()
                    ));
                }
            }
        }
        assert!(definitions > 0, "no interface definition in interfaces/");
        // The workspace and the fuzz package (a workspace of its own) say
        // the license; the packages of the workspace inherit it.
        let mut manifests = vec![
            (root.join("Cargo.toml"), true),
            (root.join("fuzz/Cargo.toml"), true),
        ];
        for p in workspace_packages(root).into_iter().skip(1) {
            manifests.push((p.join("Cargo.toml"), false));
        }
        for (m, says) in manifests {
            let text = std::fs::read_to_string(&m).unwrap();
            let want = if says {
                format!("license = \"{CODE_LICENSE}\"")
            } else {
                "license.workspace = true".to_string()
            };
            if !text.lines().any(|l| l == want) {
                found.push(format!(
                    "{}: expected `{want}`",
                    m.strip_prefix(root).unwrap().display()
                ));
            }
        }
        assert!(
            found.is_empty(),
            "files without the SPDX line of the license of velarx:\n{}",
            found.join("\n")
        );
    }

    /// The files of podman and the container libraries velarx must not
    /// read: their directories, and the variables that name them.  Its
    /// own files (of the same formats) are in /etc/velarx,
    /// /usr/share/velarx and the user's velarx directory.
    const PODMAN_PLACES: [&str; 13] = [
        "/etc/containers",
        "/usr/share/containers",
        ".config/containers",
        "/run/containers",
        "containers/registries",
        "containers/policy.json",
        "containers/certs.d",
        "containers/auth.json",
        "containers/oci",
        "CONTAINERS_CONF",
        "CONTAINERS_REGISTRIES_CONF",
        "CONTAINERS_STORAGE_CONF",
        "REGISTRIES_CONFIG_PATH",
    ];

    /// The lines that may name them (file, text of the line, why).
    const MAY_NAME_PODMAN_PLACES: [(&str, &str, &str); 7] = [
        (
            "tests/e2e/bats/podman-apiv2.bats",
            "for f in \"\\${CONTAINERS_CONF:-}\"",
            "the containers.conf files that podman's suite names, translated to velarx settings for the test",
        ),
        (
            "tests/e2e/bats/signature.bats",
            "ln -s \"$XDG_CONFIG_HOME/velarx/registries.d\"",
            "the registries.d of the podman that signs the images of the test",
        ),
        (
            "tests/e2e/bats/podman-apiv2.bats",
            "conf=\\${CONTAINERS_REGISTRIES_CONF:-",
            "the registries.conf podman's suite names, handed to velarx in its variable",
        ),
        (
            "crates/api/src/podman/build.rs",
            "const DEFAULT_SECCOMP",
            "the path podman's client sends for its default profile, taken as no option",
        ),
        (
            "tests/e2e/bats/api/build.bats",
            "CONTAINERS_STORAGE_CONF=$compat",
            "the store of the podman that the test compares with",
        ),
        (
            "tests/e2e/bats/flags.bats",
            "CONTAINERS_STORAGE_CONF=$WORKDIR/storage-typo.conf CONTAINERS_CONF=",
            "the test that velarx reads neither",
        ),
        (
            "README.md",
            "It never reads `/etc/containers`",
            "the requirements say so",
        ),
    ];

    fn podman_place_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries {
            let p = e.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            if p.is_dir() {
                if !matches!(name.as_str(), "target" | "corpus") && !name.starts_with('.') {
                    podman_place_files(&p, out);
                }
            } else if p.extension().is_some_and(|x| {
                [
                    "rs", "toml", "sh", "py", "bats", "bash", "service", "socket", "timer", "conf",
                    "md", "json", "yaml", "varlink",
                ]
                .iter()
                .any(|e| x == *e)
            }) || name == "velarx-generator"
            {
                out.push(p);
            }
        }
    }

    /// velarx reads only its own files: no source, script, unit or document
    /// names a directory or a variable of podman's configuration, but the
    /// lines of MAY_NAME_PODMAN_PLACES.
    #[test]
    fn nothing_reads_the_files_of_podman() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        for top in [
            "src",
            "crates",
            "tests",
            "systemd",
            "tools",
            "docs",
            "share",
            "examples",
            "fuzz",
            "interfaces",
        ] {
            podman_place_files(&root.join(top), &mut files);
        }
        for f in [
            "Makefile",
            "config.toml.example",
            "README.md",
            "CONTRIBUTING.md",
            "AGENTS.md",
        ] {
            files.push(root.join(f));
        }
        let mut used = vec![false; MAY_NAME_PODMAN_PLACES.len()];
        let mut found = Vec::new();
        for f in files {
            let rel = f.strip_prefix(root).unwrap().to_string_lossy().to_string();
            if rel == "src/testing.rs" {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&f) else {
                continue;
            };
            for (n, l) in text.lines().enumerate() {
                if !PODMAN_PLACES.iter().any(|p| l.contains(p)) {
                    continue;
                }
                match MAY_NAME_PODMAN_PLACES
                    .iter()
                    .position(|(file, line, _)| rel == *file && l.contains(line))
                {
                    Some(i) => used[i] = true,
                    None => found.push(format!("{rel}:{}: {}", n + 1, l.trim())),
                }
            }
        }
        assert!(
            found.is_empty(),
            "velarx reads its own files only (/etc/velarx, /usr/share/velarx, the user's \
             velarx directory, VELARX_* variables), never podman's:\n{}",
            found.join("\n")
        );
        let stale: Vec<_> = MAY_NAME_PODMAN_PLACES
            .iter()
            .zip(&used)
            .filter(|(_, u)| !**u)
            .map(|(e, _)| format!("{}: {}", e.0, e.1))
            .collect();
        assert!(
            stale.is_empty(),
            "MAY_NAME_PODMAN_PLACES lines that are gone: {stale:?}"
        );
    }

    /// Whether `code` calls a blocking function of `std::fs` (not a type of
    /// it, not a conversion).
    fn calls_std_fs(code: &str) -> bool {
        if code.contains("std::os::unix::fs::symlink(") {
            return true;
        }
        let mut rest = code;
        while let Some(i) = rest.find("std::fs::") {
            rest = &rest[i + "std::fs::".len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let after = &rest[name.len()..];
            let call = match name.as_str() {
                "File" => after.starts_with("::open(") || after.starts_with("::create("),
                n => n.chars().next().is_some_and(|c| c.is_lowercase()) && after.starts_with('('),
            };
            if call {
                return true;
            }
        }
        false
    }

    /// Whether `code` makes a call of `std::fs` whose time has no bound: a
    /// recursive remove, a copy (`fs::` as `use std::fs` names it).
    fn calls_unbounded_fs(code: &str) -> bool {
        ["remove_dir_all(", "copy("].iter().any(|f| {
            code.match_indices(&format!("fs::{f}"))
                .any(|(i, _)| !code[..i].ends_with("tokio::"))
        }) || code.contains("tree::remove_dir_all")
            || code.contains("tree::remove_tree")
    }

    /// The lines of the `async fn`s of `files` (outside of their tests)
    /// where `call` finds a call, outside the closures run by the blocking
    /// pool (`spawn_blocking`, `off_thread`) or `api::blocking`.
    fn blocking_calls_in_async_fns(
        root: &Path,
        files: &[PathBuf],
        call: fn(&str) -> bool,
    ) -> Vec<String> {
        let mut found = Vec::new();
        for file in files {
            let text = std::fs::read_to_string(file).unwrap();
            let rel = file.strip_prefix(root).unwrap().display().to_string();
            let code = text.split("#[cfg(test)]").next().unwrap();
            // the depth of the braces where the `async fn` being read
            // began, and where a blocking region began
            let (mut depth, mut in_async, mut in_blocking) = (0i32, None::<i32>, None::<i32>);
            for (n, line) in code.lines().enumerate() {
                let c = code_of(line);
                if in_async.is_none() && c.contains("async fn ") {
                    in_async = Some(depth);
                }
                if in_async.is_some()
                    && in_blocking.is_none()
                    && (c.contains("blocking(") || c.contains("off_thread("))
                {
                    in_blocking = Some(depth);
                }
                if in_async.is_some() && in_blocking.is_none() && call(&c) {
                    found.push(format!("{rel}:{}: {}", n + 1, line.trim()));
                }
                depth += c.matches('{').count() as i32 - c.matches('}').count() as i32;
                if in_blocking.is_some_and(|d| depth <= d) {
                    in_blocking = None;
                }
                if in_async.is_some_and(|d| depth <= d && c.contains('}')) {
                    in_async = None;
                    in_blocking = None;
                }
            }
        }
        found
    }

    #[test]
    fn a_blocking_call_in_an_async_fn_is_found() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.rs");
        std::fs::write(
            &file,
            "async fn a() {\n    let x = 1;\n    std::fs::create_dir(\"d\").unwrap();\n}\n\
             fn b() {\n    std::fs::create_dir(\"d\").unwrap();\n}\n\
             async fn c() {\n    off_thread(move || {\n        std::fs::remove_dir_all(\"d\")\n    })\n    .await;\n    \
             let _ = fs::remove_dir_all(\"e\");\n    tokio::fs::remove_dir_all(\"f\").await;\n    \
             std::os::unix::fs::symlink(\"a\", \"b\");\n}\n",
        )
        .unwrap();
        let files = vec![file];
        let found = blocking_calls_in_async_fns(dir.path(), &files, calls_std_fs);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(
            found[0].starts_with("a.rs:3:") && found[1].starts_with("a.rs:15:"),
            "{found:?}"
        );
        let found = blocking_calls_in_async_fns(dir.path(), &files, calls_unbounded_fs);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].starts_with("a.rs:13:"), "{found:?}");
    }

    /// The handlers of the engine run on async threads: a call of `std::fs`
    /// in an `async fn` blocks the thread (and the other tasks on it).  Use
    /// `api::off_thread` (one turn of the blocking pool for the file work of
    /// a request) or, for code that cannot await, `api::blocking`.  (The
    /// files name `std::fs` in full, which is what the test reads.)
    #[test]
    fn the_async_handlers_of_the_engine_make_no_blocking_file_calls() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        sources(&root.join("src/api"), &mut files);
        let short: Vec<_> = files
            .iter()
            .filter(|f| {
                let text = std::fs::read_to_string(f).unwrap();
                text.lines().any(|l| {
                    l.trim_start().starts_with("use std::fs") || l.contains("use std::{fs")
                })
            })
            .collect();
        assert!(short.is_empty(), "src/api names std::fs in full: {short:?}");
        let found = blocking_calls_in_async_fns(root, &files, calls_std_fs);
        assert!(
            found.is_empty(),
            "blocking calls of std::fs in async fns of src/api:\n{}",
            found.join("\n")
        );
    }

    /// The lines (from 1) of `text` outside of its `#[cfg(test)]` items (an
    /// item is skipped to the end of its braces, or of its line) and of its
    /// comments.
    fn non_test_lines(text: &str) -> Vec<(usize, &str)> {
        let lines: Vec<&str> = text.lines().collect();
        let mut out = Vec::new();
        let mut i = 0;
        while i < lines.len() {
            if lines[i].trim() != "#[cfg(test)]" {
                if !lines[i].trim_start().starts_with("//") {
                    out.push((i + 1, lines[i]));
                }
                i += 1;
                continue;
            }
            let (mut depth, mut opened) = (0i64, false);
            i += 1;
            while i < lines.len() {
                let l = lines[i];
                depth += l.matches('{').count() as i64 - l.matches('}').count() as i64;
                opened |= l.contains('{');
                i += 1;
                if (opened && depth <= 0) || (!opened && l.trim_end().ends_with(';')) {
                    break;
                }
            }
        }
        out
    }

    /// The lines of `text` (outside of its tests) that remove a tree with
    /// the `remove_dir_all` of `std::fs` (or of `tokio::fs`, the same on a
    /// thread): called, passed as a function, or imported.
    fn std_tree_removals(text: &str) -> Vec<usize> {
        non_test_lines(text)
            .into_iter()
            .filter(|(_, l)| {
                l.contains("fs::remove_dir_all")
                    || (l.trim_start().starts_with("use ")
                        && l.contains("fs::")
                        && l.contains("remove_dir_all"))
            })
            .map(|(n, _)| n)
            .collect()
    }

    #[test]
    fn a_tree_removed_by_std_is_found_outside_of_the_tests() {
        let code = "use std::fs::{self, remove_dir_all};\n\
            fn a() {\n    std::fs::remove_dir_all(\"a\").ok();\n}\n\
            #[cfg(test)]\nfn helper() {\n    std::fs::remove_dir_all(\"t\").ok();\n}\n\
            fn b() {\n    paths.iter().try_for_each(fs::remove_dir_all)\n}\n\
            // (not std::fs::remove_dir_all: a comment)\n\
            fn c() {\n    velarx_base::tree::remove_dir_all(\"c\").ok();\n}\n\
            #[cfg(test)]\nmod tests {\n    fn t() {\n        std::fs::remove_dir_all(\"t\").ok();\n    }\n}\n";
        assert_eq!(std_tree_removals(code), [1, 3, 10]);
    }

    /// A tree is removed by `velarx_base::tree` (`remove_dir_all`,
    /// `remove_dir_all_confined`, `remove_tree`), the one walker of the
    /// engine: `std::fs::remove_dir_all` recurses on the caller's stack with
    /// a descriptor per level and follows a mount.
    #[test]
    fn no_code_but_the_tests_removes_a_tree_with_std() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        sources(&root.join("src"), &mut files);
        sources(&root.join("crates"), &mut files);
        files.retain(|f| !f.components().any(|c| c.as_os_str() == "tests"));
        let mut found = Vec::new();
        for file in files {
            if file.ends_with("src/testing.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&file).unwrap();
            let lines: Vec<&str> = text.lines().collect();
            for n in std_tree_removals(&text) {
                found.push(format!("{}:{n}: {}", file.display(), lines[n - 1].trim()));
            }
        }
        assert!(
            found.is_empty(),
            "std removes a tree outside of tests (use velarx_base::tree):\n{}",
            found.join("\n")
        );
    }

    /// No `async fn` of the engine (its services, the pulls, the store...)
    /// waits on its thread for a file work without a bound, a recursive
    /// remove or a copy: `velarx_runtime::off_thread` runs it in the blocking
    /// pool.
    #[test]
    fn the_async_fns_of_the_crates_make_no_unbounded_file_calls() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        sources(&root.join("src"), &mut files);
        sources(&root.join("crates"), &mut files);
        files.retain(|f| !f.components().any(|c| c.as_os_str() == "tests"));
        let found = blocking_calls_in_async_fns(root, &files, calls_unbounded_fs);
        assert!(
            found.is_empty(),
            "recursive removes or copies in async fns:\n{}",
            found.join("\n")
        );
    }

    /// The lines (from 1) of `text` that keep a temporary directory: the
    /// directory of a test is removed when its `TempDir` goes, and one kept
    /// (`keep`, `into_path`, `disable_cleanup`) or forgotten
    /// (`mem::forget`, `ManuallyDrop`) stays in `TMPDIR` for ever.  (By the
    /// lines: a `TempDir` made over several lines, a `Builder`'s, is not
    /// seen; `make test-leaks` finds what it leaves.)  A fixture owns its
    /// directory (a field `TempDir`), and a mount point or a socket made in
    /// it is removed with it.  `make test-leaks` runs the tests of the
    /// packages in a private `TMPDIR` and fails on what they leave.
    fn kept_directories(text: &str) -> Vec<usize> {
        let (keep, into_path, disable) = (".keep(", ".into_path(", ".disable_cleanup(");
        let mut names: Vec<&str> = Vec::new();
        let mut found = Vec::new();
        for (n, line) in text.lines().enumerate().map(|(i, l)| (i + 1, l)) {
            let code = line.split("//").next().unwrap_or("");
            let made = code.contains("tempdir(")
                || code.contains("tempdir_in(")
                || code.contains("TempDir::new")
                || code.contains("TempDir::with_");
            if made {
                // (`let [mut] name = tempfile::tempdir()...`)
                if let Some(name) = code
                    .trim_start()
                    .strip_prefix("let ")
                    .map(|l| l.trim_start_matches("mut "))
                    .and_then(|l| l.split([' ', ':', '=']).next())
                    .filter(|n| !n.is_empty() && !n.starts_with('('))
                {
                    names.push(name);
                }
            }
            let keeps = |c: &str| c.contains(keep) || c.contains(into_path) || c.contains(disable);
            let forgets = |name: &str| {
                code.contains(&format!("forget({name})"))
                    || code.contains(&format!("forget(self.{name})"))
                    || code.contains(&format!("ManuallyDrop::new({name})"))
            };
            let named = names.iter().any(|name| {
                (code.contains(&format!("{name}.keep("))
                    || code.contains(&format!("{name}.into_path("))
                    || code.contains(&format!("{name}.disable_cleanup(")))
                    || forgets(name)
            });
            if (made && keeps(code)) || named {
                found.push(n);
            }
        }
        found
    }

    #[test]
    fn a_kept_temporary_directory_is_found() {
        let code = "fn a() {\n    let d = tempfile::tempdir().unwrap().keep();\n}\n\
            fn b() {\n    let t = tempfile::tempdir().unwrap();\n    let p = t.keep();\n}\n\
            fn c() {\n    let mut u = tempfile::tempdir_in(\"x\").unwrap();\n    \
            std::mem::forget(u);\n}\n\
            fn d() {\n    let v = tempfile::tempdir().unwrap().into_path();\n}\n\
            fn e() {\n    let w = tempfile::tempdir().unwrap();\n    let p = w.path();\n    \
            // t.keep() in a comment\n    other.keep();\n}\n\
            fn f() {\n    let x = TempDir::with_prefix(\"p\").unwrap();\n    \
            let _y = std::mem::ManuallyDrop::new(x);\n}\n";
        assert_eq!(kept_directories(code), [2, 6, 10, 13, 23]);
    }

    /// No test keeps its temporary directory (`tempdir().keep()`,
    /// `into_path`, `mem::forget` of a `TempDir`): it would stay in `TMPDIR`
    /// after every run.
    #[test]
    fn no_test_keeps_a_temporary_directory() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        for dir in ["src", "crates", "tests"] {
            sources(&root.join(dir), &mut files);
        }
        let mut found = Vec::new();
        for file in files {
            if file.ends_with("src/testing.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&file).unwrap();
            let lines: Vec<&str> = text.lines().collect();
            for n in kept_directories(&text) {
                found.push(format!("{}:{n}: {}", file.display(), lines[n - 1].trim()));
            }
        }
        assert!(
            found.is_empty(),
            "a temporary directory is kept (make the fixture own it):\n{}",
            found.join("\n")
        );
    }
}
