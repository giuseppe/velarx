// SPDX-License-Identifier: Apache-2.0
//! OCI hooks from hooks.d directories, as podman reads them
//! (oci-hooks(5), containers/common `pkg/hooks`): JSON files of version
//! 1.0.0 (or the older 0.1.0) that say which program runs, when (always,
//! for some annotations or commands, with bind mounts) and at which stages.
//!
//! The hooks a container matches go into its `config.json`, and the
//! runtime runs them: createRuntime (podman's mapping of `prestart` too),
//! createContainer, startContainer, poststart and poststop (at the delete,
//! as the runtime spec says).  `precreate` hooks run here, before the
//! container is created: each gets the configuration on its stdin and
//! writes the one to use on its stdout.

use regex_lite::Regex;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The directory of the hooks of the packages.
pub const DEFAULT_DIR: &str = "/usr/share/velarx/oci/hooks.d";
/// The directory of the administrator's hooks, over those of the packages.
pub const OVERRIDE_DIR: &str = "/etc/velarx/oci/hooks.d";

/// The stages a hook may name.
const STAGES: &[&str] = &[
    "createContainer",
    "createRuntime",
    "prestart",
    "poststart",
    "poststop",
    "startContainer",
    "precreate",
];

/// The program of a hook, as in the runtime spec.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct HookCommand {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<i64>,
}

impl HookCommand {
    fn to_json(&self) -> Value {
        let mut v = json!({ "path": self.path });
        if let Some(a) = &self.args {
            v["args"] = json!(a);
        }
        if let Some(e) = &self.env {
            v["env"] = json!(e);
        }
        if let Some(t) = self.timeout {
            v["timeout"] = json!(t);
        }
        v
    }
}

/// When a hook applies.
#[derive(Debug, Default)]
pub struct When {
    always: Option<bool>,
    annotations: Vec<(Regex, Regex)>,
    commands: Vec<Regex>,
    has_bind_mounts: Option<bool>,
    /// Any condition is enough (0.1.0); all of them otherwise.
    or: bool,
}

/// A hook of a hooks.d directory.
#[derive(Debug)]
pub struct HookFile {
    pub hook: HookCommand,
    pub when: When,
    pub stages: Vec<String>,
}

#[derive(Deserialize)]
struct Version {
    #[serde(default)]
    version: String,
}

#[derive(Deserialize)]
struct V1 {
    hook: HookCommand,
    #[serde(default)]
    when: V1When,
    stages: Option<Vec<String>>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct V1When {
    always: Option<bool>,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
    #[serde(default)]
    commands: Vec<String>,
    has_bind_mounts: Option<bool>,
}

#[derive(Deserialize)]
struct V0 {
    hook: Option<String>,
    arguments: Option<Vec<String>>,
    stages: Option<Vec<String>>,
    stage: Option<Vec<String>>,
    cmds: Option<Vec<String>>,
    cmd: Option<Vec<String>>,
    annotations: Option<Vec<String>>,
    annotation: Option<Vec<String>>,
    hasbindmounts: Option<bool>,
}

fn regex(what: &str, s: &str) -> Result<Regex, String> {
    Regex::new(s).map_err(|e| format!("invalid {what} {s:?}: {e}"))
}

/// One of two spellings of a 0.1.0 property.
fn one_of<T>(a: Option<T>, b: Option<T>, names: &str) -> Result<Option<T>, String> {
    match (a, b) {
        (Some(_), Some(_)) => Err(format!("cannot set both {names}")),
        (a, b) => Ok(a.or(b)),
    }
}

/// Parse a hook file.
pub fn parse(content: &[u8]) -> Result<HookFile, String> {
    let ver: Version =
        serde_json::from_slice(content).map_err(|e| format!("version check: {e}"))?;
    let hook = match ver.version.as_str() {
        "1.0.0" => {
            let v: V1 = serde_json::from_slice(content).map_err(|e| format!("1.0.0: {e}"))?;
            let mut annotations = Vec::new();
            for (k, val) in &v.when.annotations {
                annotations.push((regex("annotation key", k)?, regex("annotation value", val)?));
            }
            HookFile {
                hook: v.hook,
                when: When {
                    always: v.when.always,
                    annotations,
                    commands: v
                        .when
                        .commands
                        .iter()
                        .map(|c| regex("command", c))
                        .collect::<Result<_, _>>()?,
                    has_bind_mounts: v.when.has_bind_mounts,
                    or: false,
                },
                stages: v.stages.ok_or("missing required property: stages")?,
            }
        }
        "" | "0.1.0" => {
            let v: V0 = serde_json::from_slice(content).map_err(|e| format!("0.1.0: {e}"))?;
            let path = v.hook.ok_or("missing required property: hook")?;
            let stages = one_of(v.stages, v.stage, "'stage' and 'stages'")?
                .ok_or("missing required property: stages")?;
            let cmds = one_of(v.cmds, v.cmd, "'cmd' and 'cmds'")?.unwrap_or_default();
            let annotations = one_of(
                v.annotations,
                v.annotation,
                "'annotation' and 'annotations'",
            )?;
            HookFile {
                hook: HookCommand {
                    args: v
                        .arguments
                        .map(|a| std::iter::once(path.clone()).chain(a).collect()),
                    path,
                    env: None,
                    timeout: None,
                },
                when: When {
                    always: None,
                    annotations: match annotations {
                        Some(a) => vec![(
                            regex("annotation key", ".*")?,
                            regex("annotation", &a.join("|"))?,
                        )],
                        None => Vec::new(),
                    },
                    commands: cmds
                        .iter()
                        .map(|c| regex("command", c))
                        .collect::<Result<_, _>>()?,
                    has_bind_mounts: v.hasbindmounts,
                    or: true,
                },
                stages,
            }
        }
        other => return Err(format!("unrecognized hook version: {other:?}")),
    };
    if hook.hook.path.is_empty() {
        return Err("missing required property: hook.path".into());
    }
    if let Some(s) = hook.stages.iter().find(|s| !STAGES.contains(&s.as_str())) {
        return Err(format!("unknown stage {s:?}"));
    }
    Ok(hook)
}

impl When {
    /// Whether the hook applies to a container (containers/common's
    /// `When.Match`).
    pub fn matches(
        &self,
        annotations: &HashMap<String, String>,
        command: Option<&str>,
        has_bind_mounts: bool,
    ) -> bool {
        let mut matches = 0;
        if let Some(always) = self.always {
            if always {
                if self.or {
                    return true;
                }
                matches += 1;
            } else if !self.or {
                return false;
            }
        }
        if let Some(want) = self.has_bind_mounts {
            if want && has_bind_mounts {
                if self.or {
                    return true;
                }
                matches += 1;
            } else if !self.or {
                return false;
            }
        }
        for (k, v) in &self.annotations {
            let hit = annotations
                .iter()
                .any(|(ak, av)| k.is_match(ak) && v.is_match(av));
            if hit {
                if self.or {
                    return true;
                }
                matches += 1;
            } else if !self.or {
                return false;
            }
        }
        if !self.commands.is_empty() {
            if let Some(cmd) = command {
                return self.commands.iter().any(|c| c.is_match(cmd));
            }
        }
        matches > 0
    }
}

/// The directories of the hooks: `[containers] hooks_dir` of the
/// configuration (or `--hooks-dir`); without it, root reads the default and
/// override directories and a rootless user none.
pub fn hook_dirs(configured: &[String]) -> Result<Vec<PathBuf>, velarx_base::ids::IdsError> {
    if !configured.is_empty() {
        return Ok(configured.iter().map(PathBuf::from).collect());
    }
    Ok(if velarx_base::ids::host_uid()? == 0 {
        vec![PathBuf::from(DEFAULT_DIR), PathBuf::from(OVERRIDE_DIR)]
    } else {
        Vec::new()
    })
}

/// The hooks of `dirs` by file name; a file of a later directory replaces
/// the one of the same name.  A directory that is not there has none; a
/// file that is not valid is an error (as podman's).
pub fn load(dirs: &[PathBuf]) -> Result<BTreeMap<String, HookFile>, String> {
    let mut hooks = BTreeMap::new();
    for dir in dirs {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("reading the hooks of {}: {e}", dir.display())),
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".json") {
                continue;
            }
            let path = entry.path();
            let content = match std::fs::read(&path) {
                Ok(c) => c,
                // (a dangling link: removed meanwhile)
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(format!("reading the hook {}: {e}", path.display())),
            };
            let hook =
                parse(&content).map_err(|e| format!("parsing hook {}: {e}", path.display()))?;
            if !Path::new(&hook.hook.path).exists() {
                return Err(format!(
                    "the hook {} runs {}, which is not there",
                    path.display(),
                    hook.hook.path
                ));
            }
            hooks.insert(name, hook);
        }
    }
    Ok(hooks)
}

/// Add the hooks that apply to the configuration `spec` of a container to
/// its `hooks`, by the lowercase name of their files; the `precreate` ones
/// are returned, to be run on the configuration before it is written.
pub fn inject(
    spec: &mut Value,
    hooks: &BTreeMap<String, HookFile>,
    has_bind_mounts: bool,
) -> Vec<HookCommand> {
    let annotations: HashMap<String, String> = spec
        .get("annotations")
        .and_then(Value::as_object)
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                .collect()
        })
        .unwrap_or_default();
    let command = spec
        .pointer("/process/args/0")
        .and_then(Value::as_str)
        .map(str::to_string);
    let mut named: Vec<(&String, &HookFile)> = hooks.iter().collect();
    named.sort_by_key(|(n, _)| n.to_lowercase());
    let mut precreate = Vec::new();
    for (_, h) in named {
        if !h
            .when
            .matches(&annotations, command.as_deref(), has_bind_mounts)
        {
            continue;
        }
        for stage in &h.stages {
            let key = match stage.as_str() {
                "precreate" => {
                    precreate.push(h.hook.clone());
                    continue;
                }
                "createRuntime" | "prestart" => "createRuntime",
                s => s,
            };
            if !spec["hooks"].is_object() {
                spec["hooks"] = json!({});
            }
            let list = &mut spec["hooks"][key];
            if !list.is_array() {
                *list = json!([]);
            }
            if let Some(a) = list.as_array_mut() {
                a.push(h.hook.to_json());
            }
        }
    }
    precreate
}

/// The most a `precreate` hook may write on a stream.
const PRECREATE_OUTPUT_MAX: u64 = 64 << 20;

/// Run the `precreate` hooks: each gets the configuration on its stdin, in
/// the bundle directory, and writes the configuration to use.
pub fn run_precreate(hooks: &[HookCommand], spec: &mut Value, dir: &Path) -> Result<(), String> {
    for h in hooks {
        let mut cmd = Command::new(&h.path);
        velarx_base::hardening::restore_open_files(
            &mut cmd,
            velarx_base::hardening::original_open_files(),
        );
        velarx_base::ids::scrub_runtime_dir(&mut cmd).map_err(|e| e.to_string())?;
        if let Some(args) = &h.args {
            if let Some((argv0, rest)) = args.split_first() {
                use std::os::unix::process::CommandExt;
                cmd.arg0(argv0).args(rest);
            }
        }
        if let Some(env) = &h.env {
            cmd.env_clear();
            for e in env {
                if let Some((k, v)) = e.split_once('=') {
                    cmd.env(k, v);
                }
            }
        }
        let mut child = cmd
            .current_dir(dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("precreate hook {}: {e}", h.path))?;
        let input = serde_json::to_vec(&spec).map_err(|e| e.to_string())?;
        let mut stdin = child.stdin.take();
        let writer = std::thread::spawn(move || {
            if let Some(s) = stdin.as_mut() {
                let _ = s.write_all(&input);
            }
        });
        let reader = |stream: Option<Box<dyn Read + Send>>| {
            std::thread::spawn(move || {
                let mut out = Vec::new();
                if let Some(s) = stream {
                    let _ = s.take(PRECREATE_OUTPUT_MAX).read_to_end(&mut out);
                }
                out
            })
        };
        let stdout = reader(child.stdout.take().map(|s| Box::new(s) as _));
        let stderr = reader(child.stderr.take().map(|s| Box::new(s) as _));
        let timeout = h
            .timeout
            .filter(|t| *t > 0)
            .map(|t| rustix::event::Timespec {
                tv_sec: t,
                tv_nsec: 0,
            });
        let fail = |e: &dyn std::fmt::Display| format!("precreate hook {}: {e}", h.path);
        let pidfd = rustix::process::pidfd_open(
            rustix::process::Pid::from_child(&child),
            rustix::process::PidfdFlags::empty(),
        )
        .map_err(|e| fail(&e))?;
        let mut fds = [rustix::event::PollFd::new(
            &pidfd,
            rustix::event::PollFlags::IN,
        )];
        let ready = loop {
            match rustix::event::poll(&mut fds, timeout.as_ref()) {
                Err(rustix::io::Errno::INTR) => {}
                Err(e) => return Err(fail(&e)),
                Ok(n) => break n,
            }
        };
        if ready == 0 {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("precreate hook {} timed out", h.path));
        }
        let status = child.wait().map_err(|e| fail(&e))?;
        let _ = writer.join();
        let out = stdout.join().unwrap_or_default();
        let err = String::from_utf8_lossy(&stderr.join().unwrap_or_default()).into_owned();
        if !status.success() {
            return Err(format!(
                "precreate hook {} failed ({status}): {}",
                h.path,
                err.trim()
            ));
        }
        *spec = serde_json::from_slice(&out).map_err(|e| {
            format!(
                "precreate hook {}: its output is not a configuration: {e}",
                h.path
            )
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> Value {
        json!({
            "process": {"args": ["/usr/bin/sleep", "1"]},
            "annotations": {"io.example/trace": "on", "other": "x"},
        })
    }

    #[test]
    fn conditions_are_go_regular_expressions() {
        let hook = |cmd: &str| {
            let doc = json!({"version": "1.0.0", "hook": {"path": "/bin/true"},
                "when": {"commands": [cmd]}, "stages": ["prestart"]});
            parse(doc.to_string().as_bytes())
        };
        let none = HashMap::new();
        for (cmd, arg, hit) in [
            ("^/usr/bin/(sleep|true)$", "/usr/bin/sleep", true),
            ("^/usr/bin/(sleep|true)$", "/usr/bin/sleep2", false),
            (r"/bin/\w+$", "/bin/sh", true),
            (r"^/bin/[a-z]{2,4}\d?$", "/bin/bash", true),
            (r"^/bin/[a-z]{2}$", "/bin/bash", false),
            (r"\s", "a b", true),
            (r"\bsh\b", "/bin/sh -c", true),
            ("(?i)^/BIN/SH$", "/bin/sh", true),
            ("[[:digit:]]+", "x1", true),
            ("(?:a|b)c", "bc", true),
            (".*", "", true),
            ("^$", "x", false),
        ] {
            let h = hook(cmd).unwrap();
            assert_eq!(
                h.when.matches(&none, Some(arg), false),
                hit,
                "{cmd:?} ~ {arg:?}"
            );
        }
        // what a Go program accepts and this syntax has not is an error at load
        for bad in [r"\pL", r"(?<=a)b", "(", "a{2,1}", "[z-a]"] {
            let e = hook(bad).err().unwrap();
            assert!(e.starts_with(&format!("invalid command {bad:?}: ")), "{e}");
        }
    }

    #[test]
    fn version_1_files_and_conditions() {
        let h = parse(br#"{"version":"1.0.0","hook":{"path":"/bin/true","args":["true","a"],"timeout":5},
            "when":{"annotations":{"^io\\.example/trace$":"^on$"}},"stages":["prestart","poststop"]}"#)
        .unwrap();
        let none = HashMap::new();
        let ann: HashMap<String, String> =
            [("io.example/trace".to_string(), "on".to_string())].into();
        assert!(h.when.matches(&ann, Some("/bin/sh"), false));
        assert!(!h.when.matches(&none, Some("/bin/sh"), false));
        // all conditions must hold
        let h = parse(
            br#"{"version":"1.0.0","hook":{"path":"/bin/true"},
            "when":{"always":true,"hasBindMounts":true},"stages":["poststart"]}"#,
        )
        .unwrap();
        assert!(h.when.matches(&none, None, true));
        assert!(!h.when.matches(&none, None, false));
        // commands
        let h = parse(
            br#"{"version":"1.0.0","hook":{"path":"/bin/true"},
            "when":{"commands":["sleep$"]},"stages":["poststart"]}"#,
        )
        .unwrap();
        assert!(h.when.matches(&none, Some("/usr/bin/sleep"), false));
        assert!(!h.when.matches(&none, Some("/bin/sh"), false));
        // no condition: never
        let h = parse(
            br#"{"version":"1.0.0","hook":{"path":"/bin/true"},"when":{},"stages":["poststart"]}"#,
        )
        .unwrap();
        assert!(!h.when.matches(&none, None, true));
    }

    #[test]
    fn version_0_files_match_any_condition() {
        let h = parse(
            br#"{"hook":"/bin/true","arguments":["x"],"stage":["prestart"],
            "cmds":["nomatch"],"hasbindmounts":true}"#,
        )
        .unwrap();
        assert_eq!(
            h.hook.args.as_deref(),
            Some(&["/bin/true".to_string(), "x".to_string()][..])
        );
        assert!(h.when.matches(&HashMap::new(), Some("/bin/sh"), true));
        assert!(!h.when.matches(&HashMap::new(), Some("/bin/sh"), false));
        assert!(parse(br#"{"hook":"/bin/true","stage":["a"],"stages":["b"]}"#).is_err());
    }

    #[test]
    fn bad_files_are_refused() {
        for bad in [
            &br#"{"version":"2.0.0"}"#[..],
            br#"{"version":"1.0.0","hook":{"path":""},"when":{"always":true},"stages":["prestart"]}"#,
            br#"{"version":"1.0.0","hook":{"path":"/bin/true"},"when":{"always":true}}"#,
            br#"{"version":"1.0.0","hook":{"path":"/bin/true"},"when":{"always":true},"stages":["later"]}"#,
            br#"{"version":"1.0.0","hook":{"path":"/bin/true"},"when":{"commands":["("]},"stages":["prestart"]}"#,
            br#"not json"#,
        ] {
            assert!(parse(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn hooks_go_to_their_stages_by_file_name() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (d.path().join("a"), d.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let file = |dir: &Path, name: &str, path: &str, stages: &str| {
            std::fs::write(
                dir.join(name),
                format!(r#"{{"version":"1.0.0","hook":{{"path":"{path}"}},"when":{{"always":true}},"stages":{stages}}}"#),
            )
            .unwrap();
        };
        file(&a, "20-b.json", "/bin/false", r#"["createContainer"]"#);
        file(
            &a,
            "10-a.json",
            "/bin/true",
            r#"["prestart","createContainer","startContainer","poststart","poststop"]"#,
        );
        file(
            &b,
            "20-b.json",
            "/bin/echo",
            r#"["createContainer","precreate"]"#,
        );
        std::fs::write(a.join("README"), "not a hook").unwrap();
        let hooks = load(&[a.clone(), b.clone(), d.path().join("missing")]).unwrap();
        assert_eq!(hooks.len(), 2);
        let mut s = spec();
        let pre = inject(&mut s, &hooks, false);
        assert_eq!(pre.len(), 1);
        assert_eq!(pre[0].path, "/bin/echo");
        assert_eq!(s["hooks"]["createRuntime"], json!([{"path": "/bin/true"}]));
        assert_eq!(
            s["hooks"]["createContainer"],
            json!([{"path": "/bin/true"}, {"path": "/bin/echo"}])
        );
        for st in ["startContainer", "poststart", "poststop"] {
            assert_eq!(s["hooks"][st], json!([{"path": "/bin/true"}]), "{st}");
        }
        // a hook whose program is not there
        file(&a, "30-c.json", "/nonexistent/hook", r#"["prestart"]"#);
        assert!(load(&[a]).is_err());
    }

    /// A precreate hook has the limit of open files the engine's user gave,
    /// not the raised one of the engine.
    #[test]
    fn a_precreate_hook_has_the_limit_of_open_files_of_the_user() {
        velarx_base::testing::in_child(|| {
            rustix::process::setrlimit(
                rustix::process::Resource::Nofile,
                rustix::process::Rlimit {
                    current: Some(256),
                    maximum: Some(4096),
                },
            )
            .unwrap();
            velarx_base::hardening::raise_open_files().unwrap();
            let d = tempfile::tempdir().unwrap();
            let h = HookCommand {
                path: "/bin/sh".into(),
                args: Some(vec![
                    "sh".into(),
                    "-c".into(),
                    "echo $(ulimit -Sn) $(ulimit -Hn) > limits; cat".into(),
                ]),
                env: None,
                timeout: Some(10),
            };
            let mut s = spec();
            run_precreate(std::slice::from_ref(&h), &mut s, d.path()).unwrap();
            assert_eq!(
                std::fs::read_to_string(d.path().join("limits")).unwrap(),
                "256 4096\n"
            );
        });
    }

    #[test]
    fn precreate_hooks_edit_the_configuration() {
        let d = tempfile::tempdir().unwrap();
        let h = HookCommand {
            path: "/bin/sh".into(),
            args: Some(vec![
                "sh".into(),
                "-c".into(),
                r#"sed 's/"other":"x"/"other":"edited"/'"#.into(),
            ]),
            env: None,
            timeout: Some(10),
        };
        let mut s = spec();
        run_precreate(std::slice::from_ref(&h), &mut s, d.path()).unwrap();
        assert_eq!(s["annotations"]["other"], "edited");
        let fail = HookCommand {
            args: Some(vec!["sh".into(), "-c".into(), "echo no >&2; exit 3".into()]),
            ..h.clone()
        };
        assert!(run_precreate(&[fail], &mut s, d.path())
            .unwrap_err()
            .contains("no"));
        let noisy = HookCommand {
            args: Some(vec![
                "sh".into(),
                "-c".into(),
                "head -c 300000 /dev/zero | tr '\\0' x >&2; exit 3".into(),
            ]),
            timeout: None,
            ..h.clone()
        };
        assert!(run_precreate(&[noisy], &mut s, d.path())
            .unwrap_err()
            .contains("xxxx"));
        let slow = HookCommand {
            args: Some(vec!["sh".into(), "-c".into(), "sleep 5".into()]),
            timeout: Some(1),
            ..h
        };
        assert!(run_precreate(&[slow], &mut s, d.path())
            .unwrap_err()
            .contains("timed out"));
    }
}
