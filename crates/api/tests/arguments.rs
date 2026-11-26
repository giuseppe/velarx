// SPDX-License-Identifier: Apache-2.0
//! The rule of the arguments of a call (`MAX_ARG_BYTES` in
//! `velarx-proto`): zlink writes a message in time that grows with the
//! square of its size, so no call carries more than a few kB of strings or
//! lists; what is larger is a descriptor.  The interface file says which
//! methods have arguments that can be large (a string, a list, a document);
//! each of them must be called by the frontend through the macros that check
//! the size of the arguments, or check it itself, or be on the list below
//! with the reason it needs no check.

use std::path::Path;

/// Methods with such arguments that need no check, and why.
const EXEMPT: &[(&str, &str)] = &[
    // the command line's: podman's REST API mounts no volume
    (
        "VolumeMount",
        "the command line, not this frontend, calls it",
    ),
    (
        "ContainerClone",
        "the command line, not this frontend, calls it",
    ),
    (
        "NetworkReload",
        "the command line, not this frontend, calls it",
    ),
    (
        "VolumeUnmount",
        "the command line, not this frontend, calls it",
    ),
    (
        "SystemStores",
        "the command line, not this frontend, calls it",
    ),
    (
        "ContainerStartAttached",
        "the command line, not this frontend, calls it",
    ),
    ("PodLogs", "the command line, not this frontend, calls it"),
    (
        "ImageCredentialScopes",
        "the command line, not this frontend, calls it",
    ),
    (
        "RegistryCredentialScopes",
        "the command line, not this frontend, calls it",
    ),
    (
        "ImagePulling",
        "the command line, not this frontend, calls it",
    ),
    (
        "ImageComplete",
        "the command line, not this frontend, calls it",
    ),
    (
        "RegistryDigest",
        "the command line, not this frontend, calls it",
    ),
    (
        "CheckpointUnshare",
        "the command line, not this frontend, calls it",
    ),
    // the spec is a pipe: the argument is its length
    ("PodCreate", "the data crosses as a descriptor"),
    // the CRI frontend's: a container ID of its own
    (
        "ContainerLogReopen",
        "the CRI frontend, not this one, calls it",
    ),
    (
        "ContainerInspect",
        "the CRI frontend, not this one, calls it",
    ),
    ("ImagePull", "the CRI frontend, not this one, calls it"),
    // the CRI frontend's verbose status: the runtime spec in a pipe
    (
        "ContainerRuntimeSpec",
        "the CRI frontend, not this one, calls it",
    ),
    ("NetworkCheck", "the CRI frontend, not this one, calls it"),
    (
        "ImageBuildAnswer",
        "the command line answers its build, not a frontend",
    ),
];

fn snake(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// The methods of the interface file and the types of their arguments.
fn methods(text: &str) -> Vec<(String, Vec<(String, String)>)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("method ") else {
            continue;
        };
        let (name, rest) = rest.split_once('(').expect("a method has arguments");
        let (args, _) = rest.split_once(") ->").expect("a method has a reply");
        let params = args
            .split(", ")
            .filter(|p| !p.is_empty())
            .map(|p| {
                let (n, t) = p.split_once(": ").expect("a typed argument");
                (n.to_string(), t.to_string())
            })
            .collect();
        out.push((name.to_string(), params));
    }
    out
}

/// The calls through the macros in `source` (white space removed): the macro
/// and the method it calls, written `m!(self.method(..)..)` or
/// `m!(engine, method(..)..)`.
fn macro_calls(source: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    for (at, _) in source.match_indices("call!(") {
        // (white space is gone: `matchengine_call!` is a `match` and the macro)
        let before = &source[..at];
        let name = [
            "raw_", "fds_", "list_", "replies_", "session_", "engine_", "",
        ]
        .into_iter()
        .find(|p| before.ends_with(p))
        .map(|p| &source[at - p.len()..at + "call".len()])
        .unwrap_or("call");
        let rest = &source[at + "call!(".len()..];
        // (the method follows `self.`, or the first comma of the arguments)
        let method = if let Some(m) = rest.strip_prefix("self.") {
            m
        } else {
            let mut depth = 0;
            let comma = rest.char_indices().find(|&(_, c)| {
                match c {
                    '(' | '[' | '{' => depth += 1,
                    ')' | ']' | '}' => depth -= 1,
                    _ => {}
                }
                c == ',' && depth == 0
            });
            match comma {
                Some((i, _)) => &rest[i + 1..],
                None => continue,
            }
        };
        let end = method.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'));
        if let Some(end) = end.filter(|&e| method[e..].starts_with('(')) {
            out.push((name, &method[..end]));
        }
    }
    out
}

/// The frontend calls the method `snake` and every call of it checks the
/// size of its arguments: through `call!`/`engine_call!`/`fds_call!`, or a
/// `raw_call!` or `session_call!` (or a call on a connection) next to a `check_args` of that
/// method.  A `raw_call!` alone, or a `conn.method(...)`, is not checked.
fn call_sites_are_checked(source: &str, snake: &str) -> bool {
    // (`replies_call!` is a call with more that lasts: the proxy method
    // of a method that has a call without more too ends in `_progress`)
    let progress = format!("{snake}_progress");
    let calls = macro_calls(source);
    let sites = calls.iter().any(|&(m, method)| {
        (method == snake && matches!(m, "call" | "engine_call" | "fds_call" | "list_call"))
            || (m == "replies_call" && (method == snake || method == progress))
    });
    // (a call made by hand names the method)
    let camel: String = snake
        .split('_')
        .map(|w| w[..1].to_ascii_uppercase() + &w[1..])
        .collect();
    let raw = calls
        .iter()
        .any(|&(m, method)| matches!(m, "raw_call" | "session_call") && method == snake)
        || source.contains(&format!("conn.{snake}("))
        || source.contains(&format!("\"org.velarx.Engine.{camel}\""));
    let check = source.contains(&format!("check_args(\"{snake}\""));
    (sites || raw) && (!raw || check)
}

fn can_be_large(ty: &str) -> bool {
    let ty = ty.trim_start_matches('?');
    !matches!(ty, "bool" | "int" | "float")
}

#[test]
fn every_method_with_a_large_argument_has_its_size_checked() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let interface =
        std::fs::read_to_string(root.join("../../interfaces/org.velarx.Engine.varlink")).unwrap();
    // (without white space: rustfmt may break a call over lines)
    // (the engine module, and the handlers that call through its macros:
    // every file of the sources)
    let mut files = Vec::new();
    let mut dirs = vec![root.join("src")];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    assert!(files.iter().any(|f| f.ends_with("src/engine.rs")));
    let source: String = files
        .iter()
        .flat_map(|f| {
            std::fs::read_to_string(f)
                .unwrap()
                .chars()
                .collect::<Vec<_>>()
        })
        .filter(|c| !c.is_whitespace())
        .collect();
    let methods = methods(&interface);
    assert!(methods.len() > 50, "{} methods", methods.len());
    let mut unchecked = Vec::new();
    let mut with_large = 0;
    for (name, params) in &methods {
        if !params.iter().any(|(_, t)| can_be_large(t)) {
            continue;
        }
        with_large += 1;
        if EXEMPT.iter().any(|(m, _)| m == name) {
            continue;
        }
        let snake = snake(name);
        if !call_sites_are_checked(&source, &snake) {
            unchecked.push(name.as_str());
        }
    }
    assert!(with_large > 30, "{with_large} methods with large arguments");
    assert!(
        unchecked.is_empty(),
        "the frontend calls these without checking the size of their arguments \
         (call!, fds_call! or check_args, or EXEMPT with a reason): {unchecked:?}"
    );
    // the exemptions are methods that exist
    for (m, _) in EXEMPT {
        assert!(methods.iter().any(|(n, _)| n == m), "{m} is not a method");
    }
}

/// The methods only the CRI frontend calls are checked there: the cap of
/// the arguments holds for every frontend of the engine.
#[test]
fn the_cri_frontend_checks_the_size_of_its_arguments() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let interface =
        std::fs::read_to_string(root.join("../../interfaces/org.velarx.Engine.varlink")).unwrap();
    // (the calls of the engine are in the files of its `engine` module)
    let mut source = String::new();
    for entry in std::fs::read_dir(root.join("../cri/src/engine")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "rs") {
            source.extend(
                std::fs::read_to_string(&path)
                    .unwrap()
                    .chars()
                    .filter(|c| !c.is_whitespace()),
            );
        }
    }
    let methods = methods(&interface);
    let mut unchecked = Vec::new();
    for (name, reason) in EXEMPT {
        if !reason.contains("CRI frontend") {
            continue;
        }
        let large = methods
            .iter()
            .find(|(n, _)| n == name)
            .is_some_and(|(_, params)| params.iter().any(|(_, t)| can_be_large(t)));
        // (the specs of the CRI cross in a pipe: their call has a length)
        if large && !call_sites_are_checked(&source, &snake(name)) {
            unchecked.push(*name);
        }
    }
    assert!(
        unchecked.is_empty(),
        "the CRI frontend calls these without checking the size of their arguments: \
         {unchecked:?}"
    );
}

#[test]
fn an_unchecked_call_site_is_found() {
    let checked = "call!(self.podman_volume_create(a))";
    assert!(call_sites_are_checked(checked, "podman_volume_create"));
    assert!(call_sites_are_checked(
        "fds_call!(self.podman_volume_list(a))",
        "podman_volume_list"
    ));
    // a raw call is checked only with its check_args
    let raw = "raw_call!(self.container_wait(a, b))";
    assert!(!call_sites_are_checked(raw, "container_wait"));
    assert!(call_sites_are_checked(
        &format!("check_args(\"container_wait\", &a)?; {raw}"),
        "container_wait"
    ));
    // a checked call does not cover a raw one of the same method elsewhere
    assert!(!call_sites_are_checked(
        &format!("{checked} conn.podman_volume_create(b)"),
        "podman_volume_create"
    ));
    // one called by hand by its name too
    let by_hand = "method: \"org.velarx.Engine.ContainerWait\"";
    assert!(!call_sites_are_checked(by_hand, "container_wait"));
    assert!(call_sites_are_checked(
        &format!("check_args(\"container_wait\", &a)?; {by_hand}"),
        "container_wait"
    ));
    // a list and a call with more that lasts check theirs
    assert!(call_sites_are_checked(
        "list_call!(self.pod_list(f), take, failed)",
        "pod_list"
    ));
    assert!(call_sites_are_checked(
        "replies_call!(self.image_pull_progress(a), &b)",
        "image_pull"
    ));
    // the handlers' form, with the engine as the first argument
    assert!(call_sites_are_checked(
        "engine_call!(call.engine,network_list(f))",
        "network_list"
    ));
    assert!(call_sites_are_checked(
        "engine_call!(engine,container_top(&name,args))",
        "container_top"
    ));
    let raw = "raw_call!(call.engine,container_mount_list())";
    assert!(!call_sites_are_checked(raw, "container_mount_list"));
    assert!(call_sites_are_checked(
        &format!("check_args(\"container_mount_list\",&a)?;{raw}"),
        "container_mount_list"
    ));
    // a method the frontend never calls is not checked
    assert!(!call_sites_are_checked("", "podman_volume_create"));
}

#[test]
fn the_names_of_the_methods_become_those_of_the_proxy() {
    assert_eq!(snake("PodmanContainerList"), "podman_container_list");
    assert_eq!(snake("Ping"), "ping");
}
