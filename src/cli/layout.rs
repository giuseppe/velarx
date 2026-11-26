// SPDX-License-Identifier: Apache-2.0

/// The global options of podman that take a value, and velarx's.
pub(super) const VALUE_OPTIONS: &[&str] = &[
    "--config",
    "--socket",
    "--log-level",
    "--log-format",
    "--module",
    "--out",
    "--events-backend",
    "--root",
    "--runroot",
    "--tmpdir",
    "--storage-driver",
    "--runtime",
    "--runtime-flag",
    "--cgroup-manager",
    "--hooks-dir",
    "--cdi-spec-dir",
    "--url",
];

/// The global options without a value that podman takes after the command
/// too.
const FLAG_OPTIONS: &[&str] = &["--remote", "--noout"];

/// podman's global options are its root command's persistent flags: they
/// may follow the command (`podman run --runtime R ...`).  `invalid` is the
/// argument clap did not take: when it is a global option, it (and its
/// value) moves before the command and the parse is tried again (true); a
/// global option podman has and velarx has not is refused as before it.
pub fn hoist_global_option(
    args: &mut Vec<std::ffi::OsString>,
    invalid: &str,
) -> Result<bool, String> {
    let name = invalid.split_once('=').map_or(invalid, |(n, _)| n);
    if let Some((_, why)) = REFUSED_OPTIONS.iter().find(|(o, _)| *o == name) {
        if name.starts_with("--") {
            return Err(format!(
                "podman's global option {name} is not supported by velarx: {why}"
            ));
        }
    }
    let takes_value = VALUE_OPTIONS.contains(&name);
    if !takes_value && !FLAG_OPTIONS.contains(&name) {
        return Ok(false);
    }
    // (the last occurrence before the operands of the command, which are
    // its own: the first ones were taken before the command)
    let glued = format!("{name}=");
    let options = args.iter().position(|a| a == "--").unwrap_or(args.len());
    let Some(at) = args[..options].iter().rposition(|a| {
        a.to_str()
            .is_some_and(|a| a == name || a.starts_with(&glued))
    }) else {
        return Ok(false);
    };
    let with_value = takes_value && args[at].to_str() == Some(name) && at + 1 < args.len();
    let moved: Vec<std::ffi::OsString> = args.drain(at..=at + usize::from(with_value)).collect();
    args.splice(1..1, moved);
    Ok(true)
}

/// podman's flags take a value when it is glued: `--all=true` and
/// `--all=false` (Go's `ParseBool`).  `invalid` is the flag clap found a value
/// for that it does not take: the first `--flag=VALUE` of the command line is
/// the flag alone for a true value, gone for a false one (true when the
/// command line changed and is to be parsed again).
pub fn plain_bool_flag(args: &mut Vec<std::ffi::OsString>, invalid: &str) -> bool {
    let name = invalid.split_whitespace().next().unwrap_or(invalid);
    if !name.starts_with("--") {
        return false;
    }
    let glued = format!("{name}=");
    let options = args.iter().position(|a| a == "--").unwrap_or(args.len());
    let found = args[..options].iter().position(|a| {
        a.to_str().is_some_and(|a| {
            a.strip_prefix(&glued).is_some_and(|v| {
                matches!(
                    v,
                    "1" | "t"
                        | "T"
                        | "TRUE"
                        | "true"
                        | "True"
                        | "0"
                        | "f"
                        | "F"
                        | "FALSE"
                        | "false"
                        | "False"
                )
            })
        })
    });
    let Some(at) = found else {
        return false;
    };
    let on = args[at].to_str().is_some_and(|a| {
        matches!(
            &a[glued.len()..],
            "1" | "t" | "T" | "TRUE" | "true" | "True"
        )
    });
    if on {
        args[at] = name.into();
    } else {
        args.remove(at);
    }
    true
}

/// podman's (cobra's) words for a command line that clap does not take: a
/// flag given no value, or one the command does not have, with the help to
/// see.  None for the other errors, which keep clap's words.  `typed` is the
/// command line as it was typed (`args` is the one clap read, with podman's
/// commands as velarx names them).
pub fn go_flag_error(
    e: &clap::Error,
    args: &[std::ffi::OsString],
    typed: &[std::ffi::OsString],
) -> Option<String> {
    use clap::error::{ContextKind, ErrorKind};
    let invalid = e.get(ContextKind::InvalidArg)?.to_string();
    let flag = invalid.split_whitespace().next()?;
    let words = match e.kind() {
        ErrorKind::InvalidValue
            if e.get(ContextKind::InvalidValue)
                .is_none_or(|v| v.to_string().is_empty()) =>
        {
            // (the flag as it was typed: a short one is named in its group)
            match args.last().and_then(|a| a.to_str()) {
                Some(a) if a.len() > 1 && a.starts_with('-') && !a.starts_with("--") => {
                    format!("flag needs an argument: '{}' in {a}", &a[a.len() - 1..])
                }
                _ => format!("flag needs an argument: {flag}"),
            }
        }
        ErrorKind::UnknownArgument if flag.starts_with("--") => {
            format!("unknown flag: {}", flag.split('=').next()?)
        }
        ErrorKind::UnknownArgument if flag.len() > 1 && flag.starts_with('-') => {
            format!("unknown shorthand flag: '{}' in {flag}", &flag[1..2])
        }
        _ => return None,
    };
    // the command: as velarx names it, or as it was typed when that is
    // another name of it (`ps` for `container list`)
    let words_of = |line: &[std::ffi::OsString]| -> Vec<String> {
        let mut out = Vec::new();
        let mut skip = false;
        for a in line.iter().skip(1).filter_map(|a| a.to_str()) {
            if std::mem::take(&mut skip) {
                continue;
            }
            if a.starts_with('-') {
                skip = out.is_empty() && VALUE_OPTIONS.contains(&a) && !a.contains('=');
                continue;
            }
            out.push(a.to_string());
        }
        out
    };
    let mut path = Vec::new();
    let mut command = <crate::cli::Cli as clap::CommandFactory>::command();
    for w in words_of(args) {
        match command.find_subcommand(&w) {
            Some(sub) => {
                path.push(w);
                command = sub.clone();
            }
            None => break,
        }
    }
    let typed_words = words_of(typed);
    let mut found = typed_words.iter();
    if !path.iter().all(|w| found.any(|t| t == w)) {
        let depth = path
            .len()
            .saturating_sub(args.len().saturating_sub(typed.len()));
        path = typed_words.into_iter().take(depth.max(1)).collect();
    }
    let program = std::path::Path::new(typed.first().or(args.first())?)
        .file_name()?
        .to_string_lossy()
        .to_string();
    Some(format!(
        "{words}\nSee '{program} {} --help'",
        path.join(" ")
    ))
}

/// podman's (cobra's) words for a command line with the wrong number of
/// operands (`requires at least 1 arg(s), only received 0`, `accepts 2
/// arg(s), received 1`, `accepts between 1 and 2 arg(s), received 3`), from
/// what clap found missing or in excess; and for a value of an option that
/// does not parse (`invalid argument "x" for "--pids-limit" flag:
/// strconv.ParseInt: parsing "x": invalid syntax`).  None for the other
/// errors.  Cobra says no more than the line for the operands.
pub fn go_operand_error(e: &clap::Error, args: &[std::ffi::OsString]) -> Option<String> {
    use clap::error::{ContextKind, ErrorKind};
    let mut command = <crate::cli::Cli as clap::CommandFactory>::command();
    let mut skip = false;
    let mut first = true;
    let mut path = vec!["velarx".to_string()];
    for a in args.iter().skip(1).filter_map(|a| a.to_str()) {
        if std::mem::take(&mut skip) {
            continue;
        }
        if a.starts_with('-') {
            skip = first && VALUE_OPTIONS.contains(&a) && !a.contains('=');
            continue;
        }
        match command.find_subcommand(a) {
            Some(sub) => {
                command = sub.clone();
                // (the word typed: podman names its commands as velarx's aliases)
                path.push(a.to_string());
                first = false;
            }
            None => break,
        }
    }
    let positionals: Vec<&clap::Arg> = command.get_positionals().collect();
    let required = positionals.iter().filter(|a| a.is_required_set()).count();
    let unbounded = positionals
        .iter()
        .any(|a| a.get_num_args().is_some_and(|n| n.max_values() > 1));
    let phrase = |received: usize| -> String {
        let max = positionals.len();
        if unbounded {
            format!("requires at least {required} arg(s), only received {received}")
        } else if required == 0 {
            format!("accepts at most {max} arg(s), received {received}")
        } else if required == max {
            format!("accepts {required} arg(s), received {received}")
        } else {
            format!("accepts between {required} and {max} arg(s), received {received}")
        }
    };
    match e.kind() {
        ErrorKind::MissingRequiredArgument => {
            let missing = match e.get(ContextKind::InvalidArg) {
                Some(clap::error::ContextValue::Strings(v)) => v.clone(),
                Some(v) => vec![v.to_string()],
                None => return None,
            };
            let operands = missing.iter().filter(|m| m.starts_with('<')).count();
            // (an option that is required is clap's wording to keep)
            if operands == 0 || operands != missing.len() {
                return None;
            }
            Some(phrase(required.saturating_sub(operands)))
        }
        ErrorKind::UnknownArgument | ErrorKind::TooManyValues => {
            let extra = e.get(ContextKind::InvalidArg)?.to_string();
            if extra.starts_with('-') || unbounded {
                return None;
            }
            // (podman's validate.NoArgs)
            if positionals.is_empty() {
                return (path.len() > 1)
                    .then(|| format!("`{}` takes no arguments", path.join(" ")));
            }
            Some(phrase(positionals.len() + 1))
        }
        ErrorKind::ValueValidation | ErrorKind::InvalidValue => {
            let arg = e.get(ContextKind::InvalidArg)?.to_string();
            let value = e.get(ContextKind::InvalidValue)?.to_string();
            let flag = arg.split_whitespace().next()?;
            // (the words of the parse of a number; another check of the
            // value has its own words)
            let cause = std::error::Error::source(e)
                .map(|s| s.to_string())
                .unwrap_or_default();
            // (a boolean: clap lists true and false)
            let boolean = matches!(
                e.get(ContextKind::ValidValue),
                Some(clap::error::ContextValue::Strings(v)) if v == &["true", "false"]
            );
            if e.kind() == ErrorKind::InvalidValue && boolean {
                return Some(format!(
                    "invalid argument {value:?} for {flag:?} flag: strconv.ParseBool: parsing {value:?}: invalid syntax"
                ));
            }
            if e.kind() != ErrorKind::ValueValidation {
                return None;
            }
            let go = match cause.as_str() {
                "invalid digit found in string" | "cannot parse integer from empty string" => {
                    format!("strconv.ParseInt: parsing {value:?}: invalid syntax")
                }
                "invalid float literal" => {
                    format!("strconv.ParseFloat: parsing {value:?}: invalid syntax")
                }
                // (a negative number for an unsigned option: pflag's uint)
                _ if cause.contains(" is not in ") && value.starts_with('-') => {
                    format!("strconv.ParseUint: parsing {value:?}: invalid syntax")
                }
                // (a check of velarx's own: its words, as the command's
                // own error of podman's)
                _ if !cause.is_empty() && !cause.contains(" is not in ") => return Some(cause),
                _ => return None,
            };
            Some(format!(
                "invalid argument {value:?} for {flag:?} flag: {go}"
            ))
        }
        _ => None,
    }
}

/// podman's global options that velarx does not have: refused with what
/// to do instead, rather than ignored (a unit's `GlobalArgs=`).
pub(super) const REFUSED_OPTIONS: &[(&str, &str)] = &[
    (
        "--storage-opt",
        "velarx has a store of its own, with no drivers",
    ),
    ("--imagestore", "velarx has a store of its own"),
    ("--conmon", "the monitor is velarx-monitor, next to velarx"),
    (
        "--network-config-dir",
        "the networks are in the state directory of the configuration file",
    ),
    ("--network-cmd-path", "velarx runs pasta from PATH"),
    (
        "--volumepath",
        "the volumes are in the root directory of the configuration file",
    ),
    (
        "--identity",
        "velarx has no ssh connections: use --socket or VELARX_HOST=unix://",
    ),
    (
        "--connection",
        "velarx has no named connections: use --socket",
    ),
    ("-c", "velarx has no named connections: use --socket"),
    (
        "--syslog",
        "velarx logs to its standard error, the journal of a unit",
    ),
    ("--transient-store", "velarx has no transient store"),
    (
        "--ssh",
        "velarx has no ssh connections: use --socket or VELARX_HOST=unix://",
    ),
    (
        "--tls-ca",
        "velarx's remote engine is a unix socket, with no TLS: use --socket",
    ),
    (
        "--tls-cert",
        "velarx's remote engine is a unix socket, with no TLS: use --socket",
    ),
    (
        "--tls-key",
        "velarx's remote engine is a unix socket, with no TLS: use --socket",
    ),
];

/// podman's top-level verbs, as velarx's command layout has them:
/// podman's own Quadlet generator, scripts and habits use them.
pub(super) const PODMAN_VERBS: &[(&str, &[&str])] = &[
    ("attach", &["container", "attach"]),
    ("commit", &["image", "commit"]),
    ("cp", &["container", "cp"]),
    ("create", &["container", "create"]),
    ("diff", &["container", "diff"]),
    ("exec", &["container", "exec"]),
    ("inspect", &["system", "inspect"]),
    ("kill", &["container", "kill"]),
    ("logs", &["container", "logs"]),
    ("pause", &["container", "pause"]),
    ("ps", &["container", "list"]),
    ("rename", &["container", "rename"]),
    ("restart", &["container", "restart"]),
    ("rm", &["container", "rm"]),
    ("run", &["container", "run"]),
    ("start", &["container", "start"]),
    ("stop", &["container", "stop"]),
    ("top", &["container", "top"]),
    ("unpause", &["container", "unpause"]),
    ("wait", &["container", "wait"]),
    ("init", &["container", "init"]),
    ("port", &["container", "port"]),
    ("history", &["image", "history"]),
    ("export", &["container", "export"]),
    ("mount", &["container", "mount"]),
    ("unmount", &["container", "unmount"]),
    ("umount", &["container", "unmount"]),
    ("update", &["container", "update"]),
    ("build", &["image", "build"]),
    ("images", &["image", "list"]),
    ("import", &["image", "import"]),
    ("load", &["image", "load"]),
    ("pull", &["image", "pull"]),
    ("push", &["image", "push"]),
    ("rmi", &["image", "remove"]),
    ("save", &["image", "save"]),
    ("search", &["image", "search"]),
    ("tag", &["image", "tag"]),
    ("untag", &["image", "untag"]),
    ("login", &["registry", "login"]),
    ("logout", &["registry", "logout"]),
];

/// A time to stop (`-t`), as podman takes it: a negative one waits for
/// ever.
pub(super) fn parse_time_u64(s: &str) -> Result<u64, String> {
    match s.parse::<i64>() {
        Ok(t) if t < 0 => Ok(u64::MAX),
        Ok(t) => Ok(t as u64),
        Err(e) => Err(format!("invalid time `{s}`: {e}")),
    }
}

/// [`parse_time_u64`], for the times that are u32.
pub(super) fn parse_time_u32(s: &str) -> Result<u32, String> {
    parse_time_u64(s).map(|t| u32::try_from(t).unwrap_or(u32::MAX))
}

/// The commands whose arguments after their first operand (the image of
/// `run`, the container of `exec`) are the command of the container, as
/// podman takes them: `run IMG -c x` runs `-c x`.
pub(super) const COMMAND_AFTER_OPERAND: &[&str] = &["run", "create", "exec"];

/// `args` with a `--` after the first operand of `container run`,
/// `container create` and `container exec`, so that what follows is the
/// command of the container even where it looks like an option of
/// velarx (`-c`, `-t`...).  The options before the operand are skipped by
/// what clap knows of them: those that take a value take the next
/// argument unless they are given `=VALUE` (or, short, glued).
pub fn end_options_after_operand(
    cmd: &clap::Command,
    mut args: Vec<std::ffi::OsString>,
) -> Vec<std::ffi::OsString> {
    let strs: Vec<Option<&str>> = args.iter().map(|a| a.to_str()).collect();
    // `container SUB`, after the global options
    let mut i = 1;
    while let Some(Some(a)) = strs.get(i) {
        if !a.starts_with('-') {
            break;
        }
        let name = a.split_once('=').map_or(*a, |(n, _)| n);
        if VALUE_OPTIONS.contains(&name) && !a.contains('=') {
            i += 1;
        }
        i += 1;
    }
    if strs.get(i) != Some(&Some("container")) {
        return args;
    }
    let Some(Some(sub)) = strs.get(i + 1).copied() else {
        return args;
    };
    if !COMMAND_AFTER_OPERAND.contains(&sub) {
        return args;
    }
    let Some(sub_cmd) = cmd
        .find_subcommand("container")
        .and_then(|c| c.find_subcommand(sub))
    else {
        return args;
    };
    // whether an option takes the next argument as its value
    let takes_next = |a: &clap::Arg| {
        a.get_action().takes_values()
            && !a.is_require_equals_set()
            && a.get_num_args().is_none_or(|n| n.min_values() > 0)
    };
    let mut j = i + 2;
    while let Some(Some(a)) = strs.get(j) {
        if *a == "--" {
            return args;
        }
        if let Some(long) = a.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((n, _)) => (n, true),
                None => (long, false),
            };
            let arg = sub_cmd.get_arguments().find(|x| {
                x.get_long() == Some(name)
                    || x.get_all_aliases().is_some_and(|al| al.contains(&name))
            });
            // (a global option of podman's may be there too)
            let global = arg.is_none() && VALUE_OPTIONS.contains(&a.split('=').next().unwrap_or(a));
            if !inline && (arg.is_some_and(takes_next) || global) {
                j += 1;
            }
        } else if let Some(shorts) = a.strip_prefix('-').filter(|s| !s.is_empty()) {
            for (k, c) in shorts.char_indices() {
                let arg = sub_cmd.get_arguments().find(|x| x.get_short() == Some(c));
                if arg.is_some_and(|x| x.get_action().takes_values()) {
                    // the rest of the cluster is its value, else the next
                    if k + c.len_utf8() == shorts.len() && arg.is_some_and(takes_next) {
                        j += 1;
                    }
                    break;
                }
            }
        } else {
            // the operand: what follows is the container's (a `--` given
            // there already ends the options)
            if j + 1 < args.len() && strs.get(j + 1) != Some(&Some("--")) {
                args.insert(j + 1, std::ffi::OsString::from("--"));
            }
            return args;
        }
        j += 1;
    }
    args
}

/// podman's commands of two words that are velarx's under another name.
pub(super) const PODMAN_PATHS: &[(&str, &str, &[&str])] = &[
    ("system", "events", &["events"]),
    ("container", "commit", &["image", "commit"]),
    ("buildx", "build", &["image", "build"]),
    ("buildx", "prune", &["image", "prune"]),
    ("builder", "build", &["image", "build"]),
    ("builder", "prune", &["image", "prune"]),
];

/// podman's commands that do not apply to velarx: refused with why, and
/// exit 125 (`""`: all the subcommands).
pub(super) const REFUSED_COMMANDS: &[(&str, &str, &str)] = &[
    (
        "machine",
        "",
        "velarx runs containers on this host only, with no virtual machine",
    ),
    ("farm", "", "velarx builds on this host only"),
    (
        "compose",
        "",
        "run docker-compose or podman-compose against the socket of `velarx-api` (DOCKER_HOST=unix://PATH)",
    ),
    (
        "generate",
        "systemd",
        "deprecated in podman; write Quadlet units (`velarx quadlet --help`)",
    ),
    ("generate", "spec", "velarx has no specgen files"),
    (
        "image",
        "mount",
        "the files of an image are mounted for its containers only, by their storage driver (composefs): \
         `velarx create` and `velarx mount` a running container, or `velarx save` the image",
    ),
    (
        "image",
        "unmount",
        "velarx mounts no image (`image mount` is not supported)",
    ),
    (
        "image",
        "umount",
        "velarx mounts no image (`image mount` is not supported)",
    ),
    (
        "image",
        "scp",
        "copy images between hosts with `velarx save` and `velarx load`",
    ),
    (
        "system",
        "connection",
        "velarx talks to the local engine service only (--url, VELARX_HOST)",
    ),
    (
        "container",
        "runlabel",
        "the label of an image is content to run on the host: run the command of an image you trust yourself",
    ),
    (
        "container",
        "cleanup",
        "podman's internal command; velarx's monitors clean up after the containers",
    ),
    (
        "system",
        "migrate",
        "velarx does not tie its containers to a runtime version: nothing to convert",
    ),
    ("system", "renumber", "velarx has no lock numbers"),
    (
        "system",
        "reset",
        "remove the store by hand, after `velarx system prune --all --volumes`",
    ),
    (
        "quadlet",
        "install",
        "podman's Quadlet tooling; velarx runs podman's Quadlet units: `velarx quadlet enable`",
    ),
    (
        "quadlet",
        "list",
        "podman's Quadlet tooling; velarx runs podman's Quadlet units: `velarx quadlet enable`",
    ),
    (
        "quadlet",
        "print",
        "podman's Quadlet tooling; velarx runs podman's Quadlet units: `velarx quadlet enable`",
    ),
    (
        "quadlet",
        "rm",
        "podman's Quadlet tooling; velarx runs podman's Quadlet units: `velarx quadlet enable`",
    ),
];

/// The command line with podman's layout turned into velarx's: its
/// top-level verbs (`run`, `rm`, `pull`...) become `container run`...;
/// its global options that velarx has not are refused.
pub fn podman_layout(mut args: Vec<std::ffi::OsString>) -> Result<Vec<std::ffi::OsString>, String> {
    // a remote client has none of the options of the engine
    let remote = {
        let mut remote = false;
        let mut j = 1;
        while let Some(a) = args.get(j).and_then(|a| a.to_str()) {
            if !a.starts_with('-') {
                break;
            }
            let name = a.split_once('=').map_or(a, |(n, _)| n);
            remote |= matches!(name, "--remote" | "-r" | "--url");
            if VALUE_OPTIONS.contains(&name) && !a.contains('=') {
                j += 1;
            }
            j += 1;
        }
        remote
    };
    let mut i = 1;
    while i < args.len() {
        let Some(arg) = args[i].to_str() else {
            return Ok(args);
        };
        if !arg.starts_with('-') {
            let next = args.get(i + 1).and_then(|a| a.to_str()).unwrap_or_default();
            if let Some((_, _, why)) = REFUSED_COMMANDS
                .iter()
                .find(|(c, sub, _)| *c == arg && (sub.is_empty() || *sub == next))
            {
                let name = if REFUSED_COMMANDS
                    .iter()
                    .any(|(c, sub, _)| *c == arg && sub.is_empty())
                {
                    arg.to_string()
                } else {
                    format!("{arg} {next}")
                };
                return Err(format!(
                    "podman's command `{name}` is not supported by velarx: {why}"
                ));
            }
            if let Some((_, _, to)) = PODMAN_PATHS
                .iter()
                .find(|(c, sub, _)| *c == arg && *sub == next)
            {
                args.splice(i..=i + 1, to.iter().map(std::ffi::OsString::from));
            } else if let Some((_, to)) = PODMAN_VERBS.iter().find(|(verb, _)| *verb == arg) {
                args.splice(i..=i, to.iter().map(std::ffi::OsString::from));
            }
            return Ok(args);
        }
        if arg == "--" {
            return Ok(args);
        }
        let name = arg.split_once('=').map_or(arg, |(n, _)| n);
        if let Some((_, why)) = REFUSED_OPTIONS.iter().find(|(o, _)| *o == name) {
            // (podman's remote client has --storage-opt too, and the
            // options of its connections)
            if remote && !matches!(name, "--identity" | "--connection" | "-c" | "--storage-opt") {
                return Err(format!("unknown flag: {name}"));
            }
            return Err(format!(
                "podman's global option {name} is not supported by velarx: {why}"
            ));
        }
        if VALUE_OPTIONS.contains(&name) && !arg.contains('=') {
            i += 1;
        }
        i += 1;
    }
    Ok(args)
}

#[cfg(test)]
mod podman_layout_tests {
    use super::*;
    use crate::cli::*;

    fn layout(args: &[&str]) -> Result<Vec<String>, String> {
        podman_layout(args.iter().map(std::ffi::OsString::from).collect())
            .map(|v| v.into_iter().map(|a| a.into_string().unwrap()).collect())
    }

    #[test]
    fn global_options_after_the_command_move_before_it() {
        let hoist = |args: &[&str], invalid: &str| {
            let mut v: Vec<std::ffi::OsString> = args.iter().map(Into::into).collect();
            let moved = hoist_global_option(&mut v, invalid);
            let v: Vec<String> = v.into_iter().map(|a| a.into_string().unwrap()).collect();
            (moved, v.join(" "))
        };
        assert_eq!(
            hoist(
                &["velarx", "container", "run", "--runtime", "/r", "i"],
                "--runtime"
            ),
            (Ok(true), "velarx --runtime /r container run i".into())
        );
        assert_eq!(
            hoist(
                &["velarx", "container", "run", "--hooks-dir=/h", "i"],
                "--hooks-dir"
            ),
            (Ok(true), "velarx --hooks-dir=/h container run i".into())
        );
        assert_eq!(
            hoist(&["velarx", "container", "ps", "--remote"], "--remote"),
            (Ok(true), "velarx --remote container ps".into())
        );
        // (the command of the container has one too: not that one)
        assert_eq!(
            hoist(
                &[
                    "velarx",
                    "container",
                    "run",
                    "--runtime",
                    "/r",
                    "i",
                    "--",
                    "echo",
                    "--runtime"
                ],
                "--runtime"
            ),
            (
                Ok(true),
                "velarx --runtime /r container run i -- echo --runtime".into()
            )
        );
        // (not a global option: clap's error stays)
        assert_eq!(
            hoist(&["velarx", "container", "run", "--bogus", "i"], "--bogus"),
            (Ok(false), "velarx container run --bogus i".into())
        );
        let (refused, _) = hoist(&["velarx", "container", "run", "--syslog", "i"], "--syslog");
        assert!(refused.unwrap_err().contains("--syslog is not supported"));
        // (its value is no operand of run; the command of clap needs the
        // stack of a main thread)
        let ended = std::thread::Builder::new()
            .stack_size(8 << 20)
            .spawn(|| {
                let argv = [
                    "velarx",
                    "container",
                    "run",
                    "--runtime",
                    "/r",
                    "--rm",
                    "i",
                    "x",
                ];
                end_options_after_operand(&Cli::command(), argv.iter().map(Into::into).collect())
            })
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(ended[7], "--");
        // and through the parse
        let cli = parse_for_test(["velarx", "--runtime", "/r", "container", "ps"]).unwrap();
        assert_eq!(cli.global.runtime.as_deref(), Some("/r"));
        let Err(e) = parse_for_test(["velarx", "container", "ps", "--runtime", "/r"]) else {
            panic!("a global option after the command is clap's error")
        };
        assert_eq!(e.kind(), clap::error::ErrorKind::UnknownArgument);
        let invalid = e
            .get(clap::error::ContextKind::InvalidArg)
            .unwrap()
            .to_string();
        assert_eq!(
            hoist(&["velarx", "container", "ps", "--runtime", "/r"], &invalid).0,
            Ok(true)
        );
    }

    #[test]
    fn negative_times_wait_for_ever() {
        assert_eq!(parse_time_u32("-1"), Ok(u32::MAX));
        assert_eq!(parse_time_u32("10"), Ok(10));
        assert_eq!(parse_time_u64("-5"), Ok(u64::MAX));
        assert!(parse_time_u64("x").is_err());
        let cli = parse_for_test(["velarx", "container", "rm", "-t", "-1", "-f", "c"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Container(ContainerCommands::Rm {
                time: Some(u64::MAX),
                ..
            })
        ));
    }

    #[test]
    fn latest_stands_for_the_container_and_leaves_the_arguments() {
        let parse = |args: &[&str]| {
            let argv = ["velarx", "container"].iter().chain(args);
            parse_for_test(argv).unwrap().command
        };
        let Commands::Container(ContainerCommands::Exec {
            latest: true,
            container,
            command,
            ..
        }) = parse(&["exec", "-l", "ls", "-la", "/"])
        else {
            panic!("not an exec")
        };
        assert_eq!(
            (container.as_str(), command),
            ("ls", ["-la", "/"].map(String::from).to_vec())
        );
        let Commands::Container(ContainerCommands::Top {
            latest: true,
            container,
            ps_args,
        }) = parse(&["top", "-l", "-eo", "pid,comm"])
        else {
            panic!("not a top")
        };
        assert_eq!(
            (container, ps_args),
            (Some("-eo".into()), vec!["pid,comm".to_string()])
        );
        for args in [
            &["logs", "-l"][..],
            &["inspect", "-l"],
            &["start", "-l"],
            &["diff", "-l"],
            &["attach", "-l"],
            &["port", "-l"],
        ] {
            parse(args);
        }
    }

    #[test]
    fn podman_paths_and_refused_commands() {
        assert_eq!(
            layout(&["velarx", "container", "commit", "c"]).unwrap(),
            ["velarx", "image", "commit", "c"]
        );
        assert_eq!(
            layout(&["velarx", "system", "events", "--stream=false"]).unwrap(),
            ["velarx", "events", "--stream=false"]
        );
        assert_eq!(
            layout(&["velarx", "history", "i"]).unwrap(),
            ["velarx", "image", "history", "i"]
        );
        let e = layout(&["velarx", "machine", "init"]).unwrap_err();
        assert!(e.contains("`machine` is not supported"), "{e}");
        let e = layout(&["velarx", "generate", "systemd", "c"]).unwrap_err();
        assert!(e.contains("`generate systemd` is not supported"), "{e}");
        assert!(layout(&["velarx", "quadlet", "list"]).is_err());
        // velarx's own quadlet commands are not podman's
        assert!(layout(&["velarx", "quadlet", "enable"]).is_ok());
        // (no command of velarx: clap's own unknown subcommand error)
        assert!(layout(&["velarx", "system", "service"]).is_ok());
        assert!(layout(&["velarx", "varlink"]).is_ok());
        let e = layout(&["velarx", "container", "runlabel", "run", "img"]).unwrap_err();
        assert!(e.contains("`container runlabel` is not supported"), "{e}");
    }

    #[test]
    fn buildx_and_builder_are_build_and_prune() {
        for group in ["buildx", "builder"] {
            assert_eq!(
                layout(&["velarx", group, "build", "-t", "x", "."]).unwrap(),
                ["velarx", "image", "build", "-t", "x", "."]
            );
            assert_eq!(
                layout(&["velarx", group, "prune", "-f"]).unwrap(),
                ["velarx", "image", "prune", "-f"]
            );
        }
    }

    #[test]
    fn podman_verbs_become_velarx_commands() {
        assert_eq!(
            layout(&["velarx", "run", "--rm", "-d", "img"]).unwrap(),
            ["velarx", "container", "run", "--rm", "-d", "img"]
        );
        assert_eq!(
            layout(&[
                "velarx",
                "--log-level",
                "debug",
                "--module=m.conf",
                "rm",
                "-v",
                "-f",
                "-i",
                "c"
            ])
            .unwrap(),
            [
                "velarx",
                "--log-level",
                "debug",
                "--module=m.conf",
                "container",
                "rm",
                "-v",
                "-f",
                "-i",
                "c"
            ]
        );
        assert_eq!(
            layout(&["velarx", "images"]).unwrap(),
            ["velarx", "image", "list"]
        );
        assert_eq!(
            layout(&["velarx", "rmi", "x"]).unwrap(),
            ["velarx", "image", "remove", "x"]
        );
        // the native layout is unchanged, and so are the verbs after it
        assert_eq!(
            layout(&["velarx", "container", "run", "img", "rm"]).unwrap(),
            ["velarx", "container", "run", "img", "rm"]
        );
        assert_eq!(
            layout(&["velarx", "--version"]).unwrap(),
            ["velarx", "--version"]
        );
        // every mapping names a command of velarx
        for (verb, _) in PODMAN_VERBS {
            let args = layout(&["velarx", verb, "--help"]).unwrap();
            let err = parse_for_test(args).err().unwrap();
            assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp, "{verb}");
        }
    }

    #[test]
    fn podman_global_options_velarx_has_not_are_refused() {
        let err = layout(&["velarx", "--storage-opt", "x", "run", "img"]).unwrap_err();
        assert!(err.contains("--storage-opt is not supported"), "{err}");
        // a remote client has none of the options of podman's engine
        for args in [
            &["velarx", "--remote", "--conmon", "/x", "ps"][..],
            &["velarx", "--imagestore=/x", "-r", "ps"],
            &["velarx", "--url", "unix:///s", "--volumepath", "/x", "ps"],
        ] {
            let err = layout(args).unwrap_err();
            assert!(err.starts_with("unknown flag: --"), "{args:?}: {err}");
        }
        // but --storage-opt (podman-remote takes it) and the connections'
        for args in [
            &["velarx", "--remote", "--storage-opt", "x", "ps"][..],
            &["velarx", "--remote", "--connection", "c", "ps"],
        ] {
            let err = layout(args).unwrap_err();
            assert!(
                err.contains("is not supported by velarx"),
                "{args:?}: {err}"
            );
        }
        let err = layout(&["velarx", "--connection=c", "ps"]).unwrap_err();
        assert!(err.contains("--connection"), "{err}");
        // the ones it has are not
        assert!(layout(&["velarx", "--root", "/x", "--runtime=crun", "run", "img"]).is_ok());
        let cli = parse_for_test([
            "velarx",
            "--root",
            "/x",
            "-r",
            "--hooks-dir",
            "/h",
            "image",
            "list",
        ])
        .unwrap();
        assert_eq!(cli.global.root, Some(PathBuf::from("/x")));
        assert!(cli.global.remote);
        assert_eq!(cli.global.hooks_dir, [PathBuf::from("/h")]);
        // after the command they are its arguments
        assert!(layout(&["velarx", "container", "run", "--root", "img"]).is_ok());
        // the settings of the engine: an engine of the command's own
        let cli = parse_for_test(["velarx", "--runtime-flag", "debug", "image", "list"]).unwrap();
        assert_eq!(
            super::super::engine_setting(&cli.global),
            Some("--runtime-flag")
        );
        let cli = parse_for_test(["velarx", "--root", "/x", "image", "list"]).unwrap();
        assert_eq!(super::super::engine_setting(&cli.global), None);
    }

    #[test]
    fn the_signature_policy_is_an_option_of_some_commands() {
        let takes = |args: &[&str]| {
            let cli = parse_for_test(args.iter().copied()).unwrap();
            assert_eq!(cli.global.signature_policy, Some(PathBuf::from("/p")));
            super::super::takes_signature_policy(&cli.command)
        };
        let commands: [&[&str]; 5] = [
            &["velarx", "image", "pull", "--signature-policy", "/p", "img"],
            &["velarx", "image", "push", "--signature-policy", "/p", "img"],
            &[
                "velarx",
                "image",
                "load",
                "--signature-policy",
                "/p",
                "-i",
                "f",
            ],
            &[
                "velarx",
                "container",
                "run",
                "--signature-policy",
                "/p",
                "img",
            ],
            &[
                "velarx",
                "container",
                "create",
                "--signature-policy",
                "/p",
                "img",
            ],
        ];
        for command in commands {
            assert!(takes(command), "{command:?}");
        }
        assert!(!takes(&[
            "velarx",
            "image",
            "list",
            "--signature-policy",
            "/p"
        ]));
        assert!(!takes(&[
            "velarx",
            "container",
            "start",
            "--signature-policy",
            "/p",
            "c"
        ]));
    }
}

/// The platform of `--platform`, or of `--os`, `--arch` and `--variant`
/// (podman's), which default to linux and the architecture of this host.
/// As podman's `pull` and `run`: `--platform` with `--os` or `--arch` is an
/// error, a `--variant` is added to a platform that has none.
/// The architecture of the host as Go names it.
pub fn host_go_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        "powerpc64" => "ppc64le",
        a => a,
    }
}

/// What `push` to a registry says of an image with sha512 digests (its
/// manifest, or the layers of its base): a registry that does not take them
/// refuses it, and nothing is converted to sha256.  Nothing is said of a
/// sha256 image, or of a push to a directory or an archive.
pub const SHA512_PUSH_WARNING: &str = "Warning: the image has sha512 digests: a registry that does not support sha512 refuses it (velarx never pushes it with other digests)";

/// The name `REPOSITORY@DIGEST` of what was pushed to TARGET (`REPO:TAG`, or
/// `REPO`), when it was pushed by a tag; none for a target that names a digest.
pub fn pushed_by_digest_name(target: &str, digest: &str) -> Option<String> {
    if target.contains('@') {
        return None;
    }
    let slash = target.rfind('/').map_or(0, |i| i + 1);
    let repo = match target[slash..].rfind(':') {
        Some(i) => &target[..slash + i],
        None => target,
    };
    Some(format!("{repo}@{digest}"))
}

/// What `push` says of each name the destination refused: the tag is
/// pushed, a name by the digest of a sha512 manifest may not resolve there.
/// `by_digest` is the name by the digest of the manifest, for the refusal
/// of the digest itself.
pub fn refusal_warnings(placed: &[velarx_proto::transfer::Placed], by_digest: &str) -> Vec<String> {
    placed
        .iter()
        .filter(|p| !p.accepted)
        .map(|p| {
            format!(
                "Warning: the destination refused {}: {}",
                p.name.as_deref().unwrap_or(by_digest),
                p.reason.as_deref().unwrap_or("no reason given")
            )
        })
        .collect()
}

/// `--digest` of a command that makes images: `sha256` or `sha512`, any
/// other word refused by name (the engine checks it too).
pub fn check_digest_flag(digest: Option<&str>) -> Result<(), String> {
    match digest {
        Some(d) => velarx_types::digest::Algorithm::for_creation(d)
            .map(|_| ())
            .map_err(|e| format!("--digest: {e}")),
        None => Ok(()),
    }
}

pub fn platform_of(
    platform: Option<String>,
    os: Option<String>,
    arch: Option<String>,
    variant: Option<String>,
) -> Result<Option<String>, String> {
    if let Some(p) = platform {
        if os.is_some() || arch.is_some() {
            return Err("--platform option can not be specified with --arch or --os".into());
        }
        return Ok(Some(match variant {
            Some(v) if p.split('/').count() == 2 => format!("{p}/{v}"),
            _ => p,
        }));
    }
    if os.is_none() && arch.is_none() && variant.is_none() {
        return Ok(None);
    }
    let host = host_go_arch();
    let mut p = format!(
        "{}/{}",
        os.as_deref().unwrap_or("linux"),
        arch.as_deref().unwrap_or(host)
    );
    if let Some(v) = variant {
        p.push('/');
        p.push_str(&v);
    }
    Ok(Some(p))
}

#[cfg(test)]
mod platform_tests {
    use super::*;

    #[test]
    fn a_flag_error_has_podmans_words() {
        let words = |v: &[&str], typed: &[&str]| {
            let args = podman_layout(v.iter().map(Into::into).collect()).unwrap();
            let typed: Vec<std::ffi::OsString> = typed.iter().map(Into::into).collect();
            let Err(e) = crate::cli::parse_for_test(args.clone()) else {
                panic!("{v:?} parses")
            };
            // (the command line of every command is built: a main thread's stack)
            std::thread::Builder::new()
                .stack_size(8 << 20)
                .spawn(move || go_flag_error(&e, &args, &typed))
                .unwrap()
                .join()
                .unwrap()
        };
        let run_h = ["velarx", "run", "-h"];
        assert_eq!(
            words(&run_h, &run_h).as_deref(),
            Some("flag needs an argument: 'h' in -h\nSee 'velarx run --help'")
        );
        let run_hostname = ["velarx", "run", "--hostname"];
        assert_eq!(
            words(&run_hostname, &run_hostname).as_deref(),
            Some("flag needs an argument: --hostname\nSee 'velarx run --help'")
        );
        assert_eq!(
            words(
                &["velarx", "container", "list", "--invalid"],
                &["velarx", "ps", "--invalid"]
            )
            .as_deref(),
            Some("unknown flag: --invalid\nSee 'velarx ps --help'")
        );
        let pod_ps = ["velarx", "pod", "ps", "--invalid=1"];
        assert_eq!(
            words(&pod_ps, &pod_ps).as_deref(),
            Some("unknown flag: --invalid\nSee 'velarx pod ps --help'")
        );
    }

    #[test]
    fn a_flag_takes_a_glued_boolean() {
        let args = |v: &[&str]| {
            v.iter()
                .map(Into::into)
                .collect::<Vec<std::ffi::OsString>>()
        };
        let mut a = args(&["velarx", "ps", "--all=true", "-q"]);
        assert!(plain_bool_flag(&mut a, "--all"));
        assert_eq!(a, args(&["velarx", "ps", "--all", "-q"]));
        let mut a = args(&["velarx", "ps", "--all=F", "-q"]);
        assert!(plain_bool_flag(&mut a, "--all"));
        assert_eq!(a, args(&["velarx", "ps", "-q"]));
        for other in [
            vec!["velarx", "ps", "--all=maybe"],
            vec!["velarx", "ps", "--", "--all=true"],
            vec!["velarx", "ps", "-q"],
        ] {
            let mut a = args(&other);
            assert!(!plain_bool_flag(&mut a, "--all"));
            assert_eq!(a, args(&other));
        }
    }

    #[test]
    fn the_platform_of_podmans_options() {
        let of = |p: Option<&str>, o: Option<&str>, a: Option<&str>, v: Option<&str>| {
            let s = |x: Option<&str>| x.map(str::to_string);
            platform_of(s(p), s(o), s(a), s(v))
        };
        assert_eq!(of(None, None, None, None), Ok(None));
        assert_eq!(
            of(Some("linux/s390x"), None, None, None),
            Ok(Some("linux/s390x".into()))
        );
        assert_eq!(
            of(None, None, Some("arm64"), Some("v8")),
            Ok(Some("linux/arm64/v8".into()))
        );
        assert!(of(None, Some("linux"), None, None)
            .unwrap()
            .unwrap()
            .starts_with("linux/"));
        // podman's: --platform with --os or --arch is an error, a variant is
        // added to a platform without one
        let conflict = Err("--platform option can not be specified with --arch or --os".into());
        assert_eq!(of(Some("linux/amd64"), None, Some("arm64"), None), conflict);
        assert_eq!(of(Some("linux/amd64"), Some("linux"), None, None), conflict);
        assert_eq!(
            of(Some("linux/arm64"), None, None, Some("v8")),
            Ok(Some("linux/arm64/v8".into()))
        );
        assert_eq!(
            of(Some("linux/arm/v7"), None, None, Some("v6")),
            Ok(Some("linux/arm/v7".into()))
        );
    }
}

#[cfg(test)]
mod digest_flag_tests {
    use super::*;

    #[test]
    fn the_digest_of_a_new_image_is_sha256_or_sha512_by_name() {
        assert!(check_digest_flag(None).is_ok());
        for ok in ["sha256", "sha512"] {
            assert!(check_digest_flag(Some(ok)).is_ok(), "{ok}");
        }
        for bad in ["md5", "SHA512", "sha384", "sha512:", ""] {
            let e = check_digest_flag(Some(bad)).unwrap_err();
            assert!(
                e.starts_with("--digest: unknown digest algorithm") && e.contains(bad),
                "{bad}: {e}"
            );
        }
    }

    /// Every command that makes images takes `--digest`; the commands that
    /// do not make one (a pull, a push) do not.
    #[test]
    fn the_commands_that_make_images_take_digest() {
        for argv in [
            &["velarx", "build", "--digest", "sha512", "."][..],
            &["velarx", "commit", "--digest", "sha512", "c", "i"],
            &["velarx", "import", "--digest", "sha512", "f.tar", "i"],
            &["velarx", "manifest", "create", "--digest", "sha512", "l"],
            &["velarx", "artifact", "add", "--digest", "sha512", "a", "f"],
        ] {
            let args = podman_layout(argv.iter().map(Into::into).collect()).unwrap();
            if let Err(e) = crate::cli::parse_for_test(args) {
                panic!("{argv:?}: {e}");
            }
        }
        for argv in [
            &["velarx", "pull", "--digest", "sha512", "i"][..],
            &["velarx", "push", "--digest", "sha512", "i"],
        ] {
            let args = podman_layout(argv.iter().map(Into::into).collect()).unwrap();
            assert!(crate::cli::parse_for_test(args).is_err(), "{argv:?}");
        }
    }
}

#[cfg(test)]
mod pushed_by_digest_tests {
    use super::*;

    #[test]
    fn test_the_name_by_the_digest_of_a_push_by_a_tag() {
        let d = "sha512:ab";
        assert_eq!(
            pushed_by_digest_name("localhost:5000/r/img:t", d).as_deref(),
            Some("localhost:5000/r/img@sha512:ab")
        );
        assert_eq!(
            pushed_by_digest_name("localhost:5000/img", d).as_deref(),
            Some("localhost:5000/img@sha512:ab")
        );
        assert_eq!(pushed_by_digest_name("r/img@sha512:ab", d), None);
        assert_eq!(pushed_by_digest_name("r/img:t@sha512:ab", d), None);
    }
}
