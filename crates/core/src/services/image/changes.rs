// SPDX-License-Identifier: Apache-2.0
//! Dockerfile style changes (`--change 'ENV A=b'`) applied to an image
//! configuration.

use serde_json::{json, Map, Value};

fn unquote(s: &str) -> String {
    let b = s.as_bytes();
    if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[b.len() - 1] == b[0] {
        return s[1..s.len() - 1].to_string();
    }
    s.to_string()
}

/// `KEY=VALUE` pairs separated by spaces (values may be quoted), or the
/// legacy `KEY VALUE`.
fn parse_pairs(args: &str) -> Result<Vec<(String, String)>, String> {
    if !args.contains('=') {
        let (key, value) = args
            .split_once([' ', '\t'])
            .ok_or_else(|| format!("invalid change `{args}`: missing value"))?;
        return Ok(vec![(key.to_string(), value.trim_start().to_string())]);
    }
    let mut pairs = Vec::new();
    let mut rest = args.trim_start();
    while !rest.is_empty() {
        let eq = rest
            .find('=')
            .ok_or_else(|| format!("invalid change `{args}`: expected KEY=VALUE"))?;
        let key = unquote(&rest[..eq]);
        let after = &rest[eq + 1..];
        let end = match after.chars().next() {
            Some(q @ ('"' | '\'')) => after[1..]
                .find(q)
                .map(|i| i + 2)
                .ok_or_else(|| format!("invalid change `{args}`: unterminated quote"))?,
            _ => after.find(char::is_whitespace).unwrap_or(after.len()),
        };
        pairs.push((key, unquote(&after[..end])));
        rest = after[end..].trim_start();
    }
    Ok(pairs)
}

/// A JSON array of strings, or the words of `args` (the shell form runs it
/// with `/bin/sh -c`).
fn parse_command(args: &str, shell_form: bool) -> Result<Vec<String>, String> {
    if args.starts_with('[') {
        return serde_json::from_str(args)
            .map_err(|_| format!("invalid JSON array of strings `{args}`"));
    }
    if shell_form {
        return Ok(vec!["/bin/sh".into(), "-c".into(), args.to_string()]);
    }
    Ok(args.split_whitespace().map(str::to_string).collect())
}

fn object<'a>(parent: &'a mut Map<String, Value>, key: &str) -> &'a mut Map<String, Value> {
    let entry = parent.entry(key).or_insert_with(|| json!({}));
    if !entry.is_object() {
        *entry = json!({});
    }
    entry.as_object_mut().unwrap_or_else(|| unreachable!())
}

/// Apply one change to the configuration of an image (the whole JSON
/// document: the settings are in its `config` object).
pub fn apply(config: &mut Value, change: &str) -> Result<(), String> {
    let Some(root) = config.as_object_mut() else {
        return Err("the configuration is not an object".into());
    };
    let keyword_end = change
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(change.len());
    let keyword = change[..keyword_end].to_ascii_uppercase();
    let args = change[keyword_end..].trim_start_matches(|c: char| c.is_whitespace() || c == '=');
    if args.is_empty() {
        return Err(format!("invalid change `{change}`: missing value"));
    }
    let c = object(root, "config");
    match keyword.as_str() {
        "CMD" | "ENTRYPOINT" => {
            let key = if keyword == "CMD" {
                "Cmd"
            } else {
                "Entrypoint"
            };
            c.insert(key.into(), json!(parse_command(args, true)?));
        }
        "SHELL" => {
            if !args.starts_with('[') {
                return Err("SHELL requires a JSON array".into());
            }
            c.insert("Shell".into(), json!(parse_command(args, false)?));
        }
        "ENV" => {
            let env = c.entry("Env").or_insert_with(|| json!([]));
            let Some(env) = env.as_array_mut() else {
                return Err("the Env of the configuration is not an array".into());
            };
            for (key, value) in parse_pairs(args)? {
                let prefix = format!("{key}=");
                let entry = json!(format!("{key}={value}"));
                match env
                    .iter_mut()
                    .find(|e| e.as_str().is_some_and(|e| e.starts_with(&prefix)))
                {
                    Some(old) => *old = entry,
                    None => env.push(entry),
                }
            }
        }
        "LABEL" => {
            let labels = object(c, "Labels");
            for (key, value) in parse_pairs(args)? {
                labels.insert(key, json!(value));
            }
        }
        "WORKDIR" => {
            c.insert("WorkingDir".into(), json!(args));
        }
        "USER" => {
            c.insert("User".into(), json!(args));
        }
        "STOPSIGNAL" => {
            c.insert("StopSignal".into(), json!(args));
        }
        "EXPOSE" | "VOLUME" => {
            let key = if keyword == "EXPOSE" {
                "ExposedPorts"
            } else {
                "Volumes"
            };
            let words = if args.starts_with('[') {
                parse_command(args, false)?
            } else {
                args.split_whitespace().map(str::to_string).collect()
            };
            let set = object(c, key);
            for w in words {
                let w = if keyword == "EXPOSE" && !w.contains('/') {
                    format!("{w}/tcp")
                } else {
                    w
                };
                set.insert(w, json!({}));
            }
        }
        other => return Err(format!("unsupported change `{other}`")),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn applied(changes: &[&str]) -> Value {
        let mut c =
            json!({"architecture": "amd64", "os": "linux", "config": {"Env": ["A=old", "B=b"]}});
        for ch in changes {
            apply(&mut c, ch).unwrap();
        }
        c
    }

    #[test]
    fn test_commands_and_environment() {
        let c = applied(&[
            "CMD [\"sh\", \"-c\", \"echo $A\"]",
            "ENTRYPOINT /bin/run it",
            "ENV A=new C=\"with space\"",
            "env legacy value here",
            "WORKDIR /srv",
            "USER 1000:1000",
            "STOPSIGNAL SIGINT",
        ]);
        let c = &c["config"];
        assert_eq!(c["Cmd"], json!(["sh", "-c", "echo $A"]));
        assert_eq!(c["Entrypoint"], json!(["/bin/sh", "-c", "/bin/run it"]));
        assert_eq!(
            c["Env"],
            json!(["A=new", "B=b", "C=with space", "legacy=value here"])
        );
        assert_eq!(c["WorkingDir"], "/srv");
        assert_eq!(c["User"], "1000:1000");
        assert_eq!(c["StopSignal"], "SIGINT");
    }

    #[test]
    fn test_labels_ports_and_volumes() {
        let c = applied(&[
            "LABEL a=b c='d e'",
            "EXPOSE 80 53/udp",
            "VOLUME [\"/data\", \"/logs\"]",
        ]);
        let c = &c["config"];
        assert_eq!(c["Labels"], json!({"a": "b", "c": "d e"}));
        assert_eq!(c["ExposedPorts"], json!({"80/tcp": {}, "53/udp": {}}));
        assert_eq!(c["Volumes"], json!({"/data": {}, "/logs": {}}));
    }

    #[test]
    fn test_invalid_changes() {
        let mut c = json!({});
        for bad in [
            "",
            "CMD",
            "ENV novalue",
            "ENV a=\"open",
            "SHELL /bin/sh",
            "CMD [1]",
            "FROM x",
        ] {
            assert!(apply(&mut c, bad).is_err(), "{bad}");
        }
    }
}
