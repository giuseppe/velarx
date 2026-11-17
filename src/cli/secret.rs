// SPDX-License-Identifier: Apache-2.0
//! `velarx secret`: the secrets of the daemon, through the podman
//! compatible API.

use crate::client::{ClientError, EngineClient, SecretCreate};
use clap::Subcommand;
use serde_json::Value;
use std::io::Read;

#[derive(Subcommand, Clone)]
pub enum SecretCommands {
    #[command(about = "Create a new secret")]
    Create {
        /// Secret driver: file (default), pass or shell
        #[arg(long, short)]
        driver: Option<String>,
        /// Options of the driver (key=value, comma separated): pass root=,
        /// key=, gpghomedir=; shell list=, lookup=, store=, delete=
        #[arg(long)]
        driver_opts: Vec<String>,
        /// Replace a secret of the same name
        #[arg(long)]
        replace: bool,
        /// Do nothing when a secret of the same name exists
        #[arg(long)]
        ignore: bool,
        /// Read the data from the environment variable FILE
        #[arg(long)]
        env: bool,
        /// Labels (key=value)
        #[arg(long, short)]
        label: Vec<String>,
        /// Name of the secret
        name: String,
        /// File with the data, or - for the standard input
        file: String,
    },

    #[command(name = "ls", visible_alias = "list", about = "List secrets")]
    List {
        /// Only print the names
        #[arg(long, short)]
        quiet: bool,
        /// Do not print the header
        #[arg(long, short = 'n')]
        noheading: bool,
        /// Output format: json, table, or a template with {{.ID}}, {{.Name}}, {{.Driver}}, {{.CreatedAt}}, {{.UpdatedAt}}
        #[arg(long)]
        format: Option<String>,
        /// Filter (name=, id=, label=)
        #[arg(long, short)]
        filter: Vec<String>,
    },

    #[command(about = "Display detailed information on secrets")]
    Inspect {
        /// Print the data of the secrets
        #[arg(long)]
        showsecret: bool,
        /// Output format: json or a template
        #[arg(long, short = 'f')]
        format: Option<String>,
        /// Print the secrets as text for people (over --format)
        #[arg(long)]
        pretty: bool,
        #[arg(required = true)]
        names: Vec<String>,
    },

    #[command(name = "rm", visible_alias = "remove", about = "Remove secrets")]
    Remove {
        /// Remove all secrets
        #[arg(long, short)]
        all: bool,
        /// Do not fail on a secret that does not exist
        #[arg(long, short = 'i')]
        ignore: bool,
        names: Vec<String>,
    },

    #[command(about = "Check if a secret exists; the exit status says so")]
    Exists { name: String },
}

/// `--driver-opts k=v,k=v` (repeatable).  A value with a comma, as a shell
/// command can have, goes in an option of its own: a part without `=` is
/// part of the value before it.
fn driver_options(opts: &[String]) -> anyhow::Result<std::collections::BTreeMap<String, String>> {
    let mut out = std::collections::BTreeMap::new();
    for o in opts {
        let mut last: Option<String> = None;
        for part in o.split(',') {
            match (part.split_once('='), &last) {
                (Some((k, v)), _) if !k.is_empty() && !k.contains(' ') => {
                    out.insert(k.to_string(), v.to_string());
                    last = Some(k.to_string());
                }
                (_, Some(k)) => {
                    if let Some(v) = out.get_mut(k) {
                        v.push(',');
                        v.push_str(part);
                    }
                }
                _ => anyhow::bail!("invalid driver option `{o}`: key=value"),
            }
        }
    }
    Ok(out)
}

fn read_data(source: &str, env: bool) -> anyhow::Result<Vec<u8>> {
    if env {
        let v = std::env::var_os(source)
            .ok_or_else(|| anyhow::anyhow!("environment variable {source} is not set"))?;
        return Ok(std::os::unix::ffi::OsStrExt::as_bytes(v.as_os_str()).to_vec());
    }
    let mut data = Vec::new();
    // One byte over the limit of the daemon: a larger file is refused by it
    let limit = velarx_wire::wire::SECRET_MAX_SIZE as u64 + 1;
    if source == "-" {
        std::io::stdin().take(limit).read_to_end(&mut data)?;
    } else {
        std::fs::File::open(source)
            .map_err(|e| anyhow::anyhow!("cannot read {source}: {e}"))?
            .take(limit)
            .read_to_end(&mut data)?;
    }
    Ok(data)
}

/// Render `{{.Field}}` of a template for one secret (a `table ` prefix is
/// handled by the caller).
/// A `secret ls --format` template: the fields of podman's
/// SecretListReport (the times as `3 minutes ago`).  `s` null: the line of
/// the headers.
fn render(template: &str, s: &Value) -> String {
    let get = |f: &str| -> String {
        if s.is_null() {
            return match f {
                "CreatedAt" => "CREATED".into(),
                "UpdatedAt" => "UPDATED".into(),
                "ID" | "Name" | "Driver" => f.to_ascii_uppercase(),
                _ => String::new(),
            };
        }
        let v = match f {
            "ID" => &s["ID"],
            "Name" => &s["Spec"]["Name"],
            "Driver" => &s["Spec"]["Driver"]["Name"],
            "CreatedAt" | "UpdatedAt" => return ago(s[f].as_str().unwrap_or_default()),
            _ => return String::new(),
        };
        v.as_str().unwrap_or_default().to_string()
    };
    let mut out = String::new();
    let mut rest = template;
    while let Some(i) = rest.find("{{") {
        out.push_str(&rest[..i]);
        let Some(j) = rest[i..].find("}}") else { break };
        let field = rest[i + 2..i + j].trim().trim_start_matches('.');
        out.push_str(&get(field));
        rest = &rest[i + j + 2..];
    }
    out.push_str(rest);
    out.replace("\\t", "\t").replace("\\n", "\n")
}

/// podman's `secret inspect --pretty`.
const PRETTY: &str = "ID:              {{.ID}}
Name:              {{.Spec.Name}}
{{- if .Spec.Labels }}
Labels:
{{- range $k, $v := .Spec.Labels }}
 - {{ $k }}{{if $v }}={{ $v }}{{ end }}
{{- end }}{{ end }}
Driver:            {{.Spec.Driver.Name}}
Created at:        {{.CreatedAt}}
Updated at:        {{.UpdatedAt}}";

/// A secret as podman's templates see it: its times are Go's.
fn go_times(s: &Value) -> Value {
    let mut s = s.clone();
    // (without --showsecret, empty)
    if s["SecretData"].is_null() {
        s["SecretData"] = Value::String(String::new());
    }
    for k in ["CreatedAt", "UpdatedAt"] {
        if let Some(t) = s[k]
            .as_str()
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
            .and_then(|t| t.timestamp_nanos_opt())
        {
            s[k] = Value::String(crate::cli::events::go_time_ns(t));
        }
    }
    s
}

fn missing(e: &ClientError) -> bool {
    e.is_not_found()
}

pub fn run(cmd: SecretCommands, client: &EngineClient) -> anyhow::Result<()> {
    match cmd {
        SecretCommands::Create {
            driver,
            driver_opts,
            replace,
            ignore,
            env,
            label,
            name,
            file,
        } => {
            let data = read_data(&file, env)?;
            let labels = label
                .iter()
                .map(|l| {
                    let (k, v) = l.split_once('=').unwrap_or((l.as_str(), ""));
                    (k.to_string(), v.to_string())
                })
                .collect();
            let req = SecretCreate {
                name,
                driver,
                driver_opts: driver_options(&driver_opts)?,
                labels,
                replace,
                ignore,
            };
            println!("{}", client.secret_create(&req, &data)?);
        }
        SecretCommands::List {
            quiet,
            noheading,
            format,
            filter,
        } => {
            let items: Vec<Value> = client
                .secret_list(&filter)?
                .iter()
                .map(velarx_shape::secret::libpod)
                .collect();
            match format.as_deref() {
                _ if quiet => {
                    for s in &items {
                        println!("{}", s["ID"].as_str().unwrap_or_default());
                    }
                }
                Some("json") => println!("{}", serde_json::to_string_pretty(&items)?),
                Some(t) if t != "table" => {
                    let (table, t) = match t.strip_prefix("table ") {
                        Some(t) => (true, t),
                        None => (false, t),
                    };
                    if table && !noheading {
                        println!("{}", render(t, &Value::Null).replace("\t", "  "));
                    }
                    for s in &items {
                        println!("{}", render(t, s));
                    }
                }
                _ => {
                    // (columns as wide as their cells, as podman's tabwriter:
                    // "Less than a second ago" is wider than a fixed column)
                    let mut text = String::new();
                    if !noheading {
                        text.push_str("ID\tNAME\tDRIVER\tCREATED\tUPDATED\n");
                    }
                    for s in &items {
                        text.push_str(&format!(
                            "{}\t{}\t{}\t{}\t{}\n",
                            s["ID"].as_str().unwrap_or_default(),
                            s["Spec"]["Name"].as_str().unwrap_or_default(),
                            s["Spec"]["Driver"]["Name"].as_str().unwrap_or_default(),
                            ago(s["CreatedAt"].as_str().unwrap_or_default()),
                            ago(s["UpdatedAt"].as_str().unwrap_or_default()),
                        ));
                    }
                    print!("{}", crate::cli::template::align_text(&text));
                }
            }
        }
        SecretCommands::Inspect {
            showsecret,
            format,
            pretty,
            names,
        } => {
            let mut all = Vec::new();
            for n in &names {
                match client.secret_inspect(n, showsecret) {
                    Ok(s) => all.push(velarx_shape::secret::libpod(&s)),
                    Err(e) => anyhow::bail!("inspecting secret {n}: {e}"),
                }
            }
            let format = if pretty {
                Some(PRETTY)
            } else {
                format.as_deref()
            };
            match format {
                None | Some("json") => {
                    println!("{}", serde_json::to_string_pretty(&all)?)
                }
                Some(t) => {
                    let t = crate::cli::template::Template::parse(t).map_err(anyhow::Error::msg)?;
                    for s in &all {
                        let s = t.render(&go_times(s)).map_err(anyhow::Error::msg)?;
                        println!("{s}");
                    }
                }
            }
        }
        SecretCommands::Remove { all, ignore, names } => {
            if all {
                client.secret_remove_all()?;
                return Ok(());
            }
            if names.is_empty() {
                anyhow::bail!("`velarx secret rm` requires one argument, or the --all flag");
            }
            let mut failed = 0;
            crate::cli::run::each_item(
                &names,
                |n| match client.secret_remove(n) {
                    Ok(()) => {
                        println!("{n}");
                        Ok(())
                    }
                    Err(e) if ignore && missing(&e) => Ok(()),
                    Err(e) => Err(e),
                },
                |n, e| {
                    eprintln!("Error: {n}: {e}");
                    failed += 1;
                },
            )?;
            if failed > 0 {
                anyhow::bail!("{failed} of {} failed", names.len());
            }
        }
        SecretCommands::Exists { name } => {
            if !client.secret_exists(&name)? {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

/// "3 minutes ago" for an RFC 3339 time, as podman's `secret ls` says it
/// (go-units' HumanDuration).
fn ago(t: &str) -> String {
    match chrono::DateTime::parse_from_rfc3339(t) {
        Ok(then) => crate::cli::report::human_since(then.timestamp()),
        Err(_) => t.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn templates() {
        let s = json!({"ID": "abc", "Spec": {"Name": "db", "Driver": {"Name": "file"}}});
        assert_eq!(render("{{.ID}}\\t{{ .Name }}", &s), "abc\tdb");
        assert_eq!(render("{{.Driver}} {{.Nope}}!", &s), "file !");
        assert_eq!(render("plain", &s), "plain");
        assert_eq!(render("{{.ID", &s), "{{.ID");
        // (the headers of podman's report, and its times)
        assert_eq!(
            render(
                "{{.ID}} {{.Name}} {{.Driver}} {{.CreatedAt}} {{.UpdatedAt}}",
                &Value::Null
            ),
            "ID NAME DRIVER CREATED UPDATED"
        );
        let t = json!({"CreatedAt": "junk", "UpdatedAt": chrono::Utc::now().to_rfc3339()});
        assert_eq!(
            render("{{.CreatedAt}}|{{.UpdatedAt}}", &t),
            "junk|Less than a second ago"
        );
    }

    #[test]
    fn relative_times() {
        let now = chrono::Utc::now();
        let t = |s: i64| (now - chrono::Duration::seconds(s)).to_rfc3339();
        assert_eq!(ago(&t(0)), "Less than a second ago");
        assert_eq!(ago(&t(1)), "1 second ago");
        assert_eq!(ago(&t(61)), "About a minute ago");
        assert_eq!(ago(&t(300)), "5 minutes ago");
        assert_eq!(ago(&t(7300)), "2 hours ago");
        assert_eq!(ago(&t(3 * 86400)), "3 days ago");
        assert_eq!(ago("junk"), "junk");
    }

    #[test]
    fn driver_options_keep_commas_of_values() {
        let o = driver_options(&[
            "list=ls /s,lookup=cat /s/$SECRET_ID".into(),
            "store=tee a,b".into(),
        ])
        .unwrap();
        assert_eq!(o["list"], "ls /s");
        assert_eq!(o["lookup"], "cat /s/$SECRET_ID");
        assert_eq!(o["store"], "tee a,b");
        assert!(driver_options(&["novalue".into()]).is_err());
    }
}
