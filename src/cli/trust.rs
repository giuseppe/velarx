// SPDX-License-Identifier: Apache-2.0
//! `image trust show` and `image trust set`: the policy.json that the
//! engine reads (`[pull] policy_path`, else the user's and the system's
//! velarx/policy.json) and its registries.d, as podman's commands edit
//! containers' ones.

use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand, Clone, Debug)]
pub enum TrustCommands {
    #[command(about = "Set the default trust policy or add a trust policy for a registry")]
    Set {
        /// A public key to trust for the scope (repeatable): a GPG key for
        /// signedBy, a PEM public key for sigstoreSigned
        #[arg(long, short = 'f', value_name = "PATH")]
        pubkeysfile: Vec<PathBuf>,
        /// The trust: signedBy (the default), sigstoreSigned, accept or reject
        #[arg(long, short = 't', default_value = "signedBy", value_name = "TYPE")]
        r#type: String,
        /// The policy file to edit
        #[arg(long, hide = true, value_name = "PATH")]
        policypath: Option<PathBuf>,
        /// `default`, a registry or a repository
        scope: String,
    },

    #[command(about = "Display the trust policy")]
    Show {
        /// Output as JSON
        #[arg(long, short)]
        json: bool,
        /// Do not print the headings
        #[arg(long, short)]
        noheading: bool,
        /// Output the policy file as it is
        #[arg(long)]
        raw: bool,
        /// The policy file to show
        #[arg(long, hide = true, value_name = "PATH")]
        policypath: Option<PathBuf>,
        /// The directory of the registries.d to show
        #[arg(long, hide = true, value_name = "DIR")]
        registrypath: Option<PathBuf>,
        /// Only this scope (and the default)
        scope: Option<String>,
    },
}

#[cfg(feature = "engine")]
mod engine {
    use super::TrustCommands;
    use std::path::PathBuf;
    /// The policy file `--policypath` names, else `[pull] policy_path`.
    fn policy_file(flag: Option<PathBuf>, config: &velarx_config::Config) -> Option<PathBuf> {
        flag.or_else(|| config.pull.policy_path.clone())
    }

    /// The registries.d the engine reads, or `dir` alone.
    fn registries(
        dir: Option<PathBuf>,
        config: &velarx_config::Config,
    ) -> anyhow::Result<velarx_signature::registries_d::RegistriesD> {
        use velarx_signature::registries_d::RegistriesD;
        match dir.or_else(|| config.pull.registries_d.clone()) {
            Some(d) => RegistriesD::load_dirs(&[d]),
            None => RegistriesD::load(),
        }
        .map_err(|e| anyhow::anyhow!("registries.d: {e}"))
    }

    /// The directory `set` writes registries.d files to: the configured one,
    /// else the user's (rootless) or the system's.
    fn registries_dir(config: &velarx_config::Config) -> anyhow::Result<PathBuf> {
        if let Some(d) = &config.pull.registries_d {
            return Ok(d.clone());
        }
        if velarx_base::conf::rootless()? {
            if let Some(d) = velarx_base::conf::user_config_dir()? {
                return Ok(d.join("velarx/registries.d"));
            }
        }
        Ok(PathBuf::from("/etc/velarx/registries.d"))
    }

    /// Replace `path` by a file with `data`: a reader sees the old file or
    /// the new one, never half of one, and both survive a crash (the file
    /// and its directory are synced).  The new file takes the mode of the
    /// old one (0644 for a new one); it is made with O_EXCL, so no link of
    /// another user is followed.
    fn write_replacing(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let dir = match path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => std::path::Path::new("."),
        };
        let name = path
            .file_name()
            .ok_or_else(|| std::io::Error::other("no file name"))?
            .to_string_lossy();
        let mode = std::fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0o644);
        let tmp = dir.join(format!(
            ".{name}.{}.{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)?;
        let written = f
            .set_permissions(std::fs::Permissions::from_mode(mode))
            .and_then(|()| f.write_all(data))
            .and_then(|()| f.sync_all());
        drop(f);
        let renamed = written.and_then(|()| std::fs::rename(&tmp, path));
        if renamed.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        renamed?;
        std::fs::File::open(dir)?.sync_all()
    }

    /// An exclusive lock of the directory `dir` (made if missing), held
    /// while a file of it is read, changed and replaced: two `trust set`
    /// at once do not lose one of the changes.
    fn lock_dir(dir: &std::path::Path) -> anyhow::Result<std::fs::File> {
        std::fs::create_dir_all(dir).map_err(|e| anyhow::anyhow!("{}: {e}", dir.display()))?;
        let f = std::fs::File::open(dir).map_err(|e| anyhow::anyhow!("{}: {e}", dir.display()))?;
        f.lock()
            .map_err(|e| anyhow::anyhow!("locking {}: {e}", dir.display()))?;
        Ok(f)
    }

    pub fn run(cmd: super::TrustCommands) -> anyhow::Result<()> {
        use velarx_signature::trust;
        let config = crate::cli::config()?;
        match cmd {
            TrustCommands::Set {
                pubkeysfile,
                r#type,
                policypath,
                scope,
            } => {
                let kind = trust::TrustType::parse(&r#type).map_err(anyhow::Error::msg)?;
                // sigstore signatures are attachments of the registry: a scope
                // whose registries.d does not look for them gets a file that
                // does (decided before anything is written)
                let attach = if kind == trust::TrustType::SigstoreSigned && scope != "default" {
                    let r = velarx_signature::reference::DockerRef::parse_normalized(&scope)
                        .map_err(anyhow::Error::msg)?;
                    if registries(None, &config)?.use_sigstore_attachments(&r) {
                        None
                    } else {
                        let dir = registries_dir(&config)?;
                        let file = dir.join(format!("{}.yaml", scope.replace('/', "-")));
                        if file.exists() {
                            anyhow::bail!(
                                "{} exists and does not enable the sigstore attachments of {scope}: \
                                 add `use-sigstore-attachments: true` for it there",
                                file.display()
                            );
                        }
                        Some((dir, file))
                    }
                } else {
                    None
                };
                let file = policy_file(policypath, &config);
                let (_, target) =
                    trust::current(file.as_deref(), true).map_err(anyhow::Error::msg)?;
                {
                    let _lock = lock_dir(
                        target
                            .parent()
                            .filter(|d| !d.as_os_str().is_empty())
                            .unwrap_or(std::path::Path::new(".")),
                    )?;
                    // (read again under the lock: what is changed is what is
                    // replaced)
                    let (policy, target) =
                        trust::current(file.as_deref(), true).map_err(anyhow::Error::msg)?;
                    let text = trust::set_scope(&policy, &scope, kind, &pubkeysfile)
                        .map_err(anyhow::Error::msg)?;
                    write_replacing(&target, text.as_bytes())
                        .map_err(|e| anyhow::anyhow!("writing {}: {e}", target.display()))?;
                }
                if let Some((dir, file)) = attach {
                    let _lock = lock_dir(&dir)?;
                    if file.exists() {
                        anyhow::bail!("{} appeared meanwhile: not replaced", file.display());
                    }
                    write_replacing(&file, trust::attachments_yaml(&scope).as_bytes())
                        .map_err(|e| anyhow::anyhow!("writing {}: {e}", file.display()))?;
                }
            }
            TrustCommands::Show {
                json,
                noheading,
                raw,
                policypath,
                registrypath,
                scope,
            } => {
                let (policy, _) =
                    trust::current(policy_file(policypath, &config).as_deref(), false)
                        .map_err(anyhow::Error::msg)?;
                if raw {
                    print!("{policy}");
                    if !policy.ends_with('\n') {
                        println!();
                    }
                    return Ok(());
                }
                let mut rows = trust::show_rows(&policy, &registries(registrypath, &config)?)
                    .map_err(anyhow::Error::msg)?;
                if let Some(s) = &scope {
                    rows.retain(|r| r.name == "default" || r.name == *s);
                }
                if json {
                    println!("{}", serde_json::to_string_pretty(&rows)?);
                    return Ok(());
                }
                print!("{}", table(&rows, !noheading));
            }
        }
        Ok(())
    }

    /// The rows as podman prints them: columns separated by padding.
    fn table(rows: &[velarx_signature::trust::TrustRow], heading: bool) -> String {
        let mut lines: Vec<[String; 5]> = Vec::new();
        if heading {
            lines.push(["TRANSPORT", "NAME", "TYPE", "ID", "STORE"].map(String::from));
        }
        for r in rows {
            lines.push([
                r.transport.clone(),
                r.name.clone(),
                r.kind.clone(),
                r.gpg_id.clone(),
                r.sigstore.clone(),
            ]);
        }
        let mut widths = [0usize; 5];
        for l in &lines {
            for (w, c) in widths.iter_mut().zip(l) {
                *w = (*w).max(c.chars().count());
            }
        }
        let mut out = String::new();
        for l in &lines {
            let mut line = String::new();
            for (i, (c, w)) in l.iter().zip(widths).enumerate() {
                line.push_str(c);
                if i + 1 < l.len() {
                    line.push_str(&" ".repeat(w - c.chars().count() + 3));
                }
            }
            out.push_str(line.trim_end());
            out.push('\n');
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use velarx_signature::trust::TrustRow;

        #[test]
        fn the_table_has_aligned_columns() {
            let rows = [TrustRow {
                transport: "all".into(),
                name: "default".into(),
                keytype: String::new(),
                kind: "accept".into(),
                gpg_id: String::new(),
                sigstore: String::new(),
            }];
            assert_eq!(
                table(&rows, true),
                "TRANSPORT   NAME      TYPE     ID   STORE\nall         default   accept\n"
            );
            assert_eq!(table(&rows, false), "all   default   accept\n");
        }
    }
}
#[cfg(feature = "engine")]
pub use engine::run;
