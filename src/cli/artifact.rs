// SPDX-License-Identifier: Apache-2.0
//! `velarx artifact`: OCI artifacts, through the REST
//! API of the server (or of the command's own engine).

use super::report::{self, human_since, human_size, ListOutput};
use super::template;
use crate::client::{ArtifactAdd, ArtifactTransfer, EngineClient};
use clap::Subcommand;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Subcommand, Clone)]
pub enum ArtifactCommands {
    #[command(about = "Add files as an OCI artifact of the local store")]
    Add {
        /// Add the files to the artifact, which must exist
        #[arg(long, short)]
        append: bool,
        /// Replace the artifact of the same name
        #[arg(long)]
        replace: bool,
        /// The artifactType of the manifest
        #[arg(long = "type", value_name = "TYPE")]
        artifact_type: Option<String>,
        /// The media type of the files (default: what their bytes tell)
        #[arg(long)]
        file_type: Option<String>,
        /// An annotation of the files (KEY=VALUE)
        #[arg(long)]
        annotation: Vec<String>,
        /// Algorithm of the digests of a new artifact: sha256 or sha512 (default: [build]
        /// digest); an artifact that is appended to keeps its own
        #[arg(long, value_name = "ALGORITHM")]
        digest: Option<String>,
        name: String,
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },

    #[command(about = "Pull an artifact from a registry")]
    Pull {
        /// Say nothing but the digest
        #[arg(long, short)]
        quiet: bool,
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1,
              default_missing_value = "true", require_equals = true)]
        tls_verify: bool,
        #[command(flatten)]
        access: super::RegistryAccessArgs,
        /// How many times a failed pull is tried again
        #[arg(long, default_value = "3")]
        retry: u32,
        /// The time between the tries (default 1s)
        #[arg(long)]
        retry_delay: Option<String>,
        /// Refused: velarx pulls no encrypted artifact
        #[arg(long, hide = true)]
        decryption_key: Vec<String>,
        name: String,
    },

    #[command(about = "Push an artifact to a registry")]
    Push {
        /// Say nothing but the digest
        #[arg(long, short)]
        quiet: bool,
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1,
              default_missing_value = "true", require_equals = true)]
        tls_verify: bool,
        #[command(flatten)]
        access: super::RegistryAccessArgs,
        /// Write the digest of the manifest pushed to this file
        #[arg(long)]
        digestfile: Option<PathBuf>,
        /// How many times a failed push is tried again
        #[arg(long, default_value = "3")]
        retry: u32,
        /// The time between the tries (default 1s)
        #[arg(long)]
        retry_delay: Option<String>,
        #[command(flatten)]
        signing: super::SigningArgs,
        /// Refused: the layers are pushed as they are kept
        #[arg(long, hide = true)]
        compression_format: Option<String>,
        name: String,
    },

    #[command(
        name = "ls",
        visible_alias = "list",
        about = "List the artifacts of the local store"
    )]
    List {
        #[command(flatten)]
        out: ListOutput,
    },

    #[command(about = "Show the manifest of an artifact")]
    Inspect {
        /// Go template, or `json`
        #[arg(long, short, default_value = "json")]
        format: String,
        name: String,
    },

    #[command(about = "Remove artifacts")]
    Rm {
        /// Remove every artifact
        #[arg(long, short)]
        all: bool,
        /// Do not fail on an artifact that is not there
        #[arg(long, short)]
        ignore: bool,
        names: Vec<String>,
    },

    #[command(about = "Write the files of an artifact into a directory, or one into a file")]
    Extract {
        /// Only the file with this digest
        #[arg(long, conflicts_with = "title")]
        digest: Option<String>,
        /// Only the file with this title
        #[arg(long)]
        title: Option<String>,
        name: String,
        target: PathBuf,
    },
}

/// The path of the libpod API for an artifact named `name`.
pub fn run(cmd: ArtifactCommands, client: &EngineClient) -> anyhow::Result<()> {
    match cmd {
        ArtifactCommands::Add {
            append,
            replace,
            artifact_type,
            file_type,
            annotation,
            digest,
            name,
            files,
        } => {
            crate::cli::check_digest_flag(digest.as_deref()).map_err(anyhow::Error::msg)?;
            if append && replace {
                anyhow::bail!("--append and --replace options cannot be used together");
            }
            for a in &annotation {
                if !a.contains('=') {
                    anyhow::bail!("invalid annotation {a:?}: KEY=VALUE");
                }
            }
            let mut added = String::new();
            for (i, f) in files.iter().enumerate() {
                let title = f
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .ok_or_else(|| anyhow::anyhow!("{}: not a file", f.display()))?;
                let mut file =
                    std::fs::File::open(f).map_err(|e| anyhow::anyhow!("{}: {e}", f.display()))?;
                if !file.metadata()?.is_file() {
                    anyhow::bail!("{}: not a regular file", f.display());
                }
                // the first file makes (or replaces) the artifact, the others
                // are added to it
                let req = ArtifactAdd {
                    name: name.clone(),
                    file_name: title,
                    append: i > 0 || append,
                    replace: i == 0 && replace,
                    artifact_type: if i == 0 { artifact_type.clone() } else { None },
                    file_type: file_type.clone(),
                    annotations: annotation.clone(),
                    digest: digest.clone(),
                };
                added = client
                    .artifact_add(&req, Box::new(|w| std::io::copy(&mut file, w).map(|_| ())))?;
            }
            println!("{}", velarx_shape::without_algorithm(&added));
        }
        ArtifactCommands::Pull {
            quiet,
            tls_verify,
            access,
            retry,
            retry_delay,
            decryption_key,
            name,
        } => {
            if !decryption_key.is_empty() {
                anyhow::bail!(
                    "--decryption-key is not supported: velarx pulls no encrypted artifact"
                );
            }
            let name = super::transport::registry(&name, "artifact pull")?;
            let access = super::commands::commands_registry_access(client, &access, &name, false)?;
            if !quiet {
                eprintln!("Pulling {name}...");
            }
            let d = client.artifact_pull(&ArtifactTransfer {
                name,
                tls_verify,
                retry: crate::client::policy::retry_of(
                    Some(retry),
                    retry_delay.as_deref().filter(|d| !d.is_empty()),
                )
                .map_err(|e| anyhow::anyhow!("--retry-delay: {e}"))?,
                access,
            })?;
            println!("{}", velarx_shape::without_algorithm(&d));
        }
        ArtifactCommands::Push {
            quiet,
            tls_verify,
            access,
            digestfile,
            retry,
            retry_delay,
            signing,
            compression_format,
            name,
        } => {
            signing.refuse("artifact")?;
            if compression_format.is_some() {
                anyhow::bail!(
                    "--compression-format is not supported: the files of an artifact are pushed as they are kept"
                );
            }
            let name = super::transport::registry(&name, "artifact push")?;
            let access = super::commands::commands_registry_access(client, &access, &name, true)?;
            if !quiet {
                eprintln!("Pushing {name}...");
            }
            let pushed = client.artifact_push(&ArtifactTransfer {
                name: name.clone(),
                tls_verify,
                retry: crate::client::policy::retry_of(
                    Some(retry),
                    retry_delay.as_deref().filter(|d| !d.is_empty()),
                )
                .map_err(|e| anyhow::anyhow!("--retry-delay: {e}"))?,
                access,
            })?;
            let d = pushed.digest.clone();
            if let Some(f) = &digestfile {
                std::fs::write(f, &d).map_err(|e| anyhow::anyhow!("{}: {e}", f.display()))?;
            }
            if !quiet {
                eprintln!("Pushed {d}");
            }
            // (a sha512 artifact is put by its digest after its tag: a
            // registry that refuses that is said, even with --quiet)
            if let Some(by) = super::pushed_by_digest_name(&name, &d) {
                for line in super::refusal_warnings(&pushed.placed, &by) {
                    eprintln!("{line}");
                }
            }
        }
        ArtifactCommands::List { out } => list(client, &out)?,
        ArtifactCommands::Inspect { format, name } => {
            let a = client.artifact_inspect(&name)?;
            report::one(&a, &format)?;
        }
        ArtifactCommands::Rm { all, ignore, names } => {
            if all && !names.is_empty() {
                anyhow::bail!("--all takes no artifact");
            }
            if !all && names.is_empty() {
                anyhow::bail!("give at least one artifact, or --all");
            }
            for d in client.artifact_remove(&names, all, ignore)? {
                println!("{}", velarx_shape::without_algorithm(&d));
            }
        }
        ArtifactCommands::Extract {
            digest,
            title,
            name,
            target,
        } => extract(client, &name, &target, digest.as_deref(), title.as_deref())?,
    }
    Ok(())
}

fn list(client: &EngineClient, out: &ListOutput) -> anyhow::Result<()> {
    let all = client.artifact_list()?;
    let items: Vec<Value> = all
        .as_array()
        .into_iter()
        .flatten()
        .map(|a| {
            let name = a["Name"].as_str().unwrap_or_default();
            let (repo, tag) = match name.rsplit_once(':') {
                Some((r, t)) if !t.contains('/') => (r, t),
                _ => (name, ""),
            };
            let digest = a["Digest"].as_str().unwrap_or_default();
            let hex = velarx_shape::without_algorithm(digest);
            let size: u64 = a["Manifest"]["layers"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|l| l["size"].as_u64().unwrap_or(0))
                .sum();
            let created = a["Manifest"]["annotations"]["org.opencontainers.image.created"]
                .as_str()
                .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok());
            json!({
                "Repository": repo,
                "Tag": tag,
                "Digest": if out.no_trunc { hex.to_string() } else { hex.chars().take(12).collect() },
                "Size": human_size(size as f64),
                "VirtualSize": size.to_string(),
                "Created": created.map(|t| human_since(t.timestamp())).unwrap_or_default(),
                "CreatedAt": created.map(|t| t.to_rfc3339()).unwrap_or_default(),
            })
        })
        .collect();
    if out.quiet {
        for i in &items {
            println!("{}", template::text(&i["Digest"]));
        }
        return Ok(());
    }
    let format = out
        .format
        .as_deref()
        .unwrap_or("table {{.Repository}}\t{{.Tag}}\t{{.Digest}}\t{{.Created}}\t{{.Size}}");
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&items)?);
        return Ok(());
    }
    let headers: HashMap<&str, &str> = HashMap::new();
    let mut text = template::format_list(format, &items, &headers).map_err(anyhow::Error::msg)?;
    if out.noheading && template::Template::parse(format).is_ok_and(|t| t.is_table()) {
        text = text
            .split_once('\n')
            .map(|(_, r)| r.to_string())
            .unwrap_or_default();
    }
    print!("{text}");
    Ok(())
}

/// `extract`: the server's tar of the blobs, written into `target` (a
/// directory) or as it (one blob); never through a symbolic link.
fn extract(
    client: &EngineClient,
    name: &str,
    target: &std::path::Path,
    digest: Option<&str>,
    title: Option<&str>,
) -> anyhow::Result<()> {
    let stream = client.artifact_extract(name, digest, title)?;
    let mut tar = tar::Archive::new(stream);
    let into_dir = target.is_dir();
    for (written, entry) in tar.entries()?.enumerate() {
        let mut entry = entry?;
        let entry_name = entry.path()?.to_string_lossy().into_owned();
        if entry_name.contains('/') || entry_name == ".." || entry_name == "." {
            anyhow::bail!("invalid name {entry_name:?} in the artifact");
        }
        if !into_dir && written > 0 {
            anyhow::bail!("the artifact {name} has several files: extract it into a directory");
        }
        let dest = if into_dir {
            target.join(&entry_name)
        } else {
            target.to_path_buf()
        };
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&dest)
            .map_err(|e| anyhow::anyhow!("{}: {e}", dest.display()))?;
        std::io::copy(&mut entry, &mut f)?;
    }
    Ok(())
}
