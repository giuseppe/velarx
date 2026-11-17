// SPDX-License-Identifier: Apache-2.0
//! `velarx manifest`: manifest lists (podman manifest), through the
//! native API.

use crate::client::{EngineClient, ManifestOp};
use clap::Subcommand;
use std::collections::BTreeMap;
use velarx_registry::auth::RegistryAccess;
use velarx_types::transport::ImageLocation;
use velarx_wire::wire::{InstanceOptions, ManifestRequest};

use super::{RegistryAccessArgs, SigningArgs};

/// The function that gives the access of a reference: the backend, the
/// access flags, the reference, and whether the registry is written to.
pub type AccessFn<'a> =
    dyn Fn(&EngineClient, &RegistryAccessArgs, &str, bool) -> anyhow::Result<RegistryAccess> + 'a;

/// The platform and annotations of the instances (podman's flags).
#[derive(clap::Args, Clone, Debug, Default)]
pub struct InstanceArgs {
    /// An annotation (KEY=VALUE)
    #[arg(long)]
    pub annotation: Vec<String>,
    /// The architecture of the instance
    #[arg(long)]
    pub arch: Option<String>,
    /// The operating system of the instance
    #[arg(long)]
    pub os: Option<String>,
    /// The version of the operating system
    #[arg(long)]
    pub os_version: Option<String>,
    /// The architecture variant
    #[arg(long)]
    pub variant: Option<String>,
    /// The features of the instance
    #[arg(long)]
    pub features: Vec<String>,
    /// The features of the operating system
    #[arg(long)]
    pub os_features: Vec<String>,
}

/// `manifest add --artifact`: the arguments are files of an artifact.
#[derive(clap::Args, Clone, Debug, Default)]
pub struct ArtifactArgs {
    /// Add the arguments as the files of an artifact, not as images
    #[arg(long)]
    pub artifact: bool,
    /// The artifactType of the artifact
    #[arg(long)]
    pub artifact_type: Option<String>,
    /// A file with the configuration of the artifact
    #[arg(long)]
    pub artifact_config: Option<std::path::PathBuf>,
    /// The media type of its configuration
    #[arg(long)]
    pub artifact_config_type: Option<String>,
    /// The media type of its layers
    #[arg(long)]
    pub artifact_layer_type: Option<String>,
    /// No title annotation on its layers
    #[arg(long)]
    pub artifact_exclude_titles: bool,
    /// The subject of the artifact (an image of a registry)
    #[arg(long)]
    pub artifact_subject: Option<String>,
}

impl ArtifactArgs {
    /// The flags given without --artifact.
    fn stray(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.artifact_type.is_some() {
            out.push("--artifact-type");
        }
        if self.artifact_config.is_some() {
            out.push("--artifact-config");
        }
        if self.artifact_config_type.is_some() {
            out.push("--artifact-config-type");
        }
        if self.artifact_layer_type.is_some() {
            out.push("--artifact-layer-type");
        }
        if self.artifact_subject.is_some() {
            out.push("--artifact-subject");
        }
        if self.artifact_exclude_titles {
            out.push("--artifact-exclude-titles");
        }
        out
    }
}

#[derive(Subcommand, Clone)]
pub enum ManifestCommands {
    #[command(about = "Create a manifest list, with images")]
    Create {
        /// Every instance of a list given as an image
        #[arg(long)]
        all: bool,
        /// Take the list if it exists
        #[arg(long, short)]
        amend: bool,
        /// An annotation of the list (KEY=VALUE)
        #[arg(long)]
        annotation: Vec<String>,
        /// Verify the TLS certificates of the registries
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1,
              require_equals = true, default_missing_value = "true")]
        tls_verify: bool,
        /// Algorithm of the digest of the list: sha256 or sha512 (default: [build] digest)
        #[arg(long, value_name = "ALGORITHM")]
        digest: Option<String>,
        list: String,
        images: Vec<String>,
    },

    #[command(about = "Add images, or an artifact of files, to a manifest list")]
    Add {
        /// Every instance of a list given as an image
        #[arg(long)]
        all: bool,
        #[command(flatten)]
        artifact: ArtifactArgs,
        #[command(flatten)]
        instance: InstanceArgs,
        /// Verify the TLS certificates of the registries
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1,
              require_equals = true, default_missing_value = "true")]
        tls_verify: bool,
        #[command(flatten)]
        access: RegistryAccessArgs,
        list: String,
        #[arg(required = true)]
        images: Vec<String>,
    },

    #[command(about = "Set the platform and annotations of an instance, or of the list")]
    Annotate {
        #[command(flatten)]
        instance: InstanceArgs,
        /// The annotations are the list's
        #[arg(long)]
        index: bool,
        /// The subject of the list (an image of a registry, by digest)
        #[arg(long)]
        subject: Option<String>,
        list: String,
        /// The instance: its digest or an image of the store
        image: Option<String>,
    },

    #[command(about = "Show a manifest list, local or of a registry")]
    Inspect {
        /// Verify the TLS certificates of the registries
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1,
              require_equals = true, default_missing_value = "true")]
        tls_verify: bool,
        #[command(flatten)]
        access: RegistryAccessArgs,
        list: String,
    },

    #[command(about = "Push a manifest list (and its instances) to a registry")]
    Push {
        /// Push the instances too
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1,
              require_equals = true, default_missing_value = "true")]
        all: bool,
        /// Compression of the layers: zstd:chunked, gzip or none
        #[arg(long)]
        compression_format: Option<String>,
        /// The compression level of the layers compressed with
        /// --compression-format (gzip 0-9, zstd 1-20)
        #[arg(long)]
        compression_level: Option<i32>,
        /// Push each instance in this compression too, as an instance of its
        /// own (comma separated or repeated)
        #[arg(long, value_delimiter = ',')]
        add_compression: Vec<String>,
        /// Compress with --compression-format even a layer the registry has
        /// in another compression (always: velarx knows of no other variant
        /// of a layer)
        #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
        force_compression: Option<bool>,
        /// The manifest type of the list: oci, the only one
        #[arg(long, short = 'f')]
        format: Option<String>,
        /// Copy no signature (velarx pushes none)
        #[arg(long)]
        remove_signatures: bool,
        #[command(flatten)]
        signing: SigningArgs,
        /// The helper sinks of this push, in the order they are asked: names
        /// of `[[sinks.external]]`; the destination's own pusher always
        /// follows them, whatever the destination is, and is not named here
        #[arg(long, value_name = "NAME,...", value_delimiter = ',')]
        sinks: Option<Vec<String>>,
        /// Write the digest of the pushed list to this file
        #[arg(long)]
        digestfile: Option<std::path::PathBuf>,
        /// Print nothing
        #[arg(long, short)]
        quiet: bool,
        /// Remove the list after the push
        #[arg(long)]
        rm: bool,
        /// Verify the TLS certificates of the registry
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1,
              require_equals = true, default_missing_value = "true")]
        tls_verify: bool,
        #[command(flatten)]
        access: RegistryAccessArgs,
        list: String,
        /// Where to (the name of the list if none)
        destination: Option<String>,
    },

    #[command(name = "rm", about = "Remove manifest lists (not their instances)")]
    Rm {
        /// No error for a list that is not there
        #[arg(long, short)]
        ignore: bool,
        #[arg(required = true)]
        lists: Vec<String>,
    },

    #[command(about = "Remove an instance from a manifest list")]
    Remove { list: String, digest: String },

    #[command(about = "Check if a manifest list exists; the exit status says so")]
    Exists { list: String },
}

fn annotations(list: &[String]) -> anyhow::Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for a in list {
        let (k, v) = a
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("no value given for annotation `{a}`"))?;
        if k.is_empty() {
            anyhow::bail!("no key given for annotation `{a}`");
        }
        out.insert(k.to_string(), v.to_string());
    }
    Ok(out)
}

fn instance(args: &InstanceArgs, with_annotations: bool) -> anyhow::Result<InstanceOptions> {
    Ok(InstanceOptions {
        annotations: if with_annotations {
            annotations(&args.annotation)?
        } else {
            BTreeMap::new()
        },
        arch: args.arch.clone(),
        os: args.os.clone(),
        os_version: args.os_version.clone(),
        variant: args.variant.clone(),
        features: args.features.clone(),
        os_features: args.os_features.clone(),
    })
}

/// `access`: the credentials and certificates of the access flags for a
/// reference.
pub fn run(cmd: ManifestCommands, client: &EngineClient, access: &AccessFn) -> anyhow::Result<()> {
    match cmd {
        ManifestCommands::Create {
            all,
            amend,
            annotation,
            tls_verify,
            digest,
            list,
            images,
        } => {
            crate::cli::check_digest_flag(digest.as_deref()).map_err(anyhow::Error::msg)?;
            let req = ManifestRequest {
                images,
                all,
                amend,
                index_annotations: annotations(&annotation)?,
                tls_verify,
                algorithm: digest,
                ..Default::default()
            };
            println!("{}", client.manifest(&list, ManifestOp::Create, &req)?);
        }
        ManifestCommands::Add {
            all,
            artifact,
            instance: i,
            tls_verify,
            access,
            list,
            images,
        } if artifact.artifact => {
            if all {
                anyhow::bail!("--all is not supported with --artifact: the files are not images");
            }
            // (a subject of a registry with credentials would need
            // X-Registry-Auth, which this request does not send)
            for (name, given) in [
                ("--creds", access.creds.is_some()),
                ("--authfile", access.authfile.is_some()),
                ("--cert-dir", access.cert_dir.is_some()),
            ] {
                if given {
                    anyhow::bail!("{name} is not supported with --artifact");
                }
            }
            let config = match &artifact.artifact_config {
                Some(f) => std::fs::read_to_string(f)
                    .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", f.display()))?,
                None => String::new(),
            };
            let mut req = serde_json::json!({
                "operation": "update",
                "artifact_config": config,
                "artifact_config_type": artifact.artifact_config_type.unwrap_or_default(),
                "artifact_layer_type": artifact.artifact_layer_type.unwrap_or_default(),
                "artifact_exclude_titles": artifact.artifact_exclude_titles,
                "artifact_subject": artifact.artifact_subject.unwrap_or_default(),
                "annotations": annotations(&i.annotation)?,
                "arch": i.arch.unwrap_or_default(),
                "os": i.os.unwrap_or_default(),
                "os_version": i.os_version.unwrap_or_default(),
                "variant": i.variant.unwrap_or_default(),
                "features": i.features,
                "os_features": i.os_features,
            });
            if let Some(t) = artifact.artifact_type {
                req["artifact_type"] = serde_json::json!(t);
            }
            let files: Vec<std::path::PathBuf> = images.iter().map(Into::into).collect();
            println!(
                "{}",
                client.manifest_add_artifact(&list, &req, &files, tls_verify)?
            );
        }
        ManifestCommands::Add {
            all,
            artifact,
            instance: i,
            tls_verify,
            access: a,
            list,
            images,
        } => {
            match artifact.stray().as_slice() {
                [] => {}
                [one] => anyhow::bail!("{one} requires --artifact"),
                many => anyhow::bail!("{} require --artifact", many.join("/")),
            }
            let images = images
                .iter()
                .map(|image| match ImageLocation::parse(image)? {
                    ImageLocation::Registry(name) => Ok(name),
                    ImageLocation::Storage(name) => Ok(format!("containers-storage:{name}")),
                    other => Err(anyhow::anyhow!(
                        "the transport {} is not supported by manifest add: only containers-storage: and docker:// can be used",
                        other.transport().trim_end_matches(':')
                    )),
                })
                .collect::<anyhow::Result<Vec<String>>>()?;
            let req = ManifestRequest {
                images: images.clone(),
                all,
                instance: instance(&i, true)?,
                tls_verify,
                access: access(client, &a, images.first().map_or("", String::as_str), false)?,
                ..Default::default()
            };
            println!("{}", client.manifest(&list, ManifestOp::Add, &req)?);
        }
        ManifestCommands::Annotate {
            instance: i,
            index,
            subject,
            list,
            image,
        } => {
            if image.is_none() && !index {
                anyhow::bail!("give the instance to annotate, or --index for the list");
            }
            let req = ManifestRequest {
                images: if index {
                    Vec::new()
                } else {
                    image.into_iter().collect()
                },
                instance: instance(&i, !index)?,
                index_annotations: if index {
                    annotations(&i.annotation)?
                } else {
                    BTreeMap::new()
                },
                subject,
                ..Default::default()
            };
            println!("{}", client.manifest(&list, ManifestOp::Annotate, &req)?);
        }
        ManifestCommands::Inspect {
            tls_verify,
            access: a,
            list,
        } => {
            let req = ManifestRequest {
                tls_verify,
                access: access(client, &a, &list, false)?,
                ..Default::default()
            };
            let v = client.manifest_inspect(&list, &req)?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        ManifestCommands::Push {
            all,
            compression_format,
            compression_level,
            add_compression,
            force_compression: _,
            format,
            remove_signatures: _,
            signing,
            sinks,
            digestfile,
            quiet,
            rm,
            tls_verify,
            access: a,
            list,
            destination,
        } => {
            let sign = signing.spec("manifest push")?;
            let destination = destination
                .map(|d| match ImageLocation::external(&d)? {
                    // (a scheme of `[[transports]]`: its pusher takes it as written)
                    Some(_) => Ok(d),
                    None => ImageLocation::registry(&d, "manifest push"),
                })
                .transpose()?;
            let dest = destination.clone().unwrap_or_else(|| list.clone());
            if !quiet {
                println!("Pushing {list} to {dest}");
            }
            let req = ManifestRequest {
                all,
                destination,
                compression_format,
                compression_level,
                add_compression,
                format,
                sign,
                sinks,
                tls_verify,
                access: access(client, &a, &dest, true)?,
                ..Default::default()
            };
            let pushed = client.manifest_push(&list, &req)?;
            let digest = pushed.digest.as_str();
            // (a sha512 list pushed by a tag is put by its digest too: a
            // registry that refuses that is said, even with --quiet)
            if let Some(name) = crate::cli::pushed_by_digest_name(&dest, digest) {
                for line in crate::cli::refusal_warnings(&pushed.placed, &name) {
                    eprintln!("{line}");
                }
            }
            if let Some(f) = digestfile {
                std::fs::write(&f, digest)
                    .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", f.display()))?;
            }
            if rm {
                client.manifest_delete(&list)?;
            }
        }
        ManifestCommands::Rm { ignore, lists } => {
            let mut failed = None;
            crate::cli::run::each_item(
                lists,
                |l| {
                    let v = match client.manifest_delete(l) {
                        Err(e) if ignore && e.is_not_found() => return Ok(()),
                        r => r?,
                    };
                    for n in &v.names {
                        println!("Untagged: {n}");
                    }
                    println!("Deleted: {}", v.id);
                    Ok(())
                },
                |l, e| {
                    eprintln!("Error: {l}: {e}");
                    failed = Some(e);
                },
            )?;
            if let Some(e) = failed {
                return Err(e.into());
            }
        }
        ManifestCommands::Remove { list, digest } => {
            let req = ManifestRequest {
                digest: Some(digest),
                ..Default::default()
            };
            println!("{}", client.manifest(&list, ManifestOp::Remove, &req)?);
        }
        ManifestCommands::Exists { list } => {
            if !client.manifest_exists(&list)? {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_annotations() {
        let a = annotations(&["a=b".into(), "c=d=e".into(), "f=".into()]).unwrap();
        assert_eq!(a["a"], "b");
        assert_eq!(a["c"], "d=e");
        assert_eq!(a["f"], "");
        assert!(annotations(&["nokey".into()]).is_err());
        assert!(annotations(&["=v".into()]).is_err());
    }
}
