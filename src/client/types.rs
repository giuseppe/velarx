// SPDX-License-Identifier: Apache-2.0
use super::*;
use velarx_proto::workload::TransferStats;

/// How the engine pulls an image.
#[derive(Debug, Clone, Copy)]
pub struct PullOptions<'a> {
    /// Verify the TLS certificates of the registry (false also allows
    /// plain HTTP)
    pub tls_verify: bool,
    /// `OS/ARCH[/VARIANT]`
    pub platform: Option<&'a str>,
    /// Credentials and certificates of the client
    pub access: &'a RegistryAccess,
    /// How a pull that fails on the way is tried again
    pub retry: velarx_proto::retry::Retry,
    /// The fetchers of the pull, in the order they are asked (`--sources`);
    /// none: `[pull] sources`
    pub sources: Option<&'a [String]>,
}

/// How the engine pushes an image.
#[derive(Debug, Clone)]
pub struct PushImageRequest {
    /// Where to push; by default the name of the image
    pub destination: Option<String>,
    /// gzip, zstd:chunked or none; by default the layers keep theirs
    pub compression_format: Option<String>,
    /// The level of the layers compressed in `compression_format`
    pub compression_level: Option<i32>,
    /// Verify the TLS certificates of the registry (false also allows
    /// plain HTTP)
    pub tls_verify: bool,
    /// Credentials and certificates of the client
    pub access: RegistryAccess,
    /// How a push that fails on the way is tried again
    pub retry: velarx_proto::retry::Retry,
    /// Sign the manifests pushed with this key
    pub sign: Option<velarx_proto::workload::SigningKey>,
    /// The pushers of the push, in the order they are asked (`--sinks`);
    /// none: `[push] sinks`
    pub sinks: Option<Vec<String>>,
    /// `destination` is a path (`oci:`, `dir:`, `oci-archive:`): what this
    /// client opened for it, a directory or a file open for writing
    pub destination_fd: Option<std::sync::Arc<std::os::fd::OwnedFd>>,
}

/// What a pull pulled: podman's id of the image, and what the pull fetched
/// from where.
#[derive(Debug)]
pub struct PullResponse {
    pub id: String,
    pub stats: Option<TransferStats>,
}

#[derive(Debug, Serialize, serde::Deserialize)]
pub struct IdResponse {
    pub id: String,
}

/// The status of a command run in a container (its output went to the
/// writers of the call as it came).
#[derive(Debug, Default, Serialize, serde::Deserialize)]
pub struct ExecResponse {
    pub exit_code: i32,
    /// `--detach`: the ID of the exec session, as podman prints it
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session_id: String,
}

#[derive(Debug, Serialize, serde::Deserialize)]
pub struct PruneContainersResponse {
    pub containers_deleted: Vec<String>,
    pub space_reclaimed: u64,
}

/// A container started for a client that attaches (`ContainerAttach` with
/// `start`).
#[derive(Debug, Serialize, serde::Deserialize)]
pub struct StartedContainer {
    pub id: String,
}

/// A command to run in a container.
#[derive(Debug, Default, Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ExecParams {
    pub command: Vec<String>,
    pub env: Vec<String>,
    pub working_dir: Option<String>,
    pub user: Option<String>,
    pub tty: bool,
    pub privileged: bool,
    /// The command takes input
    pub stdin: bool,
    /// The keys that detach from a command with a terminal
    pub detach_keys: Option<String>,
    /// Kill the command after this many seconds
    pub timeout: Option<u64>,
    /// Do not wait for the command
    pub detach: bool,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(default)]
pub struct BuildImageRequest {
    /// Path to the Containerfile in the context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dockerfile: Option<String>,
    /// The Containerfile is not in the directory of the context: the
    /// client added it to the tar as `dockerfile`.
    pub containerfile_outside: bool,
    /// The Containerfile is an http(s) URL the engine fetches (`-f URL`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub containerfile_url: Option<String>,
    /// The context is a git repository or an URL the engine fetches: the
    /// upload is not read
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    /// Names for the built image
    pub tags: Vec<String>,
    pub build_args: std::collections::HashMap<String, String>,
    pub labels: std::collections::HashMap<String, String>,
    pub no_cache: bool,
    pub layers: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<String>,
    pub all_platforms: bool,
    pub squash: bool,
    pub squash_all: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// `--allow`: the entitlements the build is allowed to use.
    pub allow: Vec<velarx_base::entitlement::Entitlement>,
    /// `--digest`: `sha256` or `sha512`, the digests of everything the build
    /// makes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    pub tls_verify: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pull: Option<String>,
    pub access: velarx_registry::auth::RegistryAccess,
    /// The client answers the questions of the build for credentials (of
    /// its auth file), one for each reference the build pulls.
    pub ask_credentials: bool,
    /// What the RUN steps take from the command line.
    pub run: velarx_wire::request::BuildRun,
    /// `--env`, `--unsetenv`, `--unsetlabel`: the final image.
    pub env: Vec<(String, String)>,
    pub unset_env: Vec<String>,
    pub unset_labels: Vec<String>,
    /// `--secret`: the secrets of `RUN --mount=type=secret`.
    pub secrets: Vec<velarx_wire::buildopts::BuildSecret>,
    /// `--build-context`: the named contexts.
    pub contexts: Vec<velarx_wire::buildopts::NamedContextRequest>,
    /// `--ssh`: the ids of the agents of the client, in the order the
    /// broker the call carries numbers them.
    pub ssh: Vec<String>,
    /// `--stdin`: the standard input of the client is the one of the RUN
    /// steps (the call carries a descriptor of it).
    pub stdin: bool,
    /// `--from`, `--retry`, the times, `--omit-history`...
    pub flags: velarx_wire::buildopts::BuildFlags,
}

impl Default for BuildImageRequest {
    fn default() -> Self {
        Self {
            dockerfile: None,
            containerfile_outside: false,
            containerfile_url: None,
            remote: None,
            tags: Vec::new(),
            build_args: Default::default(),
            labels: Default::default(),
            no_cache: false,
            layers: true,
            target: None,
            platform: None,
            manifest: None,
            all_platforms: false,
            squash: false,
            squash_all: false,
            network: None,
            allow: Vec::new(),
            digest: None,
            tls_verify: true,
            pull: None,
            access: Default::default(),
            ask_credentials: false,
            run: Default::default(),
            env: Vec::new(),
            unset_env: Vec::new(),
            unset_labels: Vec::new(),
            secrets: Vec::new(),
            contexts: Vec::new(),
            ssh: Vec::new(),
            stdin: false,
            flags: Default::default(),
        }
    }
}

impl BuildImageRequest {
    /// The spec of the build the engine takes, and the credentials (they
    /// cross in a pipe of their own).
    pub fn to_spec(&self) -> velarx_proto::buildspec::BuildSpec {
        use base64::Engine as _;
        use velarx_base::entitlement::Entitlement;
        use velarx_proto::buildspec::{
            pairs, BuildClient, BuildContextKind, BuildContextSpec, BuildEntitlement, BuildPull,
            BuildSecretKind, BuildSecretSpec, BuildSpec,
        };
        use velarx_wire::buildopts::ContextSource;
        let pull = match self.pull.as_deref().filter(|p| !p.is_empty()) {
            None => BuildPull::Missing,
            Some(p) => BuildPull::parse(p).unwrap_or(BuildPull::Missing),
        };
        BuildSpec {
            client: BuildClient::Cli,
            tags: self.tags.clone(),
            build_args: pairs(self.build_args.clone()),
            labels: pairs(self.labels.clone()),
            no_cache: self.no_cache,
            layers: self.layers,
            target: self.target.clone(),
            platform: self.platform.clone(),
            manifest: self.manifest.clone(),
            all_platforms: self.all_platforms,
            squash: self.squash,
            squash_all: self.squash_all,
            network: self.network.clone(),
            allow: self
                .allow
                .iter()
                .map(|a| match a {
                    Entitlement::NetworkHost => BuildEntitlement::NetworkHost,
                    Entitlement::SecurityInsecure => BuildEntitlement::SecurityInsecure,
                })
                .collect(),
            digest: self.digest.clone(),
            tls_verify: self.tls_verify,
            pull,
            ask_credentials: self.ask_credentials,
            run: self.run.clone(),
            env: pairs(self.env.clone()),
            unset_env: self.unset_env.clone(),
            unset_labels: self.unset_labels.clone(),
            secrets: self
                .secrets
                .iter()
                .map(|s| BuildSecretSpec {
                    id: s.id.clone(),
                    kind: BuildSecretKind::Value,
                    source: base64::engine::general_purpose::STANDARD.encode(&s.value),
                })
                .collect(),
            contexts: self
                .contexts
                .iter()
                .map(|c| BuildContextSpec {
                    name: c.name.clone(),
                    kind: match &c.source {
                        ContextSource::Upload(_) => BuildContextKind::Upload,
                        ContextSource::Image(_) => BuildContextKind::Image,
                        ContextSource::Url(_) => BuildContextKind::Url,
                    },
                    source: match &c.source {
                        ContextSource::Upload(s)
                        | ContextSource::Image(s)
                        | ContextSource::Url(s) => s.clone(),
                    },
                })
                .collect(),
            ssh: self.ssh.clone(),
            stdin: self.stdin,
            flags: self.flags.clone(),
            containerfile: self.dockerfile.clone(),
            containerfile_outside: self.containerfile_outside,
            containerfile_url: self.containerfile_url.clone(),
            remote: self.remote.clone(),
            ..Default::default()
        }
    }

    /// The request of the command line a spec of its own is.
    pub fn from_spec(
        spec: velarx_proto::buildspec::BuildSpec,
        access: velarx_registry::auth::RegistryAccess,
    ) -> Result<Self, String> {
        use base64::Engine as _;
        use velarx_base::entitlement::Entitlement;
        use velarx_proto::buildspec::{
            unpair, BuildContextKind, BuildEntitlement, BuildPull, BuildSecretKind,
        };
        use velarx_wire::buildopts::{BuildSecret, ContextSource, NamedContextRequest};
        // (the command line uploads its context and writes its outputs
        // itself: what only the routes say is refused, not dropped)
        if spec.local_dir.is_some()
            || spec.containerfile_host.is_some()
            || spec.output.is_some()
            || spec.http_proxy
        {
            return Err(
                "a directory or a file of the host, outputs and the proxy of the engine are not the command line's".into(),
            );
        }
        let mut secrets = Vec::new();
        for s in spec.secrets {
            if s.kind != BuildSecretKind::Value {
                return Err(format!(
                    "the secret {}: only its value is the command line's",
                    s.id
                ));
            }
            let value = base64::engine::general_purpose::STANDARD
                .decode(s.source)
                .map_err(|_| format!("the secret {}: not base64", s.id))?;
            secrets.push(BuildSecret { id: s.id, value });
        }
        let mut contexts = Vec::new();
        for c in spec.contexts {
            let source = match c.kind {
                BuildContextKind::Upload => ContextSource::Upload(c.source),
                BuildContextKind::Image => ContextSource::Image(c.source),
                BuildContextKind::Url => ContextSource::Url(c.source),
                BuildContextKind::Host => {
                    return Err(format!(
                        "the build context {}: only the upload, an image or a URL are the command line's",
                        c.name
                    ))
                }
            };
            contexts.push(NamedContextRequest {
                name: c.name,
                source,
            });
        }
        let allow = spec
            .allow
            .into_iter()
            .map(|a| match a {
                BuildEntitlement::NetworkHost => Entitlement::NetworkHost,
                BuildEntitlement::SecurityInsecure => Entitlement::SecurityInsecure,
            })
            .collect();
        Ok(Self {
            dockerfile: spec.containerfile,
            containerfile_outside: spec.containerfile_outside,
            containerfile_url: spec.containerfile_url,
            remote: spec.remote,
            tags: spec.tags,
            build_args: unpair(spec.build_args).collect(),
            labels: unpair(spec.labels).collect(),
            no_cache: spec.no_cache,
            layers: spec.layers,
            target: spec.target,
            platform: spec.platform,
            manifest: spec.manifest,
            all_platforms: spec.all_platforms,
            squash: spec.squash,
            squash_all: spec.squash_all,
            network: spec.network,
            allow,
            digest: spec.digest,
            tls_verify: spec.tls_verify,
            pull: Some(
                match spec.pull {
                    BuildPull::Missing => "missing",
                    BuildPull::Always => "always",
                    BuildPull::Newer => "newer",
                    BuildPull::Never => "never",
                }
                .to_string(),
            ),
            access,
            ask_credentials: spec.ask_credentials,
            run: spec.run,
            env: unpair(spec.env).collect(),
            unset_env: spec.unset_env,
            unset_labels: spec.unset_labels,
            secrets,
            contexts,
            ssh: spec.ssh,
            stdin: spec.stdin,
            flags: spec.flags,
        })
    }
}

/// What `search` asks of the registries.
#[derive(Debug, Clone, Default)]
pub struct SearchRequest {
    /// `REGISTRY/TERM`, or a term for the unqualified-search registries
    pub term: String,
    /// The results of each registry (0: 25)
    pub limit: u32,
    /// `stars=N`, `is-official`, `is-automated`
    pub filters: Vec<String>,
    /// The tags of the repository `term` names instead
    pub list_tags: bool,
    /// None: what registries.conf says
    pub tls_verify: Option<bool>,
    pub access: RegistryAccess,
}

pub use velarx_proto::engine::SearchHit;

#[derive(Debug, Clone, Default)]
pub struct CommitContainerRequest {
    /// Container ID or name
    pub container: String,
    /// Image name (repository[:tag])
    pub image: Option<String>,
    /// Author name
    pub author: Option<String>,
    /// Commit message
    pub message: Option<String>,
    /// Dockerfile instructions to apply
    pub changes: Vec<String>,
    /// Pause container during commit
    pub pause: bool,
    /// `sha256` or `sha512`: the digests of the new image (none: those of
    /// the image of the container)
    pub digest: Option<String>,
    /// Add the volumes of the container to the configuration
    pub include_volumes: bool,
    /// One layer for the whole image, those of its base too
    pub squash: bool,
    /// Settings merged into the configuration of the image (a Docker
    /// container config, `commit --config`)
    pub override_config: Option<serde_json::Value>,
}

/// A changed path: `Kind` is 0 (changed), 1 (added) or 2 (deleted).
#[derive(Debug, Serialize, serde::Deserialize)]
pub struct FileChange {
    #[serde(rename = "Path")]
    pub path: String,
    #[serde(rename = "Kind")]
    pub kind: u8,
}

impl FileChange {
    /// The letter `podman diff` shows.
    pub fn letter(&self) -> char {
        match self.kind {
            0 => 'C',
            1 => 'A',
            _ => 'D',
        }
    }
}

/// podman's stat of a path of a container.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ArchiveStat {
    #[serde(rename = "linkTarget", default)]
    pub link_target: String,
    #[serde(rename = "isDir", default)]
    pub is_dir: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The remote build of the command line crosses as a spec: what it
    /// asks survives the way there and back.
    #[test]
    fn a_build_of_the_command_line_survives_its_spec() {
        use velarx_wire::buildopts::{BuildSecret, ContextSource, NamedContextRequest};
        let req = BuildImageRequest {
            dockerfile: Some("sub/Containerfile".into()),
            containerfile_outside: true,
            containerfile_url: Some("https://example.invalid/Containerfile".into()),
            remote: Some("https://example.invalid/r.git#main:sub".into()),
            tags: vec!["localhost/a:1".into()],
            build_args: [("A".to_string(), "1".to_string())].into(),
            labels: [("l".to_string(), "v".to_string())].into(),
            no_cache: true,
            layers: false,
            target: Some("t".into()),
            platform: Some("linux/amd64,linux/arm64".into()),
            manifest: Some("localhost/list".into()),
            all_platforms: true,
            squash: true,
            squash_all: true,
            network: Some("host".into()),
            allow: velarx_base::entitlement::Entitlement::ALL.to_vec(),
            digest: Some("sha512".into()),
            tls_verify: false,
            pull: Some("never".into()),
            access: Default::default(),
            ask_credentials: true,
            run: velarx_wire::request::BuildRun {
                volumes: vec!["/a:/b".into()],
                no_hosts: true,
                ..Default::default()
            },
            env: vec![("E".into(), "1".into())],
            unset_env: vec!["U".into()],
            unset_labels: vec!["L".into()],
            secrets: vec![BuildSecret {
                id: "s".into(),
                value: b"\x00hunter2".to_vec(),
            }],
            contexts: vec![
                NamedContextRequest {
                    name: "u".into(),
                    source: ContextSource::Upload("u".into()),
                },
                NamedContextRequest {
                    name: "i".into(),
                    source: ContextSource::Image("alpine".into()),
                },
                NamedContextRequest {
                    name: "r".into(),
                    source: ContextSource::Url("https://example.invalid/x.tar".into()),
                },
            ],
            ssh: vec!["default".into()],
            stdin: true,
            flags: velarx_wire::buildopts::BuildFlags {
                timestamp: Some(1),
                annotations: vec!["k=v".into()],
                ..Default::default()
            },
        };
        let spec = req.to_spec();
        let text = serde_json::to_string(&spec).unwrap();
        assert!(!text.contains("hunter2"), "{text}");
        let back =
            BuildImageRequest::from_spec(serde_json::from_str(&text).unwrap(), Default::default())
                .unwrap();
        assert_eq!(
            serde_json::to_value(&back).unwrap(),
            serde_json::to_value(&req).unwrap()
        );
    }

    /// What only the routes say is refused, not dropped.
    #[test]
    fn a_spec_of_the_routes_is_not_one_of_the_command_line() {
        use velarx_proto::buildspec::{BuildOutput, BuildOutputKind, BuildSpec};
        for spec in [
            BuildSpec {
                local_dir: Some("/".into()),
                ..Default::default()
            },
            BuildSpec {
                containerfile_host: Some("/etc/passwd".into()),
                ..Default::default()
            },
            BuildSpec {
                output: Some(BuildOutput {
                    kind: BuildOutputKind::Dir,
                    path: "/o".into(),
                }),
                ..Default::default()
            },
            BuildSpec {
                http_proxy: true,
                ..Default::default()
            },
        ] {
            assert!(BuildImageRequest::from_spec(spec, Default::default()).is_err());
        }
        assert!(BuildImageRequest::from_spec(BuildSpec::default(), Default::default()).is_ok());
        // (an entitlement is one of those velarx has)
        assert!(serde_json::from_str::<BuildSpec>(r#"{"allow":["network_host"]}"#).is_ok());
        assert!(serde_json::from_str::<BuildSpec>(r#"{"allow":["device"]}"#).is_err());
    }
}
