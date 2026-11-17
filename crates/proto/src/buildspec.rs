// SPDX-License-Identifier: Apache-2.0
//! What a build is asked: the options of a build that are not those of its
//! RUN containers ([`BuildFlags`], [`SbomFlags`]) and the document a frontend
//! sends to the engine to have an image built ([`BuildSpec`]).

use crate::request::BuildRun;
use crate::retry::Retry;
use serde::{Deserialize, Serialize};

/// What the SBOM options of a build say.
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SbomFlags {
    /// `--sbom`: a preset of a scanner image, commands and merge strategy.
    pub preset: Option<String>,
    /// `--sbom-scanner-image`
    pub scanner_image: Option<String>,
    /// `--sbom-scanner-command`, in order.
    pub scanner_commands: Vec<String>,
    /// `--sbom-merge-strategy`
    pub merge_strategy: Option<String>,
    /// `--sbom-output`: a file of the host.
    pub output: Option<String>,
    /// `--sbom-purl-output`: a file of the host.
    pub purl_output: Option<String>,
    /// `--sbom-image-output`: a path in the built image.
    pub image_output: Option<String>,
    /// `--sbom-image-purl-output`: a path in the built image.
    pub image_purl_output: Option<String>,
}

impl SbomFlags {
    /// Whether any SBOM option is given.
    pub fn given(&self) -> bool {
        *self != Self::default()
    }
}

/// The options of a build that are not those of its RUN containers.
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BuildFlags {
    /// `--from`: the image of the first FROM.
    pub from: Option<String>,
    /// `--retry`, `--retry-delay`: how a failed pull of a base image is
    /// tried again.
    pub retry: Retry,
    /// `--timestamp`: the time of the image, its history and the files of
    /// its new layers (seconds since the epoch).
    pub timestamp: Option<i64>,
    /// `--source-date-epoch`: the time of the image and its history (and
    /// the build argument SOURCE_DATE_EPOCH).
    pub source_date_epoch: Option<i64>,
    /// With `source_date_epoch`: no file of a new layer is newer.
    pub rewrite_timestamp: bool,
    /// `--omit-history`: the image has no history.
    pub omit_history: bool,
    /// `--inherit-labels=false`: a stage does not keep the labels of its
    /// base.
    pub inherit_labels: bool,
    /// `--skip-unused-stages=false`: every stage before the target is
    /// built, those it does not use too.
    pub skip_unused_stages: bool,
    /// `--jobs`: how many independent stages run at the same time (0: as
    /// many as there are).
    pub jobs: u32,
    /// `--cache-ttl`: the images of the build cache made longer ago (in
    /// milliseconds) are not used.
    pub cache_ttl_ms: Option<u64>,
    /// `--annotation`: annotations of the manifest of the image.
    pub annotations: Vec<BuildPair>,
    /// `--unsetannotation`: annotations the image does not have.
    pub unset_annotations: Vec<String>,
    /// `--inherit-annotations=false`: the image does not keep the
    /// annotations of its base, nor names it in them.
    pub inherit_annotations: bool,
    /// `--created-annotation=false`: no `org.opencontainers.image.created`.
    pub created_annotation: bool,
    /// `--os-version`: the `os.version` of the configuration of the image.
    pub os_version: Option<String>,
    /// `--os-feature`: the `os.features` of the configuration of the image.
    pub os_features: Vec<String>,
    /// `--http-proxy`: the proxy variables of the client in the RUN
    /// containers, not in the image nor in the build cache.
    pub proxy_env: Vec<BuildPair>,
    /// `--compat-volumes`: the RUN steps mount the VOLUMEs of the image
    /// (anonymous volumes), so that what they write there is discarded,
    /// as Docker's builder does; else, as buildah, they see the directory
    /// of the image and keep what they write.
    pub compat_volumes: bool,
    /// `--identity-label`: absent is the default (the label that names the
    /// builder unless a time is fixed with `timestamp` or
    /// `source_date_epoch`), `true` always, `false` never.
    pub identity_label: Option<bool>,
    /// `--cache-from`: repositories whose images are taken as the result of
    /// a step when they have one for its key.
    pub cache_from: Vec<String>,
    /// `--cache-to`: repositories the image of every new step is pushed to.
    pub cache_to: Vec<String>,
    /// `--layer-label`: labels of the intermediate images (not
    /// of the last image of a stage).
    pub layer_labels: Vec<BuildPair>,
    /// The SBOM options.
    pub sbom: SbomFlags,
}

impl Default for BuildFlags {
    fn default() -> Self {
        Self {
            from: None,
            retry: Retry::default(),
            timestamp: None,
            source_date_epoch: None,
            rewrite_timestamp: false,
            omit_history: false,
            inherit_labels: true,
            skip_unused_stages: true,
            jobs: 1,
            cache_ttl_ms: None,
            annotations: Vec::new(),
            unset_annotations: Vec::new(),
            inherit_annotations: true,
            created_annotation: true,
            os_version: None,
            os_features: Vec::new(),
            proxy_env: Vec::new(),
            compat_volumes: false,
            identity_label: None,
            cache_from: Vec::new(),
            cache_to: Vec::new(),
            layer_labels: Vec::new(),
            sbom: Default::default(),
        }
    }
}

impl BuildFlags {
    pub fn cache_ttl(&self) -> Option<std::time::Duration> {
        self.cache_ttl_ms.map(std::time::Duration::from_millis)
    }

    /// Whether the images carry the label that names the builder.
    pub fn identity(&self) -> bool {
        self.identity_label
            .unwrap_or(self.timestamp.is_none() && self.source_date_epoch.is_none())
    }
}

/// Who a build is for: the shape of the progress it answers, and what a
/// name or an option means when the client does not say.
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildClient {
    /// The command line of velarx (its build goes on when the reader of
    /// its progress goes)
    #[default]
    Cli,
    /// podman's libpod routes
    Libpod,
    /// Docker's classic builder, its defaults and messages
    Docker,
}

/// What a build step may ask for that is off unless it is allowed
/// (`--allow`).
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildEntitlement {
    /// The steps share the network namespace of the host
    NetworkHost,
    /// `RUN --security=insecure`: the step runs as a privileged container
    SecurityInsecure,
}

/// When a build pulls its base images.
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildPull {
    /// When the store does not have them
    #[default]
    Missing,
    /// Every time
    Always,
    /// When the registry serves another image than the store has
    Newer,
    /// Never: they must be in the store
    Never,
}

impl BuildPull {
    /// `missing`, `always`, `newer`, `never` and the words buildah uses for
    /// them: `true` is `always` and `false` is `never`.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "missing" | "ifmissing" | "notpresent" => Some(Self::Missing),
            "always" | "true" => Some(Self::Always),
            "newer" | "ifnewer" => Some(Self::Newer),
            "never" | "false" => Some(Self::Never),
            _ => None,
        }
    }
}

/// A name and its value: an argument, a label, a variable.  The lists of
/// them keep the order and the repeated names the user gave (the last of a
/// name wins where a map is wanted).
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildPair {
    pub name: String,
    pub value: String,
}

impl BuildPair {
    /// `NAME=VALUE` (`NAME` alone: an empty value, as buildah's).
    pub fn parse(text: &str) -> Self {
        let (name, value) = text.split_once('=').unwrap_or((text, ""));
        Self {
            name: name.to_string(),
            value: value.to_string(),
        }
    }
}

/// The pairs of a list as the records of a spec.
pub fn pairs(list: impl IntoIterator<Item = (String, String)>) -> Vec<BuildPair> {
    list.into_iter()
        .map(|(name, value)| BuildPair { name, value })
        .collect()
}

/// The records of a spec as pairs, in their order.
pub fn unpair(list: Vec<BuildPair>) -> impl Iterator<Item = (String, String)> {
    list.into_iter().map(|p| (p.name, p.value))
}

impl From<&str> for BuildPair {
    fn from(text: &str) -> Self {
        Self::parse(text)
    }
}

/// Where the value of a secret of a build is.
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildSecretKind {
    /// The bytes themselves (base64), as the command line sends them
    #[default]
    Value,
    /// A file at the top of the context, taken out of it
    ContextFile,
    /// A file of the host of the engine (the local build)
    HostFile,
}

/// A secret of a build, for `RUN --mount=type=secret`.  Its value is never
/// printed.
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildSecretSpec {
    pub id: String,
    pub kind: BuildSecretKind,
    /// The value (base64), or the name of the file
    pub source: String,
}

impl std::fmt::Debug for BuildSecretSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuildSecretSpec")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("source", &"<redacted>")
            .finish()
    }
}

/// Where a named context (`--build-context`) of a build is.
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildContextKind {
    /// An image
    #[default]
    Image,
    /// A git repository or the URL of a tar
    Url,
    /// A directory the client put at the top of the upload, under this name
    Upload,
    /// A directory of the host of the engine (the local build)
    Host,
}

/// A named context of a build (`--build-context NAME=SOURCE`).
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildContextSpec {
    pub name: String,
    pub kind: BuildContextKind,
    /// The image, the URL, the name in the upload, the path
    pub source: String,
}

/// Where the files of the image go (`outputs`).
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildOutputKind {
    /// Extracted into a directory of the host of the engine
    #[default]
    Dir,
    /// A tar, in a file of the host of the engine
    Tar,
}

/// What a build does with the files of the image (`--output`).
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildOutput {
    pub kind: BuildOutputKind,
    pub path: String,
}

/// What a build tells as it goes: the lines of the pipe `ImageBuild` answers
/// with, one JSON document of this type each line.
/// The last of them is `complete` or `error`; podman's and Docker's clients
/// are told neither `started` nor `progress` (their answers show neither).
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct BuildEvent {
    pub kind: BuildEventKind,
    /// The number of the step (`step`, `output`); the number of steps
    /// (`started`)
    #[serde(skip_serializing_if = "is_zero")]
    pub step: u64,
    /// The instruction (`step`), the text (`output`), the id of the image
    /// (`complete`), why the build failed (`error`)
    #[serde(skip_serializing_if = "String::is_empty")]
    pub text: String,
    /// What the text of an `output` is
    pub stream: BuildStream,
    /// The progress of a blob (`progress`): a base image pulled, the image
    /// committed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<crate::workload::TransferProgress>,
    /// The number of the question for credentials (`credentials`), to be
    /// answered with `ImageBuildAnswer`
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ask: String,
    /// The registries (`REGISTRY` or `REGISTRY/REPOSITORY`) the question is
    /// about (`credentials`)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    /// The names the image got (`complete`), qualified (for podman's and
    /// Docker's clients: the command line has its own)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// What a build event is.
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildEventKind {
    /// The build starts; `step` is the number of its steps
    #[default]
    Started,
    /// A step starts
    Step,
    /// What the build or a step says
    Output,
    /// A blob moves
    Progress,
    /// The build for a platform of several starts (`text`)
    Platform,
    /// The build asks for credentials
    Credentials,
    /// The image is built
    Complete,
    /// The build failed
    Error,
}

/// What the text of an `output` event is.
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildStream {
    /// What the build says of a step
    #[default]
    Step,
    /// What a RUN writes to its standard output
    Stdout,
    /// What a RUN writes to its standard error
    Stderr,
    /// The pulls of the bases
    Report,
}

/// What an image is built from and how: the document `ImageBuild` carries.  The frontend decodes its client's request into
/// it (the other options of the request it refuses by their names).
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BuildSpec {
    pub client: BuildClient,
    /// Only the id of the image in the progress
    pub quiet: bool,
    /// The names of the image, as the client wrote them
    pub tags: Vec<String>,
    pub build_args: Vec<BuildPair>,
    pub labels: Vec<BuildPair>,
    pub no_cache: bool,
    pub layers: bool,
    pub target: Option<String>,
    pub platform: Option<String>,
    pub manifest: Option<String>,
    pub all_platforms: bool,
    pub squash: bool,
    pub squash_all: bool,
    /// `none`, `host` or the name of a network
    pub network: Option<String>,
    /// The entitlements the build is allowed to use (the command line's;
    /// for the others the configuration decides)
    pub allow: Vec<BuildEntitlement>,
    /// `sha256` or `sha512`: the algorithm of the digests of everything the
    /// build makes (none: the engine's `[build] digest`)
    pub digest: Option<String>,
    pub tls_verify: bool,
    pub pull: BuildPull,
    /// The client answers the questions of the build for credentials
    pub ask_credentials: bool,
    /// What the RUN steps take
    pub run: BuildRun,
    /// `--env`: environment variables of the final image
    pub env: Vec<BuildPair>,
    /// `--unsetenv`: environment variables the final image does not have
    pub unset_env: Vec<String>,
    /// `--unsetlabel`: labels the final image does not have
    pub unset_labels: Vec<String>,
    pub secrets: Vec<BuildSecretSpec>,
    pub contexts: Vec<BuildContextSpec>,
    /// The ids of the agents of the client, in the order of its broker
    pub ssh: Vec<String>,
    /// The call carries the standard input of the client, which the RUN
    /// steps read (`--stdin`): the command line's
    pub stdin: bool,
    pub flags: BuildFlags,
    /// The proxy variables of the engine's environment are in the RUN
    /// containers
    pub http_proxy: bool,
    /// The Containerfile: a path in the context, never outside of it
    pub containerfile: Option<String>,
    /// The Containerfile is a file of the host of the engine (the local
    /// build)
    pub containerfile_host: Option<String>,
    /// The Containerfile is not in the directory of the context: the client
    /// put it in the upload as `dockerfile`
    pub containerfile_outside: bool,
    /// The Containerfile is an http(s) URL the engine fetches (`-f URL`)
    pub containerfile_url: Option<String>,
    /// The context is a git repository or the URL of a tar, not the upload
    pub remote: Option<String>,
    /// The context is a directory of the host of the engine
    pub local_dir: Option<String>,
    pub output: Option<BuildOutput>,
}

/// `--output`: `DIR`, `type=local,dest=DIR`, `type=tar,dest=FILE`; `-` is the
/// standard output of the command line, which has no meaning here.
pub fn parse_output(spec: &str) -> Result<Option<BuildOutput>, String> {
    if spec == "-" {
        return Ok(None);
    }
    let output = |kind, path: &str| {
        Some(BuildOutput {
            kind,
            path: path.to_string(),
        })
    };
    if !spec.contains('=') {
        return Ok(output(BuildOutputKind::Dir, spec));
    }
    let (mut kind, mut dest) = (None, None);
    for token in spec.split(',') {
        match token.split_once('=') {
            Some(("type", v)) => kind = Some(v),
            Some(("dest", v)) => dest = Some(v),
            _ => {
                return Err(format!(
                    "invalid --output `{spec}`: type=local|tar,dest=PATH"
                ))
            }
        }
    }
    let dest = dest
        .filter(|d| !d.is_empty())
        .ok_or_else(|| format!("--output `{spec}` needs a dest"))?;
    match kind.unwrap_or("local") {
        "local" => Ok(output(BuildOutputKind::Dir, dest)),
        "tar" if dest == "-" => Ok(None),
        "tar" => Ok(output(BuildOutputKind::Tar, dest)),
        t => Err(format!(
            "failed to parse build output {spec:?}: invalid type {t:?} selected for build output options {spec:?}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outputs_as_buildah_reads_them() {
        assert_eq!(parse_output("-"), Ok(None));
        let out = |kind, path: &str| {
            Some(BuildOutput {
                kind,
                path: path.into(),
            })
        };
        assert_eq!(parse_output("/o"), Ok(out(BuildOutputKind::Dir, "/o")));
        assert_eq!(
            parse_output("type=tar,dest=/o.tar"),
            Ok(out(BuildOutputKind::Tar, "/o.tar"))
        );
        assert_eq!(parse_output("type=tar,dest=-"), Ok(None));
        assert!(parse_output("type=oci,dest=/x")
            .unwrap_err()
            .contains("invalid type"));
        assert!(parse_output("type=tar")
            .unwrap_err()
            .contains("needs a dest"));
        assert!(parse_output("x=y").is_err());
    }

    #[test]
    fn a_spec_survives_its_document() {
        let spec = BuildSpec {
            client: BuildClient::Libpod,
            tags: vec!["localhost/a:b".into()],
            layers: true,
            pull: BuildPull::Never,
            secrets: vec![BuildSecretSpec {
                id: "s".into(),
                kind: BuildSecretKind::ContextFile,
                source: "f".into(),
            }],
            contexts: vec![BuildContextSpec {
                name: "n".into(),
                kind: BuildContextKind::Upload,
                source: "n".into(),
            }],
            env: vec![
                BuildPair {
                    name: "A".into(),
                    value: "1".into(),
                },
                BuildPair {
                    name: "A".into(),
                    value: "2".into(),
                },
            ],
            output: Some(BuildOutput {
                kind: BuildOutputKind::Dir,
                path: "/o".into(),
            }),
            ..Default::default()
        };
        let text = serde_json::to_string(&spec).unwrap();
        let back = serde_json::from_str::<BuildSpec>(&text).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), text);
        // (no value of a secret in a debug print)
        let secret = BuildSecretSpec {
            id: "s".into(),
            kind: BuildSecretKind::Value,
            source: "aHVudGVyMg==".into(),
        };
        assert!(!format!("{secret:?}").contains("aHVudGVyMg"));
        assert_eq!(BuildPull::parse("newer"), Some(BuildPull::Newer));
        // (one job unless asked: a spec of a client that has no `jobs`)
        assert_eq!(serde_json::from_str::<BuildFlags>("{}").unwrap().jobs, 1);
        assert_eq!(BuildPull::parse("false"), Some(BuildPull::Never));
        assert_eq!(BuildPull::parse("true"), Some(BuildPull::Always));
        assert_eq!(BuildPull::parse("notpresent"), Some(BuildPull::Missing));
        assert_eq!(BuildPull::parse("x"), None);
    }
}
