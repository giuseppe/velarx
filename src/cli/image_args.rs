// SPDX-License-Identifier: Apache-2.0
use super::*;

#[derive(Subcommand, Clone)]
#[allow(
    clippy::large_enum_variant,
    reason = "parsed once into one value; boxing a clap variant means a struct of its own for each"
)]
pub enum ImageCommands {
    #[command(about = "Pull an image from a registry")]
    Pull {
        /// Platform (OS/ARCH[/VARIANT]) of the image to pull from an index
        #[arg(long)]
        platform: Option<String>,
        /// The OS of the image to pull from an index (with --arch, --variant)
        #[arg(long)]
        os: Option<String>,
        /// The architecture of the image to pull from an index
        #[arg(long)]
        arch: Option<String>,
        /// The variant of the architecture of the image to pull
        #[arg(long)]
        variant: Option<String>,
        /// always (the default), missing, never or newer
        #[arg(long, default_value = "always", value_parser = parse_pull_policy)]
        policy: PullPolicy,
        /// How many times a failed pull is tried again (default 3)
        #[arg(long, value_name = "N")]
        retry: Option<u32>,
        /// The time between the tries of --retry (default: 1s)
        #[arg(long, value_name = "DURATION")]
        retry_delay: Option<String>,
        /// Pull all tagged images in the repository
        #[arg(long, short = 'a')]
        all_tags: bool,
        /// Print the ID of the image alone, no progress
        #[arg(long, short)]
        quiet: bool,
        /// Refused: velarx pulls no encrypted image
        #[arg(long, hide = true)]
        decryption_key: Vec<String>,
        /// A Docker option with no effect (as in podman)
        #[arg(long, hide = true, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
        disable_content_trust: Option<bool>,
        /// Pull metadata only (TOC + manifest), fetch files on-demand when accessed
        #[arg(long)]
        lazy: bool,
        /// The fetchers of this pull, in the order they are asked: names of
        /// `[[sources.external]]` and `registry`; the default is `registry`
        /// alone, a list without it never asks the registry and cannot pull
        /// a tag (the files a lazy pull fetches later come from `[pull]
        /// sources`)
        #[arg(long, value_name = "NAME,...", value_delimiter = ',')]
        sources: Option<Vec<String>>,
        /// Verify the TLS certificates of the registry; `--tls-verify=false`
        /// also accepts plain HTTP
        #[arg(
            long,
            default_value_t = true,
            action = clap::ArgAction::Set,
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "true"
        )]
        tls_verify: bool,
        #[command(flatten)]
        access: RegistryAccessArgs,
        /// The images, one after the other (a failure is said, the next goes on)
        #[arg(required = true)]
        image: Vec<String>,
    },

    #[command(about = "Commit container changes to a new image")]
    Commit {
        /// Author name (e.g., "John Doe <john@example.com>")
        #[arg(long, short)]
        author: Option<String>,
        /// Commit message
        #[arg(long, short)]
        message: Option<String>,
        /// Apply Dockerfile instructions to the created image
        #[arg(long, short)]
        change: Vec<String>,
        /// Merge the configuration in this JSON file into that of the image
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
        /// Pause the container during the commit
        #[arg(long, short)]
        pause: bool,
        /// Image format: oci (Docker formats are not supported)
        #[arg(long, short, default_value = "oci")]
        format: String,
        /// Algorithm of the digests of the new image: sha256 or sha512 (default: that of
        /// the image of the container)
        #[arg(long, value_name = "ALGORITHM")]
        digest: Option<String>,
        /// Add the volumes of the container to the image configuration
        #[arg(long)]
        include_volumes: bool,
        /// Squash all the layers of the image, those of its base too, into one new layer
        #[arg(long, short = 's')]
        squash: bool,
        /// Write the image id to this file
        #[arg(long)]
        iidfile: Option<PathBuf>,
        /// Print the image id only
        #[arg(long, short)]
        quiet: bool,
        /// Container ID or name
        container: String,
        /// Image name (repository[:tag])
        image: Option<String>,
    },

    #[command(about = "Show the changes of an image against its parent layer")]
    Diff {
        /// `json`: {"changed": [...], "added": [...], "deleted": [...]}
        #[arg(long)]
        format: Option<String>,
        /// Image name or ID
        image: String,
    },

    #[command(about = "Build an image from a Dockerfile/Containerfile")]
    Build {
        /// Name and optionally a tag in the 'name:tag' format (repeatable)
        #[arg(long, short)]
        tag: Vec<String>,
        /// The Containerfile (default: Containerfile or Dockerfile of the context); given again, the files are joined into one; - is the standard input, a pipe (<(...)) is read as it
        #[arg(long, short)]
        file: Vec<PathBuf>,
        /// Set build-time variables: NAME=VALUE, or NAME for the value of the environment
        #[arg(long)]
        build_arg: Vec<String>,
        /// Set metadata for an image
        #[arg(long)]
        label: Vec<String>,
        /// Do not use cache when building the image
        #[arg(long)]
        no_cache: bool,
        /// Keep the intermediate images and use them as the build cache
        #[arg(
            long,
            default_value_t = true,
            action = clap::ArgAction::Set,
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "true"
        )]
        layers: bool,
        /// Remove intermediate containers after a successful build (always
        /// done: `--rm=false` is refused)
        #[arg(
            long,
            default_value_t = true,
            action = clap::ArgAction::Set,
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "true"
        )]
        rm: bool,
        /// Always remove intermediate containers
        #[arg(long)]
        force_rm: bool,
        /// Set the target build stage to build
        #[arg(long)]
        target: Option<String>,
        /// Set the target platform for the build (several, comma separated
        /// or repeated: an image for each)
        #[arg(long, value_delimiter = ',')]
        platform: Vec<String>,
        /// The OS of the image to build (with --arch, --variant)
        #[arg(long)]
        os: Option<String>,
        /// The architecture of the image to build
        #[arg(long)]
        arch: Option<String>,
        /// The variant of the architecture of the image to build
        #[arg(long)]
        variant: Option<String>,
        /// The ignore file of the context (default: its .containerignore or
        /// .dockerignore)
        #[arg(long)]
        ignorefile: Option<PathBuf>,
        #[command(flatten)]
        extra: BuildExtra,
        #[command(flatten)]
        unsupported: BuildUnsupported,
        /// Add the image to this manifest list, created if missing
        #[arg(long)]
        manifest: Option<String>,
        /// Build for every platform all the base images have
        #[arg(long, conflicts_with = "platform")]
        all_platforms: bool,
        /// Squash the new layers of the last stage into one on its base
        #[arg(long)]
        squash: bool,
        /// Squash all the layers, the base image's too, into one
        #[arg(long)]
        squash_all: bool,
        /// The network of the RUN steps: none, host, private, bridge, pasta[:OPTIONS], ns:PATH
        /// or the name of a network (host and ns:PATH need --allow network.host)
        #[arg(long)]
        network: Option<String>,
        /// Algorithm of the digests of everything the build makes (layers, configuration,
        /// manifest): sha256 or sha512 (default: [build] digest, else sha256)
        #[arg(long, value_name = "ALGORITHM")]
        digest: Option<String>,
        /// Verify the TLS certificates of the registries of the base images
        #[arg(
            long,
            default_value_t = true,
            action = clap::ArgAction::Set,
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "true"
        )]
        tls_verify: bool,
        /// When to pull the base images: missing, always, never or newer
        #[arg(
            long,
            default_value = "missing",
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "always"
        )]
        pull: String,
        #[command(flatten)]
        access: RegistryAccessArgs,
        /// Write the image id to this file
        #[arg(long)]
        iidfile: Option<PathBuf>,
        /// Suppress the build output
        #[arg(long, short)]
        quiet: bool,
        /// Build context directory (default: current directory)
        #[arg(default_value = ".")]
        context: PathBuf,
    },

    #[command(about = "List images", alias = "ls")]
    List {
        #[arg(long, short)]
        all: bool,
        #[command(flatten)]
        out: report::ListOutput,
        #[command(flatten)]
        args: report::ImagesArgs,
    },

    #[command(about = "Remove an image", alias = "rm")]
    Remove {
        /// Remove the containers that use the image; an image that is not
        /// there is no error
        #[arg(long, short)]
        force: bool,
        /// Remove every image
        #[arg(long, short)]
        all: bool,
        /// Do not fail on an image that is not there
        #[arg(long, short)]
        ignore: bool,
        /// Do not delete the untagged parents (velarx has none to keep)
        #[arg(long)]
        no_prune: bool,
        images: Vec<String>,
    },

    #[command(about = "Check if an image exists (exit 0) or not (exit 1)")]
    Exists { image: String },

    #[command(about = "Show the history of an image")]
    History {
        /// Sizes and times for humans
        #[arg(long, short = 'H', default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
        human: bool,
        #[command(flatten)]
        out: report::ListOutput,
        image: String,
    },

    #[command(about = "Show image details")]
    Inspect {
        /// Go template of each image, or `json`
        #[arg(long, short)]
        format: Option<String>,
        #[arg(required = true)]
        images: Vec<String>,
    },

    #[command(about = "Tag an image")]
    Tag {
        source: String,
        #[arg(required = true)]
        targets: Vec<String>,
    },

    #[command(about = "Remove names from an image (all of them without a name)")]
    Untag { image: String, names: Vec<String> },

    #[command(about = "Push an image to a registry")]
    Push {
        /// Image to push (e.g., docker.io/library/myimage:tag)
        image: String,
        /// Where to push it; by default the name of the image
        destination: Option<String>,
        /// Push all tagged images in the repository
        #[arg(long)]
        all_tags: bool,
        /// No progress
        #[arg(long, short)]
        quiet: bool,
        /// Compression of the layers that are uploaded: gzip, zstd:chunked
        /// or none (by default each layer keeps its own)
        #[arg(long)]
        compression_format: Option<String>,
        /// The compression level of the layers compressed with
        /// --compression-format (gzip 0-9, zstd 1-20)
        #[arg(long)]
        compression_level: Option<i32>,
        /// Compress with --compression-format even a layer the registry has
        /// in another compression (always: velarx knows of no other variant
        /// of a layer)
        #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
        force_compression: Option<bool>,
        /// Compress the layers of a dir: destination (gzip)
        #[arg(long)]
        compress: bool,
        /// The helper sinks of this push, in the order they are asked: names
        /// of `[[sinks.external]]`; the destination's own pusher always
        /// follows them, whatever the destination is, and is not named here
        #[arg(long, value_name = "NAME,...", value_delimiter = ',')]
        sinks: Option<Vec<String>>,
        /// The manifest type of the pushed image: oci, the only one
        #[arg(long, short = 'f')]
        format: Option<String>,
        /// Write the digest of the pushed image to this file
        #[arg(long)]
        digestfile: Option<PathBuf>,
        /// How many times a failed push is tried again (default 3)
        #[arg(long, value_name = "N")]
        retry: Option<u32>,
        /// The time between the tries of --retry (default: 1s)
        #[arg(long, value_name = "DURATION")]
        retry_delay: Option<String>,
        /// Copy no signature (velarx pushes none)
        #[arg(long)]
        remove_signatures: bool,
        /// A Docker option with no effect (as in podman)
        #[arg(long, hide = true, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
        disable_content_trust: Option<bool>,
        /// Refused: velarx pushes no encrypted image
        #[arg(long, hide = true, allow_hyphen_values = true, value_delimiter = ',')]
        encrypt_layer: Vec<i64>,
        /// Refused: velarx pushes no encrypted image
        #[arg(long, hide = true, allow_hyphen_values = true)]
        encryption_key: Vec<String>,
        #[command(flatten)]
        signing: SigningArgs,
        /// Verify the TLS certificates of the registry; `--tls-verify=false`
        /// also accepts plain HTTP
        #[arg(
            long,
            default_value_t = true,
            action = clap::ArgAction::Set,
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "true"
        )]
        tls_verify: bool,
        #[command(flatten)]
        access: RegistryAccessArgs,
    },

    #[command(about = "Search registries for images")]
    Search {
        /// Filter the results: stars=N, is-official, is-automated
        #[arg(long, short)]
        filter: Vec<String>,
        /// Go template of each result, or `json`
        #[arg(long)]
        format: Option<String>,
        /// The results of each registry (default 25)
        #[arg(long)]
        limit: Option<i64>,
        /// List the tags of the repository TERM names
        #[arg(long)]
        list_tags: bool,
        /// Do not truncate the descriptions
        #[arg(long)]
        no_trunc: bool,
        /// Show the stars and the official and automated columns too
        #[arg(long)]
        compatible: bool,
        /// Verify the TLS certificates of the registries (default: as
        /// registries.conf says)
        #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
        tls_verify: Option<bool>,
        #[command(flatten)]
        access: RegistryAccessArgs,
        /// REGISTRY/TERM, or a term for the unqualified-search registries
        term: String,
    },

    #[command(
        about = "Sign the manifest of images with GPG, into the signature storage",
        long_about = "Sign the manifest of images with GPG (the gpg of the user), into the \
                      signature storage of registries.d, as containers/image's simple signing: \
                      the signatures `signedBy` of policy.json verifies.  The manifest signed \
                      is the one the registry has for the name"
    )]
    Sign {
        /// The key (fingerprint or user id) of the keyring of gpg
        #[arg(long, value_name = "KEY")]
        sign_by: String,
        /// Write the signatures here (`DIR/REPOSITORY@sha256=HEX/signature-N`)
        /// instead of the signature storage of registries.d
        #[arg(short, long, value_name = "DIR")]
        directory: Option<PathBuf>,
        /// The file with the passphrase of the key (gpg asks for it
        /// otherwise)
        #[arg(long, value_name = "PATH")]
        passphrase_file: Option<PathBuf>,
        /// Verify the TLS certificates of the registry; `--tls-verify=false`
        /// also accepts plain HTTP
        #[arg(
            long,
            default_value_t = true,
            action = clap::ArgAction::Set,
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "true"
        )]
        tls_verify: bool,
        #[command(flatten)]
        access: RegistryAccessArgs,
        /// The images in their registry (`docker://` is accepted)
        #[arg(required = true)]
        images: Vec<String>,
    },

    #[command(about = "Generate a sigstore key pair to sign images with")]
    GenerateSigstoreKey {
        /// Write the private key to PREFIX.private and the public key to
        /// PREFIX.pub
        #[arg(long, value_name = "PREFIX")]
        output_prefix: PathBuf,
        /// The file with the passphrase of the private key (asked for twice
        /// on a terminal when not given)
        #[arg(long, value_name = "PATH")]
        passphrase_file: Option<PathBuf>,
    },

    #[command(subcommand, about = "Manage the trust policy of the registries")]
    Trust(super::trust::TrustCommands),

    #[command(about = "Show the layers of an image as a tree")]
    Tree {
        /// Show the images built on the image instead
        #[arg(long)]
        whatrequires: bool,
        image: String,
    },

    #[command(about = "List the pulls in progress, or cancel them")]
    Pulls {
        /// Only the ids
        #[arg(long, short)]
        quiet: bool,
        /// Do not shorten the ids
        #[arg(long)]
        no_trunc: bool,
        /// Go template of each row (ID, Names, State, Progress, Percent,
        /// Containers, Error), or `json`
        #[arg(long)]
        format: Option<String>,
        /// Cancel the pull of this image: nothing more is fetched and its
        /// staging goes (refused while a container is made on it)
        #[arg(long, value_name = "ID")]
        cancel: Vec<String>,
    },

    #[command(about = "Fetch what a lazily pulled image lacks and verify its layers")]
    Complete {
        #[command(flatten)]
        access: RegistryAccessArgs,
        image: String,
    },

    #[command(about = "Save images to an archive")]
    Save {
        /// File (or directory for oci-dir) to write; by default standard output
        #[arg(long, short)]
        output: Option<PathBuf>,
        /// oci-archive (default) or oci-dir
        #[arg(long, default_value = "oci-archive")]
        format: String,
        /// No progress
        #[arg(long, short)]
        quiet: bool,
        /// Accepted: the arguments are always all images
        #[arg(long, short = 'm')]
        multi_image_archive: bool,
        /// Refused (it is only for docker-dir, which velarx does not write)
        #[arg(long)]
        compress: bool,
        /// Accepted: the layers are always saved uncompressed
        #[arg(long)]
        uncompressed: bool,
        images: Vec<String>,
    },

    #[command(about = "Load images from an archive")]
    Load {
        /// Archive (or oci-dir directory) to read; by default standard input
        #[arg(long, short)]
        input: Option<PathBuf>,
        /// Print only the ids of the loaded images
        #[arg(long, short)]
        quiet: bool,
        /// Platform (OS/ARCH[/VARIANT]) of an archive with several
        #[arg(long)]
        platform: Option<String>,
    },

    #[command(about = "Create an image from the tar of a root file system")]
    Import {
        /// Apply a Dockerfile instruction (CMD, ENV, ...) to the image
        #[arg(long, short)]
        change: Vec<String>,
        /// Comment of the history
        #[arg(long, short)]
        message: Option<String>,
        /// Tar archive, or - for standard input
        file: String,
        /// Name of the image
        name: Option<String>,
        /// No progress
        #[arg(long, short)]
        quiet: bool,
        /// The architecture of the image (default: this host's)
        #[arg(long)]
        arch: Option<String>,
        /// The OS of the image (default: this host's)
        #[arg(long)]
        os: Option<String>,
        /// The variant of the architecture of the image
        #[arg(long)]
        variant: Option<String>,
        /// Algorithm of the digests of the new image: sha256 or sha512 (default: [build] digest)
        #[arg(long, value_name = "ALGORITHM")]
        digest: Option<String>,
    },

    #[command(about = "Remove unused images")]
    Prune {
        /// Remove all unused images, not just dangling ones
        #[arg(long, short)]
        all: bool,
        /// Filter images to prune (e.g., "until=24h")
        #[arg(long)]
        filter: Vec<String>,
        /// Do not prompt for confirmation
        #[arg(long, short)]
        force: bool,
        /// Remove the persistent cache of RUN --mount=type=cache too
        #[arg(long)]
        build_cache: bool,
        /// Remove images used by containers of other tools too (the store
        /// has none)
        #[arg(long)]
        external: bool,
    },
}

/// The signing options of podman's pushes: `--sign-by-sigstore-private-key`
/// is implemented, the others are refused by name.
#[derive(clap::Args, Clone, Debug, Default)]
pub struct SigningArgs {
    /// Also sign the manifest pushed with GPG (the key of the keyring of
    /// gpg), into the signature storage of registries.d (`image sign`)
    #[arg(long, value_name = "KEY", allow_hyphen_values = true)]
    pub sign_by: Option<String>,
    #[arg(long, hide = true, value_name = "PATH")]
    pub sign_by_sigstore: Option<PathBuf>,
    /// Sign the manifests pushed with this sigstore private key (cosign or
    /// `skopeo generate-sigstore-key`)
    #[arg(long, value_name = "PATH")]
    pub sign_by_sigstore_private_key: Option<PathBuf>,
    #[arg(long, hide = true, value_name = "FINGERPRINT")]
    pub sign_by_sq_fingerprint: Option<String>,
    /// The file with the passphrase of the signing key (asked for on a
    /// terminal when not given)
    #[arg(long, value_name = "PATH")]
    pub sign_passphrase_file: Option<PathBuf>,
}

/// The text of the file `path` (a pipe of the shell too, as
/// `<(echo pass)`), at most `limit` bytes; the buffer of a file that is
/// refused is wiped.
pub(crate) fn read_secret(path: &std::path::Path, limit: u64) -> std::io::Result<String> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    // (one buffer, never grown: no copy of it is left behind)
    let mut data = zeroize::Zeroizing::new(Vec::with_capacity(limit as usize + 1));
    file.take(limit + 1).read_to_end(&mut data)?;
    if data.len() as u64 > limit {
        return Err(std::io::Error::other(format!("larger than {limit} bytes")));
    }
    match String::from_utf8(std::mem::take(&mut *data)) {
        Ok(text) => Ok(text),
        Err(e) => {
            zeroize::Zeroize::zeroize(&mut e.into_bytes());
            Err(std::io::Error::other("not UTF-8 text"))
        }
    }
}

/// What the user types at the terminal after `text`, with no echo.  A ^C
/// ends the command after the terminal is put back: rpassword raises SIGINT
/// before it restores the terminal, which the default action of the signal
/// would leave with no echo.
pub(crate) fn prompt_password(text: &str) -> std::io::Result<String> {
    let before = velarx_sys::catch::ignore(libc::SIGINT);
    let typed = rpassword::prompt_password(text);
    if let Some(before) = before {
        before.restore();
    }
    if matches!(&typed, Err(e) if e.kind() == std::io::ErrorKind::Interrupted) {
        // the signal of the ^C, now that the terminal is back
        let _ =
            rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::INT);
    }
    typed
}

impl SigningArgs {
    /// The key of `--sign-by-sigstore-private-key` and its passphrase, read
    /// from their files: the signing options of the commands that sign
    /// `what`, where the others are errors naming them.
    pub fn spec(&self, what: &str) -> anyhow::Result<Option<velarx_proto::workload::SigningKey>> {
        let refused: Vec<(&str, &str)> = [
            (
                "--sign-by",
                "GPG signing is for `push` and `image sign`",
                self.sign_by.is_some() && what != "push",
            ),
            (
                "--sign-by-sigstore",
                "keyless signing (Fulcio) is not implemented",
                self.sign_by_sigstore.is_some(),
            ),
            (
                "--sign-by-sq-fingerprint",
                "Sequoia signing is not implemented",
                self.sign_by_sq_fingerprint.is_some(),
            ),
        ]
        .into_iter()
        .filter(|(_, _, given)| *given)
        .map(|(name, why, _)| (name, why))
        .collect();
        if !refused.is_empty() {
            anyhow::bail!(
                "{} is not supported for {what}: {}",
                refused
                    .iter()
                    .map(|(n, _)| *n)
                    .collect::<Vec<_>>()
                    .join(", "),
                refused
                    .iter()
                    .map(|(_, w)| *w)
                    .collect::<Vec<_>>()
                    .join("; ")
            );
        }
        let Some(key) = &self.sign_by_sigstore_private_key else {
            if self.sign_passphrase_file.is_some() && self.sign_by.is_none() {
                anyhow::bail!("--sign-passphrase-file requires --sign-by-sigstore-private-key");
            }
            return Ok(None);
        };
        let key_text = read_secret(key, 1 << 20)
            .map_err(|e| anyhow::anyhow!("reading the signing key {}: {e}", key.display()))?;
        let passphrase = match &self.sign_passphrase_file {
            Some(file) => {
                let text = zeroize::Zeroizing::new(read_secret(file, 64 << 10).map_err(|e| {
                    anyhow::anyhow!("reading the passphrase file {}: {e}", file.display())
                })?);
                // (the first line, as containers/image reads it)
                text.lines().next().unwrap_or_default().to_string()
            }
            None if rustix::termios::isatty(std::io::stdin()) => {
                prompt_password("Passphrase of the signing key: ")?
            }
            None => String::new(),
        };
        Ok(Some(velarx_proto::workload::SigningKey {
            key: key_text,
            passphrase,
        }))
    }

    /// An error naming the options given: velarx signs no `what`.
    pub fn refuse(&self, what: &str) -> anyhow::Result<()> {
        let given: Vec<&str> = [
            ("--sign-by", self.sign_by.is_some()),
            ("--sign-by-sigstore", self.sign_by_sigstore.is_some()),
            (
                "--sign-by-sigstore-private-key",
                self.sign_by_sigstore_private_key.is_some(),
            ),
            (
                "--sign-by-sq-fingerprint",
                self.sign_by_sq_fingerprint.is_some(),
            ),
            (
                "--sign-passphrase-file",
                self.sign_passphrase_file.is_some(),
            ),
        ]
        .into_iter()
        .filter_map(|(name, given)| given.then_some(name))
        .collect();
        if given.is_empty() {
            return Ok(());
        }
        anyhow::bail!(
            "{} is not supported: velarx signs no {what}",
            given.join(", ")
        )
    }
}

/// How a pull or a push authenticates to the registry.
#[derive(clap::Args, Clone, Default)]
pub struct RegistryAccessArgs {
    /// Credentials (USERNAME[:PASSWORD]) for the host you named, not for a
    /// mirror on another host
    #[arg(long)]
    pub creds: Option<String>,
    /// The auth file to use instead of the default ones
    #[arg(long)]
    pub authfile: Option<PathBuf>,
    /// A directory of certificates (*.crt, *.cert and *.key) for the registry
    #[arg(long)]
    pub cert_dir: Option<PathBuf>,
}

impl std::fmt::Debug for RegistryAccessArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryAccessArgs")
            .field("creds", &self.creds.as_ref().map(|_| "<redacted>"))
            .field("authfile", &self.authfile)
            .field("cert_dir", &self.cert_dir)
            .finish()
    }
}

/// The options of podman's build that velarx's build does not have:
/// refused with their names when given.
#[derive(clap::Args, Clone, Debug, Default)]
pub struct BuildUnsupported {
    #[arg(long = "cw", hide = true, allow_hyphen_values = true)]
    pub cw: Option<String>,
    #[arg(long = "decryption-key", hide = true, allow_hyphen_values = true)]
    pub decryption_key: Vec<String>,
    #[arg(long = "sign-by", hide = true, allow_hyphen_values = true)]
    pub sign_by: Option<String>,
}

impl BuildUnsupported {
    /// The options that were given.
    pub fn given(&self) -> Vec<String> {
        [
            (
                "--cw",
                "there is no krun runtime to run a confidential workload",
                self.cw.is_some(),
            ),
            (
                "--decryption-key",
                "velarx does not decrypt images",
                !self.decryption_key.is_empty(),
            ),
            (
                "--sign-by",
                "GPG signing is not implemented: sign what the build made with `push --sign-by-sigstore-private-key`",
                self.sign_by.is_some(),
            ),
        ]
        .into_iter()
        .filter(|(_, _, given)| *given)
        .map(|(name, why, _)| format!("{name} ({why})"))
        .collect()
    }
}

/// The options of podman's build that change what the RUN steps run in or
/// the image config, and the few that only take a value.
#[derive(clap::Args, Clone, Debug, Default)]
pub struct BuildExtra {
    /// Format of the manifest and the config of the image: oci (Docker
    /// formats are not supported)
    #[arg(long, value_name = "FORMAT")]
    pub format: Option<String>,
    /// Pull the base images every time
    #[arg(long, hide = true)]
    pub pull_always: bool,
    /// Never pull the base images
    #[arg(long, hide = true)]
    pub pull_never: bool,
    /// Bind mount a volume in the RUN containers
    #[arg(long, short = 'v', value_name = "SRC:DST[:OPTIONS]")]
    pub volume: Vec<String>,
    /// Set an environment variable of the image
    #[arg(long, value_name = "NAME=VALUE")]
    pub env: Vec<String>,
    /// Remove an environment variable of the image
    #[arg(long, value_name = "NAME")]
    pub unsetenv: Vec<String>,
    /// Remove a label of the base image
    #[arg(long, value_name = "NAME")]
    pub unsetlabel: Vec<String>,
    /// File of build arguments, one NAME=VALUE a line
    #[arg(long, value_name = "FILE")]
    pub build_arg_file: Vec<PathBuf>,
    /// Add a host to IP mapping in the RUN containers (HOST:IP)
    #[arg(long, value_name = "HOST:IP")]
    pub add_host: Vec<String>,
    /// DNS servers of the RUN containers
    #[arg(long)]
    pub dns: Vec<String>,
    /// DNS options of the RUN containers
    #[arg(long, alias = "dns-opt")]
    pub dns_option: Vec<String>,
    /// DNS search domains of the RUN containers
    #[arg(long)]
    pub dns_search: Vec<String>,
    /// Add a capability to the RUN containers
    #[arg(long, value_delimiter = ',')]
    pub cap_add: Vec<String>,
    /// Drop a capability of the RUN containers
    #[arg(long, value_delimiter = ',')]
    pub cap_drop: Vec<String>,
    /// Security options of the RUN containers
    #[arg(long)]
    pub security_opt: Vec<String>,
    /// Ulimits of the RUN containers
    #[arg(long, value_delimiter = ',')]
    pub ulimit: Vec<String>,
    /// A device for the RUN containers
    #[arg(long)]
    pub device: Vec<String>,
    /// Size of /dev/shm of the RUN containers
    #[arg(long)]
    pub shm_size: Option<String>,
    /// Write the output of the build to this file
    #[arg(long, value_name = "FILE")]
    pub logfile: Option<PathBuf>,
    /// With --logfile, one file for each platform: FILE_OS_ARCH
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub logsplit: Option<bool>,
    /// How many independent stages to run at the same time (0: as many as there are)
    #[arg(long, value_name = "N")]
    pub jobs: Option<u32>,
    /// A secret for RUN --mount=type=secret: id=ID[,src=ENV_OR_FILE][,env=ENV][,type=file|env]
    #[arg(long, value_name = "SECRET")]
    pub secret: Vec<String>,
    /// An ssh agent for RUN --mount=type=ssh: default (SSH_AUTH_SOCK) or ID[=SOCKET]
    #[arg(long, value_name = "default|ID[=SOCKET]")]
    pub ssh: Vec<String>,
    /// Allow an entitlement the engine configuration enables: network.host
    /// (RUN --network=host, --network=host or ns:PATH), security.insecure (RUN
    /// --security=insecure); repeatable, or a comma separated list
    #[arg(long, value_name = "ENTITLEMENT")]
    pub allow: Vec<String>,
    /// A named context for FROM, COPY --from and RUN --mount from=:
    /// NAME=DIRECTORY, URL or docker-image://IMAGE
    #[arg(long, value_name = "NAME=VALUE")]
    pub build_context: Vec<String>,
    /// The image of the first FROM, instead of the one it names
    #[arg(long = "from", value_name = "IMAGE")]
    pub from_image: Option<String>,
    /// A supplementary group of the RUN containers
    #[arg(long, value_name = "GROUP", value_delimiter = ',')]
    pub group_add: Vec<String>,
    /// No /etc/hosts in the RUN containers
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub no_hosts: Option<bool>,
    /// The standard input of the command is the one of the RUN steps
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub stdin: Option<bool>,
    /// No /etc/hostname in the RUN containers
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub no_hostname: Option<bool>,
    /// The memory limit of the RUN containers
    #[arg(long, short = 'm', allow_hyphen_values = true)]
    pub memory: Option<String>,
    /// The memory and swap limit of the RUN containers (-1: no limit)
    #[arg(long, allow_hyphen_values = true)]
    pub memory_swap: Option<String>,
    /// The CPU period of the RUN containers, in microseconds
    #[arg(long)]
    pub cpu_period: Option<u64>,
    /// The CPU quota of the RUN containers, in microseconds a period
    #[arg(long, allow_hyphen_values = true)]
    pub cpu_quota: Option<i64>,
    /// The CPU shares (relative weight) of the RUN containers
    #[arg(long, short = 'c')]
    pub cpu_shares: Option<u64>,
    /// The CPUs the RUN containers may use (0-3, 0,1)
    #[arg(long)]
    pub cpuset_cpus: Option<String>,
    /// The memory nodes the RUN containers may use
    #[arg(long)]
    pub cpuset_mems: Option<String>,
    /// The cgroup of the RUN containers
    #[arg(long)]
    pub cgroup_parent: Option<String>,
    /// The IPC namespace of the RUN containers (host, private, container:ID, ns:PATH)
    #[arg(long)]
    pub ipc: Option<String>,
    /// The PID namespace of the RUN containers
    #[arg(long)]
    pub pid: Option<String>,
    /// The UTS namespace of the RUN containers
    #[arg(long)]
    pub uts: Option<String>,
    /// The cgroup namespace of the RUN containers (host, private)
    #[arg(long)]
    pub cgroupns: Option<String>,
    /// The user namespace of the RUN containers (host, auto, keep-id, nomap, ns:PATH)
    #[arg(long)]
    pub userns: Option<String>,
    /// A uid mapping of the user namespace of the RUN containers (CONTAINER:HOST:SIZE)
    #[arg(long)]
    pub userns_uid_map: Vec<String>,
    /// A gid mapping of the user namespace of the RUN containers
    #[arg(long)]
    pub userns_gid_map: Vec<String>,
    /// The uid mapping of the RUN containers: the ranges of this user in /etc/subuid
    #[arg(long)]
    pub userns_uid_map_user: Option<String>,
    /// The gid mapping of the RUN containers: the ranges of this group in /etc/subgid
    #[arg(long)]
    pub userns_gid_map_group: Option<String>,
    /// How the RUN steps are isolated: oci (the default) or rootless (the same here)
    #[arg(long)]
    pub isolation: Option<String>,
    /// How many times a failed pull of a base image is tried again (default 3)
    #[arg(long, value_name = "N")]
    pub retry: Option<u32>,
    /// The time between the tries of --retry (default: 2s)
    #[arg(long, value_name = "DURATION")]
    pub retry_delay: Option<String>,
    /// The creation time of the image and its history, and the time of its files (seconds since the epoch)
    #[arg(long, value_name = "SECONDS")]
    pub timestamp: Option<i64>,
    /// The creation time of the image and its history (seconds since the epoch;
    /// default: SOURCE_DATE_EPOCH), also the build argument SOURCE_DATE_EPOCH
    #[arg(long, value_name = "SECONDS")]
    pub source_date_epoch: Option<i64>,
    /// With --source-date-epoch: no file of the new layers is newer
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub rewrite_timestamp: Option<bool>,
    /// No history in the image
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub omit_history: Option<bool>,
    /// The final image keeps the labels of its base (default: true)
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub inherit_labels: Option<bool>,
    /// Build only the stages the target needs (default: true)
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub skip_unused_stages: Option<bool>,
    /// Use the images of the build cache made at most this long ago (1h, 30m)
    #[arg(long, value_name = "DURATION")]
    pub cache_ttl: Option<String>,
    /// Write the files of the image: DIRECTORY, type=local,dest=DIRECTORY,
    /// type=tar,dest=FILE (- for the standard output); repeatable, the image
    /// is built once and written to each (one of them may be -)
    #[arg(long, short = 'o', value_name = "OUTPUT")]
    pub output: Vec<String>,
    /// An option of podman's build that has no effect there either
    #[arg(long, hide = true)]
    pub compress: bool,
    /// A Docker option of podman's build with no effect
    #[arg(long, hide = true, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub disable_content_trust: Option<bool>,
    /// An annotation of the manifest of the image (NAME=VALUE)
    #[arg(long, value_name = "NAME=VALUE")]
    pub annotation: Vec<String>,
    /// Remove an annotation the image has from its base
    #[arg(long, value_name = "NAME")]
    pub unsetannotation: Vec<String>,
    /// The image keeps the annotations of its base and names it in them (default: true)
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub inherit_annotations: Option<bool>,
    /// The annotation org.opencontainers.image.created (default: true)
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub created_annotation: Option<bool>,
    /// The label io.velarx.version in the image (default: true, but not with
    /// --timestamp or --source-date-epoch)
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub identity_label: Option<bool>,
    /// The RUN steps mount the VOLUMEs of the image: what they write there
    /// is discarded, as Docker's builder does (default: they keep it)
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub compat_volumes: Option<bool>,
    /// A repository to take the images of steps from, tried on a miss of the
    /// local cache (needs --layers)
    #[arg(long, value_name = "REPOSITORY")]
    pub cache_from: Vec<String>,
    /// A repository to push the image of every new step to (needs --layers)
    #[arg(long, value_name = "REPOSITORY")]
    pub cache_to: Vec<String>,
    /// A flag for cpp(1), which preprocesses a Containerfile named *.in
    #[arg(long, value_name = "FLAG", allow_hyphen_values = true)]
    pub cpp_flag: Vec<String>,
    /// Make SBOMs with the scanner of a preset: syft, syft-cyclonedx, syft-spdx, trivy, trivy-cyclonedx, trivy-spdx
    #[arg(long, value_name = "PRESET")]
    pub sbom: Option<String>,
    /// The image whose commands make the SBOM
    #[arg(long, value_name = "IMAGE")]
    pub sbom_scanner_image: Option<String>,
    /// A command of the scanner image, with {ROOTFS}, {CONTEXT} and {OUTPUT}
    #[arg(long, value_name = "COMMAND", allow_hyphen_values = true)]
    pub sbom_scanner_command: Vec<String>,
    /// How the documents of several commands are merged (cat, merge-cyclonedx-by-component-name-and-version, merge-spdx-by-package-name-and-versioninfo)
    #[arg(long, value_name = "METHOD")]
    pub sbom_merge_strategy: Option<String>,
    /// A file for the SBOM
    #[arg(long, value_name = "FILE")]
    pub sbom_output: Option<String>,
    /// A file for the package URLs of the SBOM
    #[arg(long, value_name = "FILE")]
    pub sbom_purl_output: Option<String>,
    /// A path in the image for the SBOM
    #[arg(long, value_name = "PATH")]
    pub sbom_image_output: Option<String>,
    /// A path in the image for the package URLs of the SBOM
    #[arg(long, value_name = "PATH")]
    pub sbom_image_purl_output: Option<String>,
    /// A label of the intermediate images (NAME[=VALUE])
    #[arg(long, value_name = "NAME[=VALUE]")]
    pub layer_label: Vec<String>,
    /// The os.version of the image
    #[arg(long, value_name = "VERSION")]
    pub os_version: Option<String>,
    /// A feature of the OS of the image (os.features)
    #[arg(long, value_name = "FEATURE")]
    pub os_feature: Vec<String>,
    /// Pass the proxy variables of this command to the RUN steps (default: true)
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub http_proxy: Option<bool>,
    /// As podman's, no effect: the layers of a build are stored
    /// uncompressed
    #[arg(long, short = 'D', hide = true, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub disable_compression: Option<bool>,
    /// Checked, no effect: the layers of a build are stored uncompressed
    /// (gzip, zstd, zstd:chunked or none)
    #[arg(long, value_name = "FORMAT")]
    pub compression_format: Option<String>,
    /// Checked, no effect (the layers of a build are stored uncompressed)
    #[arg(long, value_name = "LEVEL")]
    pub compression_level: Option<i32>,
    /// Checked, no effect (the layers of a build are stored uncompressed)
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub force_compression: Option<bool>,
    /// A flag of the OCI runtime for the RUN steps (as the global --runtime-flag)
    #[arg(long, value_name = "FLAG")]
    pub runtime_flag: Vec<String>,
    /// A directory of OCI hooks for the RUN steps (as the global --hooks-dir)
    #[arg(long, value_name = "DIR")]
    pub hooks_dir: Vec<PathBuf>,
}
