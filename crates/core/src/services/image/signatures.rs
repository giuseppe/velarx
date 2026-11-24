// SPDX-License-Identifier: Apache-2.0
//! The signatures of the images a pull gets: found where
//! registries.d says (lookaside storage, sigstore attachments), and
//! checked against the requirements of policy.json before anything else
//! of the image is fetched, as podman checks them.

use super::*;
use velarx_content::fetcher::fetch::SignedRecord;
use velarx_content::pull::net::Net;
use velarx_signature::evaluate::{self, Image, Manifest, Mode, Pre, Why};
use velarx_signature::name;
use velarx_signature::reference::DockerRef;
use velarx_signature::registries_d::{self, RegistriesD};
use velarx_signature::sigstore::{Signature, MAX_SIGNATURE_SIZE};
use velarx_signature::PolicyRequirement;

/// Most layers of a sigstore attachment read.
const MAX_ATTACHMENTS: usize = 128;
/// The bytes of all the signatures of an image read at most (lookaside
/// storage and attachments together).
const MAX_SIGNATURES_TOTAL: u64 = 8 << 20;
/// Longest a verification may take: it runs on a thread of its own.
const VERIFY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Take `n` bytes of the budget of the signatures of an image.
fn spend(budget: &mut u64, n: u64) -> ImageResult<()> {
    if n > *budget {
        return Err(rejected("the signatures of the image are too large"));
    }
    *budget -= n;
    Ok(())
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The signatures of `signatures` that `requirements` accept for
/// `reference` and `manifest` (their indexes), computed on a blocking
/// thread, in VERIFY_TIMEOUT at most.
async fn accepted_blocking(
    mode: Mode,
    requirements: Vec<PolicyRequirement>,
    reference: DockerRef,
    manifest: Vec<u8>,
    signatures: Vec<Signature>,
) -> ImageResult<Vec<usize>> {
    let job = tokio::task::spawn_blocking(move || {
        evaluate::accepted(
            mode,
            &requirements,
            &Image {
                reference: &reference,
                manifest: Manifest::Bytes(&manifest),
                signatures: &signatures,
            },
            now(),
        )
    });
    match tokio::time::timeout(VERIFY_TIMEOUT, job).await {
        Err(_) => Err(rejected("the verification of the signatures took too long")),
        Ok(Err(e)) => Err(ImageError::Storage(e.to_string())),
        Ok(Ok(result)) => result.map_err(rejected),
    }
}

/// The record of `records` that `requirements` accept for the tag
/// `reference` with the latest time of signing, computed on a blocking
/// thread, in VERIFY_TIMEOUT at most.
async fn newest_blocking(
    requirements: Vec<PolicyRequirement>,
    reference: DockerRef,
    records: Vec<name::Record>,
) -> ImageResult<Option<name::Named>> {
    let job = tokio::task::spawn_blocking(move || {
        name::newest(&requirements, &reference, records, now())
    });
    match tokio::time::timeout(VERIFY_TIMEOUT, job).await {
        Err(_) => Err(rejected("the verification of the signatures took too long")),
        Ok(Err(e)) => Err(ImageError::Storage(e.to_string())),
        Ok(Ok(result)) => result.map_err(rejected),
    }
}

/// The signatures of `record` that read as signatures, in what is left of
/// `budget`: what a fetcher sends is not an error when it is junk or too
/// much, it is left out.
fn read_record(record: SignedRecord, budget: &mut u64) -> name::Record {
    use base64::Engine;
    let mut signatures = Vec::new();
    for text in record.signatures {
        let blob = base64::engine::general_purpose::STANDARD.decode(text);
        let Ok(blob) = blob else { continue };
        if blob.len() as u64 > MAX_SIGNATURE_SIZE || spend(budget, blob.len() as u64).is_err() {
            continue;
        }
        if let Ok(signature) = Signature::from_blob(&blob) {
            signatures.push(signature);
        }
    }
    name::Record {
        digest: record.digest,
        signatures,
    }
}

fn rejected(e: impl std::fmt::Display) -> ImageError {
    ImageError::Registry(format!("Source image rejected: {e}"))
}

/// The reference an image was asked by, as the identity rules compare it.
pub(super) fn intended(image_ref: &ImageReference) -> ImageResult<DockerRef> {
    let mut s = format!("{}/{}", image_ref.registry, image_ref.repository);
    if let Some(t) = &image_ref.tag {
        s.push(':');
        s.push_str(t);
    }
    if let Some(d) = &image_ref.digest {
        s.push('@');
        s.push_str(&d.to_string());
    }
    DockerRef::parse_normalized(&s).map_err(rejected)
}

/// How the signature policy judges the image of a container.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureJudging {
    /// The default of a create: the signature rules of the policy of now
    /// (`reject` is for pulls), at the create only.
    Policy,
    /// `--security-opt signature=check`: the whole policy of now, `reject`
    /// included, at the create and at every start.
    Check,
    /// `--security-opt signature=require` or the configuration (the
    /// reason): a signature must have satisfied a requirement of every name.
    Require(&'static str),
}

/// The short id of `image` as it is shown (the digest of its config).
fn shown_id(image: &velarx_db::ImageRecord) -> String {
    image.config_digest.short()
}

impl ImageService {
    pub(super) fn registries_config(&self) -> ImageResult<RegistriesD> {
        match &self.pull_config.registries_d {
            Some(dir) if !dir.is_dir() => Err(format!("{} is not a directory", dir.display())),
            Some(dir) => RegistriesD::load_dirs(std::slice::from_ref(dir)),
            None => RegistriesD::load(),
        }
        .map_err(|e| ImageError::Registry(format!("registries.d: {e}")))
    }

    /// The digest the tag of `image_ref` names according to `[pull] names`,
    /// in the order of the list: None when the registry is to say (it comes
    /// first); a source that is not the registry is believed for nothing,
    /// the tag is the newest record signed for exactly this name and tag by
    /// a key the policy (`requirements`) accepts.
    pub(super) async fn resolve_tag(
        &self,
        image_ref: &ImageReference,
        requirements: &[PolicyRequirement],
    ) -> ImageResult<Option<Digest>> {
        use velarx_content::pull::net::origin::MetadataSources;
        let reference = intended(image_ref)?;
        let name = reference.string();
        let mut why = "[pull] names has no source".to_string();
        for source in self.sources_of(Some(&self.pull_config.names))? {
            if source == "registry" {
                return Ok(None);
            }
            if !evaluate::needs_signatures(Mode::Whole, requirements) {
                why = "the signature policy names no key for it, so no signature says what the tag names".into();
                continue;
            }
            let links = self.source_links(std::slice::from_ref(&source)).await;
            let given = MetadataSources::open(links).await.signatures(&name).await;
            if given.is_empty() {
                why = "no source has a signed record of the tag".into();
                continue;
            }
            let given_count = given.len();
            let mut budget = MAX_SIGNATURES_TOTAL;
            let records: Vec<_> = given
                .into_iter()
                .map(|r| read_record(r, &mut budget))
                .filter(|r| !r.signatures.is_empty())
                .collect();
            match newest_blocking(requirements.to_vec(), reference.clone(), records).await? {
                Some(named) => {
                    return named.digest.parse().map(Some).map_err(rejected);
                }
                None => {
                    why = format!(
                        "{given_count} records of the tag, none signed by a key the policy accepts"
                    );
                }
            }
        }
        Err(ImageError::Registry(format!(
            "{name}: `registry` is not one of [pull] names, and {why}"
        )))
    }

    /// Check the manifest `manifest` (of digest `digest`) of `image_ref`
    /// against `requirements`; the signatures the requirements accepted.  Nothing is fetched when no requirement needs
    /// signatures.
    pub(super) async fn verify_signatures(
        &self,
        net: &Net,
        image_ref: &ImageReference,
        digest: &Digest,
        manifest: &[u8],
        requirements: &[PolicyRequirement],
    ) -> ImageResult<Vec<Signature>> {
        let text = digest.to_string();
        if !evaluate::needs_signatures(Mode::Whole, requirements) {
            return Ok(Vec::new());
        }
        let reference = intended(image_ref)?;
        let config = self.registries_config()?;
        let mut budget = MAX_SIGNATURES_TOTAL;
        let mut signatures = self
            .lookaside_signatures(net, &config, &reference, &text, &mut budget)
            .await?;
        let attachments = config.use_sigstore_attachments(&reference);
        if attachments && net.has_registry() {
            signatures.extend(self.sigstore_attachments(net, &text, &mut budget).await?);
        }
        // (what the fetchers of the sources keep: judged like the rest)
        let fetched = net.fetched_signatures(digest).await;
        for record in fetched.into_iter().filter(|r| r.digest == text) {
            for signature in read_record(record, &mut budget).signatures {
                if !signatures.contains(&signature) {
                    signatures.push(signature);
                }
            }
        }
        debug!(
            "{} signatures of {} ({digest})",
            signatures.len(),
            reference.string()
        );
        // (a sigstore signature is an attachment: where registries.d does
        // not ask for them, a sigstoreSigned requirement finds none)
        let unlooked = (!attachments
            && requirements
                .iter()
                .any(|r| matches!(r, PolicyRequirement::SigstoreSigned { .. }))
            && !signatures
                .iter()
                .any(|s| matches!(s, Signature::Sigstore(_))))
        .then(|| reference.string());
        let used = accepted_blocking(
            Mode::Whole,
            requirements.to_vec(),
            reference,
            manifest.to_vec(),
            signatures.clone(),
        )
        .await
        .map_err(|e| match (e, unlooked) {
            (ImageError::Registry(m), Some(name)) if m.ends_with(evaluate::NO_SIGNATURE) => {
                ImageError::Registry(format!(
                    "{m} (registries.d sets no use-sigstore-attachments for {name}, so sigstore signatures are not looked for)"
                ))
            }
            (e, _) => e,
        })?;
        // only what was accepted is kept
        Ok(used
            .into_iter()
            .filter_map(|i| signatures.get(i).cloned())
            .collect())
    }

    /// How the pull by `image_ref` is recorded: its reference and the
    /// signatures found (JSON), for the checks of `verify_stored`.
    pub(super) fn pull_record(
        &self,
        image_ref: &ImageReference,
        signatures: &[Signature],
    ) -> ImageResult<(String, Vec<u8>)> {
        use base64::Engine;
        let reference = intended(image_ref)?.string();
        let blobs: Vec<String> = signatures
            .iter()
            .map(|s| base64::engine::general_purpose::STANDARD.encode(s.to_blob()))
            .collect();
        Ok((reference, serde_json::to_vec(&blobs)?))
    }

    /// Check an image against the signature policy of now, with the
    /// signatures stored from every pull of its manifest: a container is
    /// made of it, or starts.  Every name the image has (its `tags`, as
    /// [`Self::get_with_tags`] read them with the image), the names it was
    /// pulled by, and `asked` when it is a whole name, must be accepted: an
    /// image tagged with the name of a repository whose policy requires
    /// signatures needs signatures for that name, whether it was pulled by
    /// another name, loaded from an archive or built; an image with no tag
    /// is judged by the names it was pulled by.  With `Check` and `Require` a `reject`
    /// or `signedBaseLayer` requirement of the scope refuses the image (as a
    /// pull does), as podman's
    /// `composefs-verity` branch judges the whole policy with
    /// `signature=`; `Policy` does not apply it (`reject` is for pulls:
    /// podman runs the images of its store whatever the policy says of
    /// them, also those built, loaded or pulled before the rule).
    /// `insecureAcceptAnything` accepts the image without a signature.
    ///
    /// With `Check` and `Require` (the reason, for the error) the image must
    /// have at least one name, as podman's branch refuses "image has no
    /// names": a tag, or a name it was pulled by (a `repository@digest` one
    /// included, as podman counts every name), is a name.  With `Require`
    /// the image must also have, for each name, a requirement of the policy
    /// that a signature satisfied: an image the policy accepts without a
    /// signature is refused.
    pub async fn verify_stored(
        &self,
        asked: &str,
        image: &velarx_db::ImageRecord,
        tags: &[ImageTag],
        judging: SignatureJudging,
    ) -> ImageResult<()> {
        let pulled = self.db.pulled_image(&image.manifest_digest).await?;
        self.verify_pulled(asked, image, tags, judging, pulled)
            .await
    }

    /// [`Self::verify_stored`] for an image being pulled: the signatures its
    /// pulls found are in the staging area.
    pub async fn verify_staged(
        &self,
        asked: &str,
        pull: &velarx_content::pull::staged::StagedPull,
        judging: SignatureJudging,
    ) -> ImageResult<()> {
        let tags: Vec<ImageTag> = pull
            .tags
            .iter()
            .map(|t| ImageTag {
                repository: t.repository.clone(),
                tag: t.tag.clone(),
                image_id: pull.id.clone(),
            })
            .collect();
        let pulled = pull
            .pulls
            .iter()
            .map(|p| (p.reference.clone(), p.signatures.clone()))
            .collect();
        self.verify_pulled(asked, &pull.image_record(), &tags, judging, pulled)
            .await
    }

    async fn verify_pulled(
        &self,
        asked: &str,
        image: &velarx_db::ImageRecord,
        tags: &[ImageTag],
        judging: SignatureJudging,
        pulled: Vec<(String, Vec<u8>)>,
    ) -> ImageResult<()> {
        let require = match judging {
            SignatureJudging::Require(why) => Some(why),
            _ => None,
        };
        // (the signatures are over the manifest of this digest: the bytes
        // judged must be those)
        let have = Digest::of(image.manifest_digest.alg(), image.manifest.as_bytes());
        if have != image.manifest_digest {
            return Err(ImageError::Invalid(format!(
                "the stored manifest of image {} is not the one its id names ({have}): the store was modified; pull the image again",
                &image.id[..image.id.len().min(12)]
            )));
        }
        let mut names: Vec<ImageReference> = Vec::new();
        let mut add = |r: ImageReference| {
            if !names.iter().any(|n| n.full_name() == r.full_name()) {
                names.push(r);
            }
        };
        // (a name that does not parse would be left out of the judgment,
        // and with it what the policy has for it: an error)
        let parse = |name: &str| {
            ImageReference::parse(name).map_err(|e| {
                ImageError::Invalid(format!(
                    "the name {name:?} of image {} cannot be judged by the signature policy: {e}",
                    image.id.get(..12).unwrap_or(&image.id)
                ))
            })
        };
        for t in tags {
            add(parse(&format!("{}:{}", t.repository, t.tag))?);
        }
        if qualified(asked) {
            add(parse(asked)?);
        }
        // (in every mode: `require` judges no fewer names than `check`)
        for (reference, _) in &pulled {
            add(parse(reference)?);
        }
        if names.is_empty() && judging != SignatureJudging::Policy {
            // (an image without a name cannot be judged, as in podman's
            // `composefs-verity` branch: "image has no names")
            let because = require.unwrap_or("signature=check judges an image by its names");
            return Err(ImageError::Registry(format!(
                "image {} has no name the signature policy can be applied to (it has no tag and was never pulled), and {because}",
                // (the id as the image is shown, the digest of its config)
                shown_id(image)
            )));
        }
        let mode = match judging {
            SignatureJudging::Policy => Mode::SignaturesOnly,
            SignatureJudging::Check => Mode::Whole,
            SignatureJudging::Require(_) => Mode::MustBeSigned,
        };
        let mut signatures: Option<Vec<Signature>> = None;
        for name in names {
            let (scope, requirements) = self.scoped_requirements_of(&name)?;
            match evaluate::precheck(mode, &requirements) {
                Pre::Accept => continue,
                Pre::NeedsSignatures => {}
                Pre::Refuse { why, .. } => {
                    let said = match (why, require) {
                        (Why::NotSigned, Some(because)) => {
                            format!("accepts it without a signature, and {because}")
                        }
                        _ => format!("{} ({scope})", evaluate::refusal(why)),
                    };
                    return Err(ImageError::Registry(format!(
                        "{}: the signature policy ({}) {said}",
                        name.full_name(),
                        self.policy_location()
                    )));
                }
            }
            if signatures.is_none() {
                signatures = Some(signatures_of(&pulled)?);
            }
            accepted_blocking(
                mode,
                requirements,
                intended(&name)?,
                image.manifest.as_bytes().to_vec(),
                signatures.clone().unwrap_or_default(),
            )
            .await?;
        }
        Ok(())
    }

    /// The file the signature policy is read from, for a message.
    fn policy_location(&self) -> String {
        match &self.pull_config.policy_path {
            Some(p) => p.display().to_string(),
            None => velarx_signature::trust::policy_paths()
                .ok()
                .and_then(|paths| {
                    // (an error is the file the engine failed to read)
                    paths
                        .into_iter()
                        .find(|p| velarx_signature::trust::is_there(p).unwrap_or(true))
                })
                .map_or_else(
                    || "the built-in default".to_string(),
                    |p| p.display().to_string(),
                ),
        }
    }

    /// The signatures of `digest` in the lookaside storage of `reference`:
    /// `signature-1`, `signature-2`... up to the first that is missing.
    async fn lookaside_signatures(
        &self,
        net: &Net,
        config: &RegistriesD,
        reference: &DockerRef,
        digest: &str,
        budget: &mut u64,
    ) -> ImageResult<Vec<Signature>> {
        let base = config
            .lookaside_base(reference, false)
            .map_err(ImageError::Registry)?;
        let mut out = Vec::new();
        for i in 0.. {
            if i >= registries_d::MAX_LOOKASIDE_SIGNATURES {
                return Err(ImageError::Registry(format!(
                    "the signature storage has more than {} signatures of {digest}",
                    registries_d::MAX_LOOKASIDE_SIGNATURES
                )));
            }
            let url =
                registries_d::lookaside_url(&base, digest, i).map_err(ImageError::Registry)?;
            let blob = match registries_d::file_path(&url) {
                Some(path) => match read_bounded(path) {
                    Ok(b) => b,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                    Err(e) => return Err(ImageError::Registry(format!("{}: {e}", path.display()))),
                },
                // (over the network: the registry fetcher reads it, when
                // the registry is one of the sources)
                None if !net.has_registry() => break,
                None => match net
                    .signature(&url, MAX_SIGNATURE_SIZE.min(*budget))
                    .await
                    .map_err(|e| {
                        ImageError::Registry(format!("reading signature from {url}: {e}"))
                    })? {
                    Some(blob) => blob,
                    None => break,
                },
            };
            spend(budget, blob.len() as u64)?;
            out.push(
                Signature::from_blob(&blob)
                    .map_err(|e| ImageError::Registry(format!("parsing signature {url}: {e}")))?,
            );
        }
        Ok(out)
    }

    /// The sigstore attachments of `digest`: the layers of the manifest
    /// tagged `ALGO-HEX.sig` in the repository, if it has one.
    async fn sigstore_attachments(
        &self,
        net: &Net,
        digest: &str,
        budget: &mut u64,
    ) -> ImageResult<Vec<Signature>> {
        let tag = format!("{}.sig", digest.replacen(':', "-", 1));
        let Some((body, _)) = net.manifest_opt(&tag).await? else {
            return Ok(Vec::new());
        };
        let manifest: OciManifest = serde_json::from_slice(&body).map_err(|e| {
            ImageError::Registry(format!("invalid sigstore attachment manifest: {e}"))
        })?;
        if manifest.layers.len() > MAX_ATTACHMENTS {
            return Err(ImageError::Registry("too many sigstore attachments".into()));
        }
        let mut out = Vec::new();
        for layer in manifest.layers {
            if layer.size < 0 || layer.size as u64 > MAX_SIGNATURE_SIZE {
                return Err(ImageError::Registry(format!(
                    "the sigstore attachment {} is too large",
                    layer.digest
                )));
            }
            spend(budget, layer.size as u64)?;
            let mut payload = Vec::new();
            net.blob(&layer.digest, layer.size as u64, &mut |b| {
                payload.extend_from_slice(b);
                Ok(())
            })
            .await?;
            let actual = Digest::of(layer.digest.alg(), &payload);
            if actual != layer.digest {
                return Err(ImageError::DigestMismatch {
                    expected: layer.digest.to_string(),
                    actual: actual.to_string(),
                });
            }
            out.push(Signature::Sigstore(velarx_signature::sigstore::Sigstore {
                mime_type: layer.media_type,
                payload,
                annotations: layer.annotations.into_iter().collect(),
            }));
        }
        Ok(out)
    }
}

/// Whether `asked` is a whole name (its registry included), which the
/// container is made by, rather than an ID or a short name (whose image
/// has the name it resolved to as a tag).
fn qualified(asked: &str) -> bool {
    let Some((first, _)) = asked.split_once('/') else {
        return false;
    };
    velarx_base::reference::is_registry_domain(first)
}

/// A local signature, at most MAX_SIGNATURE_SIZE bytes.
fn read_bounded(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    velarx_base::conf::read_bounded(path, MAX_SIGNATURE_SIZE)
}

/// The signatures the pulls found (`pull_record`).
fn signatures_of(pulled: &[(String, Vec<u8>)]) -> ImageResult<Vec<Signature>> {
    use base64::Engine;
    let mut out = Vec::new();
    for (_, stored) in pulled {
        let blobs: Vec<String> = serde_json::from_slice(stored)?;
        for b in blobs {
            let blob = base64::engine::general_purpose::STANDARD
                .decode(b.as_bytes())
                .map_err(|_| ImageError::Storage("a stored signature is not base64".into()))?;
            let sig = Signature::from_blob(&blob).map_err(|e| ImageError::Storage(e.0))?;
            if !out.contains(&sig) {
                out.push(sig);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fifo_is_refused_not_waited_for() {
        let d = tempfile::tempdir().unwrap();
        let fifo = d.path().join("fifo");
        velarx_base::testing::make_fifo(&fifo);
        let r =
            velarx_base::testing::returns_within(std::time::Duration::from_secs(10), move || {
                read_bounded(&fifo)
            });
        assert!(r.is_err());
    }

    const FIRST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const SECOND: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    /// The base64 blob of the signature of `digest` for `docker.io/acme/app:1`
    /// by `signer` at `time`.
    fn record_of(signer: &velarx_signature::sign::Signer, digest: &str, time: i64) -> SignedRecord {
        use base64::Engine;
        let signature = signer
            .sign_manifest(digest, "docker.io/acme/app:1", "test", time)
            .unwrap();
        SignedRecord {
            digest: digest.into(),
            signatures: vec![base64::engine::general_purpose::STANDARD
                .encode(Signature::Sigstore(signature).to_blob())],
        }
    }

    fn signer() -> (velarx_signature::sign::Signer, String) {
        let (private, public) = velarx_signature::sign::generate_key_pair(b"x").unwrap();
        let files = velarx_signature::sign::KeyFiles {
            key: private.as_bytes().to_vec(),
            passphrase: b"x".to_vec(),
        };
        (
            velarx_signature::sign::Signer::load(&files).unwrap(),
            public,
        )
    }

    /// A service whose policy trusts `public` for `docker.io/acme` and whose
    /// source `peer` gives `records`, with `names` as `[pull] names`.
    async fn resolving(
        public: &str,
        records: &[SignedRecord],
        names: &[&str],
    ) -> (
        tempfile::TempDir,
        ImageService,
        velarx_content::serve_fetch::ServerThread,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let key = tmp.path().join("acme.pub");
        std::fs::write(&key, public).unwrap();
        let policy = tmp.path().join("policy.json");
        std::fs::write(
            &policy,
            serde_json::json!({
                "default": [{"type": "insecureAcceptAnything"}],
                "transports": {"docker": {"docker.io/acme": [
                    {"type": "sigstoreSigned", "keyPath": key}
                ]}}
            })
            .to_string(),
        )
        .unwrap();
        let socket = tmp.path().join("peer.sock");
        let served = velarx_content::serve_fetch::serve_in_thread(
            std::os::unix::net::UnixListener::bind(&socket).unwrap(),
            Arc::new(velarx_content::fakes::Metadata(
                serde_json::to_vec(records).unwrap(),
            )),
            velarx_content::activation::Limits::default(),
        )
        .unwrap();
        let db = velarx_db::Database::open_in_memory().await.unwrap();
        let store = Arc::new(velarx_storage::FileStore::new(tmp.path().join("objects")).unwrap());
        let service = ImageService::new(
            db,
            store,
            tmp.path().join("pulls"),
            velarx_storage::VerityMode::Off,
        )
        .unwrap()
        .with_fetchers(vec![velarx_config::ExternalSourceConfig {
            name: "peer".into(),
            socket: Some(socket),
            dir: None,
            idle_timeout_secs: 15,
            settings: Default::default(),
        }])
        .with_pull_config(velarx_config::PullConfig {
            names: names.iter().map(|n| n.to_string()).collect(),
            policy_path: Some(policy),
            ..Default::default()
        })
        .unwrap();
        (tmp, service, served)
    }

    async fn resolved(service: &ImageService, name: &str) -> ImageResult<Option<Digest>> {
        let image_ref = ImageReference::parse(name).unwrap();
        let requirements = service.policy_for(&image_ref)?;
        service.resolve_tag(&image_ref, &requirements).await
    }

    /// A tag is the digest of the newest record a key of the policy signed
    /// for it, from a source that is believed for nothing else; and what
    /// cannot be resolved says why.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_tag_is_resolved_by_the_newest_signed_record_of_the_names_sources() {
        let ((mine, public), (other, _)) = (signer(), signer());
        let records = [
            record_of(&mine, FIRST, 100),
            record_of(&mine, SECOND, 200),
            // newer, by a key the policy does not name
            record_of(&other, FIRST, 300),
        ];
        let (_tmp, service, _served) = resolving(&public, &records, &["peer"]).await;
        let got = resolved(&service, "acme/app:1").await.unwrap();
        assert_eq!(got.map(|d| d.to_string()).as_deref(), Some(SECOND));
        // (another tag has no record: the signatures are for `:1`)
        let e = resolved(&service, "acme/app:2").await.unwrap_err();
        assert!(e.to_string().contains("none signed by a key"), "{e}");
        // (a policy that asks for no signature says nobody names the tag)
        let e = resolved(&service, "quay.io/x/y:1").await.unwrap_err();
        assert!(e.to_string().contains("names no key"), "{e}");
        let (_tmp, none, _served) = resolving(&public, &[], &["peer"]).await;
        let e = resolved(&none, "acme/app:1").await.unwrap_err();
        assert!(
            e.to_string().contains("no source has a signed record"),
            "{e}"
        );
        // two records of the same time that disagree
        let tied = [record_of(&mine, FIRST, 100), record_of(&mine, SECOND, 100)];
        let (_tmp, service, _served) = resolving(&public, &tied, &["peer"]).await;
        let e = resolved(&service, "acme/app:1").await.unwrap_err();
        assert!(e.to_string().contains("same time"), "{e}");
        // the registry first: it says, as it always did
        let (_tmp, service, _served) = resolving(&public, &records, &["registry", "peer"]).await;
        assert_eq!(resolved(&service, "acme/app:1").await.unwrap(), None);
    }

    /// A service whose policy is `policy` (the JSON text).
    async fn with_policy(policy: &str) -> (tempfile::TempDir, ImageService) {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("policy.json");
        std::fs::write(&file, policy).unwrap();
        let db = velarx_db::Database::open_in_memory().await.unwrap();
        let store = Arc::new(velarx_storage::FileStore::new(tmp.path().join("objects")).unwrap());
        let service = ImageService::new(
            db,
            store,
            tmp.path().join("pulls"),
            velarx_storage::VerityMode::Off,
        )
        .unwrap()
        .with_pull_config(velarx_config::PullConfig {
            policy_path: Some(file),
            ..Default::default()
        })
        .unwrap();
        (tmp, service)
    }

    fn scope_of(service: &ImageService, name: &str) -> String {
        service
            .scoped_requirements_of(&ImageReference::parse(name).unwrap())
            .unwrap()
            .0
    }

    /// The four spellings of the one image of Docker Hub are in the scopes
    /// of its name, whichever way the policy writes them.
    #[tokio::test]
    async fn the_spellings_of_a_docker_hub_image_have_one_scope() {
        let spellings = [
            "alpine",
            "docker.io/alpine",
            "docker.io/library/alpine",
            "index.docker.io/library/alpine",
        ];
        for scope in ["docker.io/library/alpine", "docker.io/library"] {
            let (_tmp, service) = with_policy(&format!(
                r#"{{"default": [{{"type": "insecureAcceptAnything"}}],
                    "transports": {{"docker": {{"{scope}": [{{"type": "reject"}}]}}}}}}"#
            ))
            .await;
            for name in spellings {
                assert_eq!(
                    scope_of(&service, name),
                    format!("scope {scope}"),
                    "{name} against {scope}"
                );
            }
        }
    }

    /// A host in capitals is refused, and the message says to write it in
    /// lower case: it would be the same registry for DNS and another one
    /// for the scopes of the policy and the blocks of registries.conf,
    /// which compare the text.
    #[tokio::test]
    async fn a_host_in_capitals_is_refused() {
        let (_tmp, service) = with_policy(
            r#"{"default": [{"type": "insecureAcceptAnything"}],
                "transports": {"docker": {"quay.io/x": [{"type": "reject"}]}}}"#,
        )
        .await;
        assert_eq!(scope_of(&service, "quay.io/x/y"), "scope quay.io/x");
        let image = test_image();
        service.db.insert_image(&image).await.unwrap();
        let block = "[[registry]]\nprefix = \"quay.io\"\nblocked = true\n";
        assert!(endpoints_of(block, "quay.io/x/y").is_err());
        for name in ["Quay.io/x/y", "Quay.IO/x/y"] {
            let e = ImageReference::parse(name).unwrap_err().to_string();
            assert!(e.contains("host is written in lower case"), "{e}");
            assert!(endpoints_of(block, name).is_err());
            assert!(endpoints_of("", name).is_err());
            assert!(service.tag(&image.id, name).await.is_err());
        }
    }

    /// The image `quay.io/x/y:1` (its manifest is `{}`), as the create and
    /// the start judge it, with `signatures` as its pulls found them.
    async fn judged_with(
        service: &ImageService,
        judging: SignatureJudging,
        names: &[&str],
        signatures: &[Signature],
    ) -> ImageResult<()> {
        let manifest = "{}".to_string();
        let digest = Digest::of(velarx_types::digest::Algorithm::Sha256, manifest.as_bytes());
        let image = velarx_db::ImageRecord {
            id: "0".repeat(64),
            manifest_digest: digest,
            config_digest: digest,
            manifest,
            config: "{}".into(),
            created_at: String::new(),
            is_lazy: false,
        };
        let tags: Vec<ImageTag> = names
            .iter()
            .map(|name| {
                let (repository, tag) = name.rsplit_once(':').unwrap();
                ImageTag {
                    repository: repository.into(),
                    tag: tag.into(),
                    image_id: image.id.clone(),
                }
            })
            .collect();
        let pulled = match signatures.is_empty() {
            true => Vec::new(),
            false => vec![service
                .pull_record(&ImageReference::parse("quay.io/x/y:1").unwrap(), signatures)
                .unwrap()],
        };
        service
            .verify_pulled(
                names.first().copied().unwrap_or(""),
                &image,
                &tags,
                judging,
                pulled,
            )
            .await
    }

    async fn judged(policy: &str, judging: SignatureJudging) -> ImageResult<()> {
        let (_tmp, service) = with_policy(policy).await;
        judged_with(&service, judging, &["quay.io/x/y:1"], &[]).await
    }

    #[tokio::test]
    async fn a_scope_with_only_a_signed_base_layer_at_create_and_start() {
        let policy = r#"{"default": [{"type": "insecureAcceptAnything"}],
            "transports": {"docker": {"quay.io/x": [{"type": "signedBaseLayer",
                "baseLayerIdentity": {"type": "matchRepository"}}]}}}"#;
        // (documented: in this mode the requirements that only refuse, as
        // `reject`, are for pulls)
        judged(policy, SignatureJudging::Policy).await.unwrap();
        for judging in [SignatureJudging::Check, SignatureJudging::Require("why")] {
            let e = judged(policy, judging).await.unwrap_err();
            assert!(e.to_string().contains("signedBaseLayer"), "{e}");
        }
    }

    #[tokio::test]
    async fn a_reject_at_create_and_start() {
        let policy = r#"{"default": [{"type": "insecureAcceptAnything"}],
            "transports": {"docker": {"quay.io/x": [{"type": "reject"}]}}}"#;
        // (documented: in this mode `reject` is for pulls only)
        judged(policy, SignatureJudging::Policy).await.unwrap();
        let e = judged(policy, SignatureJudging::Check).await.unwrap_err();
        assert!(e.to_string().contains("rejects it"), "{e}");
        let e = judged(policy, SignatureJudging::Require("why"))
            .await
            .unwrap_err();
        assert!(e.to_string().contains("rejects it"), "{e}");
    }

    /// The signature `signer` makes of the manifest `{}` for `name`.
    fn signed_by(signer: &velarx_signature::sign::Signer, name: &str) -> Signature {
        let digest = Digest::of(velarx_types::digest::Algorithm::Sha256, b"{}");
        Signature::Sigstore(
            signer
                .sign_manifest(&digest.to_string(), name, "test", 100)
                .unwrap(),
        )
    }

    /// What a pull decides of `quay.io/x/y:1` given `signatures`: the
    /// pre-check, and when it asks for signatures, their evaluation.
    async fn pulled_with(service: &ImageService, signatures: &[Signature]) -> ImageResult<()> {
        let image_ref = ImageReference::parse("quay.io/x/y:1").unwrap();
        let requirements = service.policy_for(&image_ref)?;
        if !evaluate::needs_signatures(Mode::Whole, &requirements) {
            return Ok(());
        }
        accepted_blocking(
            Mode::Whole,
            requirements,
            intended(&image_ref)?,
            b"{}".to_vec(),
            signatures.to_vec(),
        )
        .await
        .map(|_| ())
    }

    /// The decision on a list of requirements of one scope, for the pull and
    /// for each way the create and the start judge, with the image signed
    /// by the key `good` and not by `other` (every row: what the list is, and
    /// whether the pull, `Policy`, `Check` and `Require` accept).  The pull
    /// and `Check` are the same decision.
    #[tokio::test]
    async fn a_list_of_requirements_is_judged_by_the_pull_and_by_each_judging() {
        let (signer, good) = signer();
        let (_, other) = self::signer();
        let tmp = tempfile::tempdir().unwrap();
        for (name, key) in [("good", &good), ("other", &other)] {
            std::fs::write(tmp.path().join(name), key).unwrap();
        }
        let dir = tmp.path().display();
        let key =
            |name: &str| format!(r#"{{"type": "sigstoreSigned", "keyPath": "{dir}/{name}"}}"#);
        let anything = r#"{"type": "insecureAcceptAnything"}"#;
        let reject = r#"{"type": "reject"}"#;
        let base_layer = r#"{"type": "signedBaseLayer"}"#;
        let missing = format!(r#"{{"type": "sigstoreSigned", "keyPath": "{dir}/missing"}}"#);
        let elsewhere = format!(
            r#"{{"type": "sigstoreSigned", "keyPath": "{dir}/good",
                "signedIdentity": {{"type": "exactReference", "dockerReference": "quay.io/x/y:2"}}}}"#
        );
        let (good, other) = (key("good"), key("other"));
        // pull, Policy, Check, Require
        let rows: Vec<(&str, Vec<&str>, [bool; 4])> = vec![
            (
                "only insecureAcceptAnything",
                vec![anything],
                [true, true, true, false],
            ),
            ("reject", vec![reject], [false, true, false, false]),
            (
                "signedBaseLayer",
                vec![base_layer],
                [false, true, false, false],
            ),
            (
                "reject and a signature that holds",
                vec![reject, &good],
                [false, true, false, false],
            ),
            (
                "reject and one that does not",
                vec![reject, &other],
                [false; 4],
            ),
            (
                "signedBaseLayer and a signature that holds",
                vec![base_layer, &good],
                [false, true, false, false],
            ),
            ("a key that cannot be loaded", vec![&missing], [false; 4]),
            ("a signature that holds", vec![&good], [true; 4]),
            ("one that does not", vec![&other], [false; 4]),
            (
                "a signature of another reference",
                vec![&elsewhere],
                [false; 4],
            ),
            ("both, the first holds", vec![&good, &other], [false; 4]),
            ("both, the second holds", vec![&other, &good], [false; 4]),
            ("the same twice", vec![&good, &good], [true; 4]),
            (
                "insecureAcceptAnything and a signature that holds",
                vec![anything, &good],
                [true; 4],
            ),
            (
                "insecureAcceptAnything and one that does not",
                vec![anything, &other],
                [false; 4],
            ),
        ];
        let signatures = [signed_by(&signer, "quay.io/x/y:1")];
        for (what, list, expected) in rows {
            let (_tmp, service) = with_policy(&format!(
                r#"{{"default": [{anything}],
                    "transports": {{"docker": {{"quay.io/x": [{}]}}}}}}"#,
                list.join(",")
            ))
            .await;
            let mut got = vec![pulled_with(&service, &signatures).await.is_ok()];
            for judging in [
                SignatureJudging::Policy,
                SignatureJudging::Check,
                SignatureJudging::Require("why"),
            ] {
                let result = judged_with(&service, judging, &["quay.io/x/y:1"], &signatures).await;
                got.push(result.is_ok());
            }
            assert_eq!(got, expected, "{what}");
        }
    }

    /// An image without a name cannot be judged by `Check` and `Require`;
    /// `Policy` accepts it.
    #[tokio::test]
    async fn an_image_with_no_name_is_judged_by_the_policy_only() {
        let (_tmp, service) = with_policy(r#"{"default": [{"type": "reject"}]}"#).await;
        judged_with(&service, SignatureJudging::Policy, &[], &[])
            .await
            .unwrap();
        for judging in [SignatureJudging::Check, SignatureJudging::Require("why")] {
            let e = judged_with(&service, judging, &[], &[]).await.unwrap_err();
            assert!(e.to_string().contains("has no name"), "{e}");
        }
    }

    /// Every name of the image is judged, each by the requirements of its
    /// own scope; one that is refused refuses the image.
    #[tokio::test]
    async fn every_name_of_an_image_is_judged() {
        let (signer, public) = signer();
        let tmp = tempfile::tempdir().unwrap();
        let key = tmp.path().join("key");
        std::fs::write(&key, public).unwrap();
        let signed = format!(
            r#"[{{"type": "sigstoreSigned", "keyPath": "{}"}}]"#,
            key.display()
        );
        let (_tmp, service) = with_policy(&format!(
            r#"{{"default": [{{"type": "insecureAcceptAnything"}}],
                "transports": {{"docker": {{"quay.io/x": {signed}, "quay.io/w": {signed}}}}}}}"#
        ))
        .await;
        let both = ["quay.io/x/y:1", "quay.io/w/z:1"];
        let signatures = [signed_by(&signer, "quay.io/x/y:1")];
        let free = ["quay.io/x/y:1", "quay.io/free/z:1"];
        for judging in [
            SignatureJudging::Policy,
            SignatureJudging::Check,
            SignatureJudging::Require("why"),
        ] {
            // a name that needs a signature for it
            let e = judged_with(&service, judging, &both, &signatures)
                .await
                .unwrap_err();
            assert!(e.to_string().contains("is not accepted"), "{e}");
            // the signature of the first name does not accept the second
            judged_with(&service, judging, &free[..1], &signatures)
                .await
                .unwrap();
        }
        // a name that the policy accepts without a signature
        let result = |judging| judged_with(&service, judging, &free, &signatures);
        result(SignatureJudging::Policy).await.unwrap();
        result(SignatureJudging::Check).await.unwrap();
        let e = result(SignatureJudging::Require("why")).await.unwrap_err();
        assert!(
            e.to_string().contains("accepts it without a signature"),
            "{e}"
        );
    }

    #[tokio::test]
    async fn a_pull_refuses_reject_and_signed_base_layer() {
        for (rule, said) in [
            (r#"{"type": "reject"}"#, "rejects it"),
            (r#"{"type": "signedBaseLayer"}"#, "signedBaseLayer"),
        ] {
            let (_tmp, service) = with_policy(&format!(
                r#"{{"default": [{{"type": "insecureAcceptAnything"}}],
                    "transports": {{"docker": {{"quay.io/x": [{rule}]}}}}}}"#
            ))
            .await;
            let e = service
                .policy_for(&ImageReference::parse("quay.io/x/y:1").unwrap())
                .unwrap_err();
            assert!(e.to_string().contains(said), "{e}");
            service
                .policy_for(&ImageReference::parse("quay.io/z/y:1").unwrap())
                .unwrap();
        }
    }

    /// The pre-check of a pull answers before any signature is fetched: a
    /// list with a `reject` is refused whatever else it holds; the other
    /// lists give their requirements.
    #[tokio::test]
    async fn the_pre_check_of_a_pull_sees_the_whole_list() {
        let signed = r#"{"type": "signedBy", "keyType": "GPGKeys", "keyPath": "/k"}"#;
        let anything = r#"{"type": "insecureAcceptAnything"}"#;
        for (list, refused) in [
            (vec![anything], false),
            (vec![signed], false),
            (vec![anything, signed], false),
            (vec![signed, r#"{"type": "reject"}"#], true),
            (vec![r#"{"type": "reject"}"#, signed], true),
            (
                vec![anything, r#"{"type": "signedBaseLayer"}"#, signed],
                true,
            ),
        ] {
            let (_tmp, service) = with_policy(&format!(
                r#"{{"default": [{anything}],
                    "transports": {{"docker": {{"quay.io/x": [{}]}}}}}}"#,
                list.join(",")
            ))
            .await;
            let got = service.policy_for(&ImageReference::parse("quay.io/x/y:1").unwrap());
            assert_eq!(got.is_err(), refused, "{list:?}");
            if let Ok(requirements) = got {
                assert_eq!(requirements.len(), list.len(), "{list:?}");
            }
        }
    }

    #[test]
    fn the_intended_reference_keeps_tag_and_digest() {
        let r = intended(&ImageReference::parse("busybox").unwrap()).unwrap();
        assert_eq!(r.string(), "docker.io/library/busybox:latest");
        let r = intended(&ImageReference::parse("docker.io/busybox:1").unwrap()).unwrap();
        assert_eq!(r.string(), "docker.io/library/busybox:1");
        let d = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let r = intended(&ImageReference::parse(&format!("quay.io/a/b@{d}")).unwrap()).unwrap();
        assert_eq!(r.string(), format!("quay.io/a/b@{d}"));
    }

    /// The (host, repository) pairs a pull of `name` asks, mirrors first,
    /// with the registries.conf `conf`; or why it is refused.
    fn endpoints_of(conf: &str, name: &str) -> Result<Vec<(String, String)>, String> {
        let transport = velarx_registry::target::TransportConfig {
            registries: velarx_registry::RegistriesConfig::parse(conf).unwrap(),
            certs_dirs: Vec::new(),
            tls_verify: true,
        };
        let r = ImageReference::parse(name).map_err(|e| e.to_string())?;
        r.validate().map_err(|e| e.to_string())?;
        transport
            .endpoints(&r.registry, &r.repository, r.digest.is_some(), true)
            .map(|endpoints| {
                endpoints
                    .into_iter()
                    .map(|e| (e.host, e.repository))
                    .collect()
            })
            .map_err(|e| e.to_string())
    }

    fn pair(host: &str, repository: &str) -> (String, String) {
        (host.to_string(), repository.to_string())
    }

    /// An image whose manifest is `{}`.
    fn test_image() -> velarx_db::ImageRecord {
        let manifest = "{}".to_string();
        let digest = Digest::of(velarx_types::digest::Algorithm::Sha256, manifest.as_bytes());
        velarx_db::ImageRecord {
            id: "0".repeat(64),
            manifest_digest: digest,
            config_digest: digest,
            manifest,
            config: "{}".into(),
            created_at: String::new(),
            is_lazy: false,
        }
    }

    /// `docker.io/alpine` and `docker.io/library/alpine` are one image for
    /// the signature policy (the scope, the identity judged), but not for
    /// the request (the path asked) nor for registries.conf (the prefix).
    #[tokio::test]
    async fn docker_io_alpine_is_judged_as_library_alpine_and_asked_as_alpine() {
        let (_tmp, service) = with_policy(
            r#"{"default": [{"type": "insecureAcceptAnything"}],
                "transports": {"docker": {"docker.io/library/alpine": [{"type": "reject"}]}}}"#,
        )
        .await;
        let hub = "registry-1.docker.io";
        for (name, path) in [
            ("alpine", "library/alpine"),
            ("docker.io/library/alpine", "library/alpine"),
            // Pins a disagreement: the request is for `alpine` (not `library/alpine`) though the policy judges it as `library/alpine`; a reader expects one name for both.
            ("docker.io/alpine", "alpine"),
        ] {
            let r = ImageReference::parse(name).unwrap();
            assert_eq!(scope_of(&service, name), "scope docker.io/library/alpine");
            assert_eq!(
                intended(&r).unwrap().string(),
                "docker.io/library/alpine:latest"
            );
            assert!(service.policy_for(&r).is_err(), "{name}");
            assert_eq!(endpoints_of("", name).unwrap(), [pair(hub, path)], "{name}");
        }
        // a block, or a mirror, written for the name the policy uses
        let block = "[[registry]]\nprefix = \"docker.io/library/alpine\"\nblocked = true\n";
        let mirror = "[[registry]]\nprefix = \"docker.io/library\"\n[[registry.mirror]]\nlocation = \"m.example/lib\"\n";
        assert!(endpoints_of(block, "alpine").is_err());
        assert!(endpoints_of(block, "docker.io/library/alpine").is_err());
        // Pins a disagreement: the block of `docker.io/library/alpine` does not apply to `docker.io/alpine`; a reader expects it to be refused.
        assert_eq!(
            endpoints_of(block, "docker.io/alpine").unwrap(),
            [pair(hub, "alpine")]
        );
        assert_eq!(
            endpoints_of(mirror, "alpine").unwrap(),
            [pair("m.example", "lib/alpine"), pair(hub, "library/alpine")]
        );
        // Pins a disagreement: the mirror of `docker.io/library` is not asked for `docker.io/alpine`; a reader expects it to be.
        assert_eq!(
            endpoints_of(mirror, "docker.io/alpine").unwrap(),
            [pair(hub, "alpine")]
        );
    }

    /// `index.docker.io` is `docker.io` for the signature policy, and a
    /// registry of its own for registries.conf: a block of `docker.io` does
    /// not refuse it, and a mirror of `docker.io` is not used.
    #[tokio::test]
    async fn index_docker_io_escapes_a_block_of_docker_io() {
        let (_tmp, service) = with_policy(
            r#"{"default": [{"type": "reject"}],
                "transports": {"docker": {"docker.io/a": [{"type": "insecureAcceptAnything"}]}}}"#,
        )
        .await;
        for name in ["docker.io/a/b", "index.docker.io/a/b"] {
            assert_eq!(scope_of(&service, name), "scope docker.io/a", "{name}");
            assert!(service
                .policy_for(&ImageReference::parse(name).unwrap())
                .is_ok());
        }
        let block = "[[registry]]\nprefix = \"docker.io\"\nblocked = true\n";
        let e = endpoints_of(block, "docker.io/a/b").unwrap_err();
        assert!(e.contains("is blocked in registries.conf"), "{e}");
        // Pins a disagreement: the block of `docker.io` does not refuse `index.docker.io`, which the policy judges as `docker.io`; a reader expects it to be refused.
        assert_eq!(
            endpoints_of(block, "index.docker.io/a/b").unwrap(),
            [pair("index.docker.io", "a/b")]
        );
        let mirror =
            "[[registry]]\nprefix = \"docker.io\"\n[[registry.mirror]]\nlocation = \"m.example\"\n";
        assert_eq!(
            endpoints_of(mirror, "docker.io/a/b").unwrap(),
            [
                pair("m.example", "a/b"),
                pair("registry-1.docker.io", "a/b")
            ]
        );
        // Pins a disagreement: no mirror of `docker.io` is used for `index.docker.io`; a reader expects the same endpoints.
        assert_eq!(
            endpoints_of(mirror, "index.docker.io/a/b").unwrap(),
            [pair("index.docker.io", "a/b")]
        );
    }

    /// An image tagged `docker.io/a.b/c` is stored as `a.b/c`, and every
    /// reader of the stored name takes `a.b` for a host: the signature
    /// policy judges it by the scope `a.b`, and a pull by the name asks
    /// that host.
    #[tokio::test]
    async fn a_docker_io_name_with_a_dotted_first_component_is_stored_as_another_host() {
        let (_tmp, service) = with_policy(
            r#"{"default": [{"type": "insecureAcceptAnything"}],
                "transports": {"docker": {
                    "a.b": [{"type": "reject"}],
                    "docker.io/a.b": [{"type": "insecureAcceptAnything"}]}}}"#,
        )
        .await;
        let image = test_image();
        service.db.insert_image(&image).await.unwrap();
        service.tag(&image.id, "docker.io/a.b/c").await.unwrap();
        let tags = service.get_tags(&image.id).await.unwrap();
        // Pins a disagreement: the repository stored is `a.b/c`, without the registry `docker.io`; a reader expects the name to be read back as it was written.
        assert_eq!(
            tags.iter()
                .map(|t| (t.repository.as_str(), t.tag.as_str()))
                .collect::<Vec<_>>(),
            [("a.b/c", "latest")]
        );
        let stored = ImageReference::parse("a.b/c:latest").unwrap();
        assert_eq!(
            (stored.registry.as_str(), stored.repository.as_str()),
            ("a.b", "c")
        );
        // the name written is found by its text, as is the stored one
        assert_eq!(service.get("docker.io/a.b/c").await.unwrap().id, image.id);
        assert_eq!(service.get("a.b/c").await.unwrap().id, image.id);
        // the policy: the scope of the host `a.b`, not of `docker.io/a.b`
        assert_eq!(scope_of(&service, "docker.io/a.b/c"), "scope docker.io/a.b");
        assert_eq!(scope_of(&service, "a.b/c"), "scope a.b");
        let e = service
            .verify_pulled(
                "a.b/c:latest",
                &image,
                &tags,
                SignatureJudging::Check,
                Vec::new(),
            )
            .await
            .unwrap_err();
        assert!(e.to_string().contains("rejects it (scope a.b)"), "{e}");
        // the request: the host a.b, not the registry of Docker Hub
        assert_eq!(
            endpoints_of("", "docker.io/a.b/c").unwrap(),
            [pair("registry-1.docker.io", "a.b/c")]
        );
        assert_eq!(
            endpoints_of("", "a.b/c:latest").unwrap(),
            [pair("a.b", "c")]
        );
    }

    /// `image tag` refuses a name that the grammar of the references
    /// refuses, as a pull does: nothing is stored that no create could judge.
    #[tokio::test]
    async fn image_tag_refuses_the_names_that_a_pull_refuses() {
        let d = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let long_tag = format!("a:{}", "t".repeat(129));
        let (_tmp, service) =
            with_policy(r#"{"default": [{"type": "insecureAcceptAnything"}]}"#).await;
        let image = test_image();
        service.db.insert_image(&image).await.unwrap();
        for target in [
            "Foo/bar",
            "Quay.IO/a/b",
            "quay.io//a",
            "a/",
            "/a",
            "../x",
            "quay.io/a b",
            "quay.io/a?x=1",
            "quay.io/a%2f..%2fb",
            "a:",
            "a:.x",
            "quay.io/a..b",
            ":5000/x",
            " alpine\n",
            &long_tag,
            &format!("x@y@{d}"),
        ] {
            assert!(service.tag(&image.id, target).await.is_err(), "{target:?}");
        }
        assert!(service.get_tags(&image.id).await.unwrap().is_empty());
        // (the tag before a digest is not stored: the digest names the image)
        service
            .tag(&image.id, &format!("quay.io/a:t@{d}"))
            .await
            .unwrap();
        let tags = service.get_tags(&image.id).await.unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(
            (tags[0].repository.as_str(), tags[0].tag.as_str()),
            ("quay.io/a", "latest")
        );
    }
}
