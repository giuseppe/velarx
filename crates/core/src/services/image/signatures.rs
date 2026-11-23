// SPDX-License-Identifier: Apache-2.0
//! The signatures of the images a pull gets: found where
//! registries.d says (lookaside storage, sigstore attachments), and
//! checked against the requirements of policy.json before anything else
//! of the image is fetched, as podman checks them.

use super::*;
use velarx_content::fetcher::fetch::SignedRecord;
use velarx_content::pull::net::Net;
use velarx_signature::evaluate::{self, Image, Manifest};
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
    requirements: Vec<PolicyRequirement>,
    reference: DockerRef,
    manifest: Vec<u8>,
    signatures: Vec<Signature>,
) -> ImageResult<Vec<usize>> {
    let job = tokio::task::spawn_blocking(move || {
        evaluate::accepted(
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
            if !evaluate::needs_signatures(requirements) {
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
        if !evaluate::needs_signatures(requirements) {
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
    /// requirement of the scope refuses the image, as podman's
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
        let mut signatures: Option<Vec<Signature>> = None;
        for name in names {
            let (scope, all) = self.scoped_requirements_of(&name)?;
            if judging != SignatureJudging::Policy
                && all.iter().any(|r| matches!(r, PolicyRequirement::Reject))
            {
                return Err(ImageError::Registry(format!(
                    "{}: the signature policy ({}) rejects it ({scope})",
                    name.full_name(),
                    self.policy_location()
                )));
            }
            let requirements = evaluate::signature_requirements(&all);
            if requirements.is_empty() {
                if let Some(why) = require {
                    return Err(ImageError::Registry(format!(
                        "{}: the signature policy ({}) accepts it without a signature, and {why}",
                        name.full_name(),
                        self.policy_location()
                    )));
                }
                continue;
            }
            if signatures.is_none() {
                signatures = Some(signatures_of(&pulled)?);
            }
            accepted_blocking(
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
                .and_then(|paths| paths.into_iter().find(|p| p.exists()))
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
}
