// SPDX-License-Identifier: Apache-2.0
//! Manifest lists made locally (`podman manifest`): an OCI image index whose
//! instances are images of the store or of a registry, pushed with them.

use super::archive::local_reference;
use super::*;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use velarx_db::ManifestListRecord;
use velarx_registry::target::{select_platform, Platform};
use velarx_types::transport::ImageLocation;

pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
/// The largest number of instances of a list.
const MAX_INSTANCES: usize = 1000;
/// Where the stored index keeps the repositories the instances that are not
/// in the store come from; never shown or pushed.
const SOURCES_KEY: &str = "io.velarx.sources";
/// Where the stored index keeps the algorithm of its digest when it is not
/// SHA-256 (`manifest create --digest sha512`); never shown or pushed.
const DIGEST_KEY: &str = "io.velarx.digest";

/// A manifest list of the store.
#[derive(Debug, Clone)]
pub struct ManifestList {
    pub id: String,
    /// `localhost/name:tag`.
    pub names: Vec<String>,
    pub index: Value,
    /// The digest of the index as it is stored and pushed.
    pub digest: Digest,
    /// The algorithm of the digest of the index, and of the artifacts added
    /// to it.
    pub alg: Algorithm,
    pub created_at: String,
    /// The registry repository of the instances that are not in the store,
    /// by digest.
    pub sources: BTreeMap<String, String>,
    /// The index as it is stored (a change is written back only if it is
    /// still this).
    raw: String,
}

impl ManifestList {
    fn from_record(r: ManifestListRecord) -> ImageResult<Self> {
        let mut index: Value = serde_json::from_str(&r.manifest)?;
        let sources = index
            .as_object_mut()
            .and_then(|o| o.remove(SOURCES_KEY))
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        let alg = match index
            .as_object_mut()
            .and_then(|o| o.remove(DIGEST_KEY))
            .as_ref()
            .and_then(Value::as_str)
        {
            Some(name) => Algorithm::from_name(name)
                .map_err(|e| invalid(format!("the manifest list {}: {e}", r.id)))?,
            None => Algorithm::Sha256,
        };
        Ok(Self {
            alg,
            digest: Digest::of(alg, &serde_json::to_vec(&index)?),
            sources,
            id: r.id,
            names: r
                .names
                .iter()
                .map(|(repo, tag)| format!("{repo}:{tag}"))
                .collect(),
            index,
            created_at: r.created_at,
            raw: r.manifest,
        })
    }

    pub fn instances(&self) -> &[Value] {
        self.index["manifests"]
            .as_array()
            .map_or(&[], Vec::as_slice)
    }
}

pub use velarx_wire::wire::{InstanceOptions, ManifestRequest};

/// How images are added to a list.
#[derive(Debug, Clone)]
pub struct AddOptions {
    /// Every instance of a list given as an image.
    pub all: bool,
    pub instance: InstanceOptions,
    pub tls_verify: bool,
    pub access: velarx_registry::auth::RegistryAccess,
}

impl Default for AddOptions {
    fn default() -> Self {
        Self {
            all: false,
            instance: InstanceOptions::default(),
            tls_verify: true,
            access: Default::default(),
        }
    }
}

/// How a list is pushed.
#[derive(Debug, Clone)]
pub struct ListPushOptions {
    /// The instances too (else only the index: the registry must have them).
    pub all: bool,
    pub tls_verify: bool,
    pub access: velarx_registry::auth::RegistryAccess,
    pub compression: Option<velarx_content::layer::writer::Compression>,
    /// The level of the layers that are compressed.
    pub compression_level: Option<i32>,
    /// Each instance of the store is pushed in these compressions too, as
    /// instances of their own (`--add-compression`).
    pub add_compression: Vec<velarx_content::layer::writer::Compression>,
    /// Sign the list and each of its instances with this key.
    pub sign: Option<Arc<velarx_signature::sign::Signer>>,
    /// The pushers of the push (`--sinks`); none: `[push] sinks`
    pub sinks: Option<Vec<String>>,
}

impl Default for ListPushOptions {
    fn default() -> Self {
        Self {
            all: true,
            tls_verify: true,
            access: Default::default(),
            compression: None,
            compression_level: None,
            add_compression: Vec::new(),
            sign: None,
            sinks: None,
        }
    }
}

fn empty_index() -> Value {
    json!({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": []})
}

fn invalid(m: impl Into<String>) -> ImageError {
    ImageError::Manifest(m.into())
}

/// `(repository, tag)` of a name typed by a user.
fn split_name(name: &str) -> ImageResult<(String, String)> {
    let r = ImageReference::parse(name)?;
    if r.digest.is_some() {
        return Err(invalid(format!(
            "`{name}`: a list is named by a tag, not a digest"
        )));
    }
    r.validate()?;
    Ok((r.name(), r.tag.unwrap_or_else(|| "latest".into())))
}

/// Apply the platform and annotations of `opts` to an instance.
pub(super) fn edit_instance(entry: &mut Value, opts: &InstanceOptions) {
    let Some(obj) = entry.as_object_mut() else {
        return;
    };
    if !opts.annotations.is_empty() {
        let a = obj.entry("annotations").or_insert_with(|| json!({}));
        if !a.is_object() {
            *a = json!({});
        }
        if let Some(a) = a.as_object_mut() {
            for (k, v) in &opts.annotations {
                a.insert(k.clone(), json!(v));
            }
        }
    }
    let p = obj.entry("platform").or_insert_with(|| json!({}));
    if !p.is_object() {
        *p = json!({});
    }
    let Some(p) = p.as_object_mut() else {
        return;
    };
    let set = |p: &mut Map<String, Value>, k: &str, v: &Option<String>| {
        if let Some(v) = v.as_ref().filter(|v| !v.is_empty()) {
            p.insert(k.into(), json!(v));
        }
    };
    set(p, "architecture", &opts.arch);
    set(p, "os", &opts.os);
    set(p, "os.version", &opts.os_version);
    set(p, "variant", &opts.variant);
    if !opts.features.is_empty() {
        p.insert("features".into(), json!(opts.features));
    }
    if !opts.os_features.is_empty() {
        p.insert("os.features".into(), json!(opts.os_features));
    }
    if p.is_empty() {
        obj.remove("platform");
    }
}

/// The `os/arch` the instance options ask for, the host's by default.
fn wanted_platform(opts: &InstanceOptions) -> Platform {
    let host = Platform::host();
    Platform {
        os: opts.os.clone().filter(|s| !s.is_empty()).unwrap_or(host.os),
        arch: opts
            .arch
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or(host.arch),
        variant: opts.variant.clone().filter(|s| !s.is_empty()),
    }
}

/// The text of the index as the database keeps it: with the sources of the
/// instances that are still in it.
fn stored_index(
    index: &Value,
    sources: &BTreeMap<String, String>,
    alg: Algorithm,
) -> ImageResult<String> {
    let mut stored = index.clone();
    if alg != Algorithm::Sha256 {
        stored[DIGEST_KEY] = json!(alg.name());
    }
    // Only the instances that are still in the list.
    let kept: BTreeMap<&String, &String> = sources
        .iter()
        .filter(|(d, _)| {
            index["manifests"]
                .as_array()
                .is_some_and(|m| m.iter().any(|m| m["digest"].as_str() == Some(d.as_str())))
        })
        .collect();
    if !kept.is_empty() {
        stored[SOURCES_KEY] = json!(kept);
    }
    Ok(serde_json::to_string(&stored)?)
}

impl ImageService {
    /// The list `reference` names: an id, an id prefix, or a name.
    pub async fn manifest_lookup(&self, reference: &str) -> ImageResult<Option<ManifestList>> {
        let reference = velarx_types::digest::without_algorithm(reference);
        let mut names = Vec::new();
        if let Ok(r) = ImageReference::parse(reference) {
            if r.digest.is_none() {
                let unqualified = r.registry == "docker.io" && !reference.starts_with("docker.io/");
                names.push((r.name(), r.tag.clone().unwrap_or_else(|| "latest".into())));
                if unqualified {
                    if let Ok(local) = ImageReference::parse(&format!("localhost/{reference}")) {
                        names.push((local.name(), local.tag.unwrap_or_else(|| "latest".into())));
                    }
                }
            }
        }
        if let Some(r) = self.db.find_manifest_list(Some(reference), None).await? {
            return Ok(Some(ManifestList::from_record(r)?));
        }
        for (repo, tag) in &names {
            if let Some(r) = self.db.find_manifest_list(None, Some((repo, tag))).await? {
                return Ok(Some(ManifestList::from_record(r)?));
            }
        }
        Ok(None)
    }

    pub(super) async fn manifest_get(&self, reference: &str) -> ImageResult<ManifestList> {
        self.manifest_lookup(reference)
            .await?
            .ok_or_else(|| ImageError::NotFound(format!("{reference}: no such manifest list")))
    }

    pub async fn manifest_lists(&self) -> ImageResult<Vec<ManifestList>> {
        self.db
            .list_manifest_lists()
            .await?
            .into_iter()
            .map(ManifestList::from_record)
            .collect()
    }

    /// Create the list `name` with the images `images`.  With `amend` an
    /// existing list of that name is returned (and the images added to it).
    pub async fn manifest_create(
        &self,
        name: &str,
        images: &[String],
        add: &AddOptions,
        index_annotations: &BTreeMap<String, String>,
        amend: bool,
        digest: Option<&str>,
    ) -> ImageResult<String> {
        let alg = self.creation_algorithm(digest)?;
        let local = local_reference(name)?;
        let (repo, tag) = split_name(&local)?;
        if let Some(existing) = self
            .db
            .find_manifest_list(None, Some((&repo, &tag)))
            .await?
        {
            if !amend {
                return Err(ImageError::Storage(format!(
                    "the manifest list {local} exists already (use amend)"
                )));
            }
            // (the digests of a list are those it was made with)
            let have = ManifestList::from_record(existing.clone())?.alg;
            if digest.is_some_and(|d| !d.is_empty()) && have != alg {
                return Err(invalid(format!(
                    "the manifest list {local} has {have} digests, not {alg}"
                )));
            }
            if !images.is_empty() {
                self.manifest_add(&existing.id, images, add).await?;
            }
            return Ok(existing.id);
        }
        let mut index = empty_index();
        if !index_annotations.is_empty() {
            index["annotations"] = json!(index_annotations);
        }
        self.check_digest_algorithm(alg)?;
        // (a random name, no digest of anything)
        let id = Digest::of(Algorithm::Sha256, &velarx_base::random::bytes16()).hex();
        self.db
            .create_manifest_list(&ManifestListRecord {
                id: id.clone(),
                manifest: stored_index(&index, &BTreeMap::new(), alg)?,
                created_at: chrono::Utc::now().to_rfc3339(),
                names: vec![(repo, tag)],
            })
            .await?;
        if !images.is_empty() {
            if let Err(e) = self.manifest_add(&id, images, add).await {
                let _ = self.db.remove_manifest_list(&id).await;
                return Err(e);
            }
        }
        Ok(id)
    }

    /// The descriptor of a local image for a list.
    async fn local_instance(&self, reference: &str) -> ImageResult<Value> {
        let image = self.get(reference).await?;
        let manifest: Value = serde_json::from_str(&image.manifest)?;
        let config: OciConfig = serde_json::from_str(&image.config)?;
        let media_type = manifest["mediaType"]
            .as_str()
            .unwrap_or(OCI_MANIFEST)
            .to_string();
        let mut platform = json!({"architecture": config.architecture, "os": config.os});
        let cfg: Value = serde_json::from_str(&image.config)?;
        if let Some(v) = cfg["variant"].as_str().filter(|v| !v.is_empty()) {
            platform["variant"] = json!(v);
        }
        Ok(json!({
            "mediaType": media_type,
            "digest": image.manifest_digest,
            "size": image.manifest.len(),
            "platform": platform,
        }))
    }

    /// The descriptors a registry reference gives: the instance for the
    /// platform asked (or every one with `all`) of an index, the manifest
    /// otherwise.
    async fn remote_instances(
        &self,
        reference: &str,
        add: &AddOptions,
    ) -> ImageResult<(Vec<Value>, String)> {
        let image_ref = ImageReference::parse(reference)?;
        image_ref.validate()?;
        self.check_policy(&image_ref)?;
        image_ref.validate()?;
        let net = self.inspect_net(&image_ref, add.tls_verify, &add.access)?;
        let wanted = super::pull::manifest_reference(&image_ref);
        let (body, mut digest) = net.manifest_top(&wanted).await?;
        if let Some(pinned) = &image_ref.digest {
            velarx_registry::target::verify_digest(pinned, &body)?;
            digest = *pinned;
        }
        let value: Value = serde_json::from_slice(&body)?;
        let repo = image_ref.name();
        if let Some(list) = value["manifests"].as_array() {
            if add.all {
                for m in list {
                    let d = m["digest"].as_str().unwrap_or_default();
                    velarx_types::docker::refuse_instance(list, d)?;
                }
                return Ok((list.clone(), repo));
            }
            let platform = wanted_platform(&add.instance);
            let chosen = select_platform(list, &platform)
                .ok_or_else(|| invalid(format!("no instance for {platform} in {reference}")))?;
            velarx_types::docker::refuse_instance(list, &chosen)?;
            return Ok((
                list.iter()
                    .filter(|m| m["digest"].as_str() == Some(chosen.as_str()))
                    .take(1)
                    .cloned()
                    .collect(),
                repo,
            ));
        }
        let manifest: OciManifest = serde_json::from_slice(&body)?;
        let (config, _) = net.config_raw(&manifest.config).await?;
        Ok((
            vec![json!({
                "mediaType": value["mediaType"].as_str().unwrap_or(OCI_MANIFEST),
                "digest": digest,
                "size": body.len(),
                "platform": {"architecture": config.architecture, "os": config.os},
            })],
            repo,
        ))
    }

    /// Change the list `reference`: `edit` is given its index and the
    /// sources of its instances and changes them, and the result is written
    /// back if the list is still what `edit` was given (else it is read
    /// again and `edit` runs again on it): two changes at once both stay.
    /// Whatever the change needs from the network or the store is done
    /// before, not in `edit`.
    pub(super) async fn edit_list(
        &self,
        reference: &str,
        mut edit: impl FnMut(&mut Value, &mut BTreeMap<String, String>) -> ImageResult<()>,
    ) -> ImageResult<String> {
        loop {
            let list = self.manifest_get(reference).await?;
            let mut index = list.index.clone();
            let mut sources = list.sources.clone();
            edit(&mut index, &mut sources)?;
            let stored = stored_index(&index, &sources, list.alg)?;
            if self
                .db
                .swap_manifest_list(&list.id, &list.raw, &stored)
                .await?
            {
                return Ok(list.id);
            }
        }
    }

    /// Add images to a list: `containers-storage:REF` (or an image of the
    /// store named without a transport) or `docker://REF` (a registry).
    pub async fn manifest_add(
        &self,
        reference: &str,
        images: &[String],
        add: &AddOptions,
    ) -> ImageResult<String> {
        // What the images are (the registry and the store are asked) comes
        // first: the list is read, merged and written back after it, and
        // written only if it did not change since it was read.
        let mut added: Vec<Vec<Value>> = Vec::new();
        let mut sources = BTreeMap::new();
        for image in images {
            let location = ImageLocation::parse(image).map_err(|e| invalid(e.to_string()))?;
            let mut entries = if let ImageLocation::Storage(local) = &location {
                vec![self.local_instance(local).await?]
            } else {
                // podman takes a name without a transport for a registry's.
                let ImageLocation::Registry(remote) = &location else {
                    return Err(invalid(format!(
                        "the transport {} is not supported by manifest add: only containers-storage: and docker:// can be used",
                        location.transport().trim_end_matches(':')
                    )));
                };
                let (entries, repo) = self.remote_instances(remote, add).await?;
                for e in &entries {
                    if let Some(d) = e["digest"].as_str() {
                        sources.insert(d.to_string(), repo.clone());
                    }
                }
                entries
            };
            for e in &mut entries {
                edit_instance(e, &add.instance);
            }
            added.push(entries);
        }
        self.edit_list(reference, |index, listed| {
            listed.extend(sources.clone());
            let manifests = index["manifests"]
                .as_array_mut()
                .ok_or_else(|| invalid("the index has no manifests"))?;
            for entries in &added {
                for e in entries {
                    // The same instance once: the last one wins.
                    manifests.retain(|m| m["digest"] != e["digest"]);
                    manifests.push(e.clone());
                }
                if manifests.len() > MAX_INSTANCES {
                    return Err(invalid(format!(
                        "a list has at most {MAX_INSTANCES} instances"
                    )));
                }
            }
            Ok(())
        })
        .await
    }

    /// Annotate the instance `instance` (a digest, or an image of the store)
    /// or, with none, the index itself.
    pub async fn manifest_annotate(
        &self,
        reference: &str,
        instance: Option<&str>,
        opts: &InstanceOptions,
        index_annotations: &BTreeMap<String, String>,
        subject: Option<&str>,
    ) -> ImageResult<String> {
        let digest = match instance.filter(|i| !i.is_empty()) {
            Some(instance) if instance.parse::<Digest>().is_ok() => Some(instance.to_string()),
            Some(instance) => {
                let local = instance
                    .strip_prefix("containers-storage:")
                    .unwrap_or(instance);
                Some(self.get(local).await?.manifest_digest.to_string())
            }
            None => None,
        };
        let subject = match subject.filter(|s| !s.is_empty()) {
            Some(subject) => {
                let s = self.local_instance(subject).await?;
                Some(json!({
                    "mediaType": s["mediaType"],
                    "digest": s["digest"],
                    "size": s["size"],
                }))
            }
            None => None,
        };
        self.edit_list(reference, |index, _| {
            if let Some(digest) = &digest {
                let entry = index["manifests"]
                    .as_array_mut()
                    .and_then(|m| {
                        m.iter_mut()
                            .find(|m| m["digest"].as_str() == Some(digest.as_str()))
                    })
                    .ok_or_else(|| ImageError::NotFound(format!("{digest} is not in the list")))?;
                edit_instance(entry, opts);
            }
            if !index_annotations.is_empty() {
                let a = index
                    .as_object_mut()
                    .ok_or_else(|| invalid("the index is not an object"))?
                    .entry("annotations")
                    .or_insert_with(|| json!({}));
                if let Some(a) = a.as_object_mut() {
                    for (k, v) in index_annotations {
                        a.insert(k.clone(), json!(v));
                    }
                }
            }
            if let Some(subject) = &subject {
                index["subject"] = subject.clone();
            }
            Ok(())
        })
        .await
    }

    /// Remove the instance `digest` from a list.
    pub async fn manifest_remove_instance(
        &self,
        reference: &str,
        digest: &str,
    ) -> ImageResult<String> {
        self.edit_list(reference, |index, _| {
            let manifests = index["manifests"]
                .as_array_mut()
                .ok_or_else(|| invalid("the index has no manifests"))?;
            let before = manifests.len();
            manifests.retain(|m| m["digest"].as_str() != Some(digest));
            if manifests.len() == before {
                return Err(ImageError::NotFound(format!("{digest} is not in the list")));
            }
            Ok(())
        })
        .await
    }

    /// Remove a list (not its instances): its id and names.
    pub async fn manifest_delete(&self, reference: &str) -> ImageResult<(String, Vec<String>)> {
        let list = self.manifest_get(reference).await?;
        self.db.remove_manifest_list(&list.id).await?;
        self.remove_artifacts(&list.id);
        Ok((list.id, list.names))
    }

    /// Give a list another name.
    pub async fn manifest_tag(&self, reference: &str, name: &str) -> ImageResult<()> {
        let list = self.manifest_get(reference).await?;
        let (repo, tag) = split_name(&local_reference(name)?)?;
        Ok(self.db.name_manifest_list(&list.id, &repo, &tag).await?)
    }

    /// The index of a local list, or what a registry serves for the
    /// reference.
    pub async fn manifest_inspect(
        &self,
        reference: &str,
        tls_verify: bool,
        access: &velarx_registry::auth::RegistryAccess,
    ) -> ImageResult<Value> {
        if let Some(list) = self.manifest_lookup(reference).await? {
            return Ok(list.index);
        }
        self.remote_manifest(reference, tls_verify, access).await
    }

    /// The manifest (an image's or an index) a registry has for `reference`.
    pub async fn remote_manifest(
        &self,
        reference: &str,
        tls_verify: bool,
        access: &velarx_registry::auth::RegistryAccess,
    ) -> ImageResult<Value> {
        let (body, _) = self
            .remote_manifest_raw(reference, tls_verify, access)
            .await?;
        Ok(serde_json::from_slice(&body)?)
    }

    /// The bytes of the manifest a registry has for `reference`, and its
    /// digest.
    pub(super) async fn remote_manifest_raw(
        &self,
        reference: &str,
        tls_verify: bool,
        access: &velarx_registry::auth::RegistryAccess,
    ) -> ImageResult<(Bytes, Digest)> {
        let image_ref = ImageReference::parse(reference)?;
        image_ref.validate()?;
        self.check_policy(&image_ref)?;
        image_ref.validate()?;
        let net = self.inspect_net(&image_ref, tls_verify, access)?;
        let wanted = super::pull::manifest_reference(&image_ref);
        let (body, mut digest) = net.manifest_top(&wanted).await?;
        if let Some(pinned) = &image_ref.digest {
            velarx_registry::target::verify_digest(pinned, &body)?;
            digest = *pinned;
        }
        Ok((body, digest))
    }

    /// The local image of the instance of a list for a platform.
    pub async fn manifest_instance_for(
        &self,
        list: &ManifestList,
        platform: &Platform,
    ) -> ImageResult<ImageRecord> {
        let digest = select_platform(list.instances(), platform)
            .ok_or_else(|| invalid(format!("no instance for {platform} in the manifest list")))?;
        let digest: Digest = digest
            .parse()
            .map_err(|e| invalid(format!("the instance {digest} of the manifest list: {e}")))?;
        self.db
            .get_image_by_digest(&digest)
            .await
            .map_err(|_| ImageError::NotFound(format!("the instance {digest} is not in the store")))
    }

    /// Push a list to `destination` (a registry reference with a tag): its
    /// instances of the store (with `all`), then the index, which names
    /// them as they were pushed.  Returns the digest of the index.
    pub async fn manifest_push(
        &self,
        reference: &str,
        destination: &str,
        opts: &ListPushOptions,
    ) -> ImageResult<Digest> {
        let (digest, placed) = self
            .manifest_push_noted(reference, destination, opts)
            .await?;
        for refused in placed.iter().filter(|p| !p.accepted) {
            tracing::warn!(
                "{destination}: the destination refused {}: {}",
                refused
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("{destination}@{digest}")),
                refused.reason.as_deref().unwrap_or("no reason given")
            );
        }
        Ok(digest)
    }

    /// [`manifest_push`](Self::manifest_push), and how the destination
    /// resolves the list by each name.
    pub async fn manifest_push_noted(
        &self,
        reference: &str,
        destination: &str,
        opts: &ListPushOptions,
    ) -> ImageResult<(Digest, Vec<velarx_proto::transfer::Placed>)> {
        // (a destination of the scheme of a `[[transports]]` is pushed
        // through its pusher like an image: the images of the list go by
        // their digests to its repository, the list under its name)
        let external = ImageLocation::external(destination)
            .map_err(|e| invalid(e.to_string()))?
            .map(|(scheme, _)| scheme);
        let list = self.manifest_get(reference).await?;
        let dest = match external {
            Some(_) => None,
            None => Some(ImageReference::parse(destination)?),
        };
        if let Some(dest) = &dest {
            dest.validate()?;
        }
        let registry = |what: &str| {
            dest.as_ref().ok_or_else(|| {
                invalid(format!(
                    "{what} is for the images of a registry: not to the transport of a pusher"
                ))
            })
        };
        let repo = match &dest {
            Some(dest) => dest.name(),
            None => ImageLocation::external_repository(destination)
                .unwrap_or(destination)
                .to_string(),
        };
        let signing = match &opts.sign {
            Some(signer) => Some(self.signing_for(signer, registry("signing")?, None)?),
            None => None,
        };
        let mut index = list.index.clone();
        // a list that cannot be signed whole is refused before anything is
        // pushed
        if signing.is_some() && opts.all {
            for d in index["manifests"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|m| m["digest"].as_str())
            {
                let d: Digest = d.parse().map_err(|e| {
                    invalid(format!("the instance {d} of the list is not a digest: {e}"))
                })?;
                Self::check_signable(&d)?;
            }
        }
        let mut variants = Vec::new();
        if let Some(manifests) = index["manifests"].as_array_mut() {
            for m in manifests.iter_mut() {
                let Some(d) = m["digest"].as_str().map(str::to_string) else {
                    continue;
                };
                if !opts.all {
                    continue;
                }
                let Ok(d_typed) = d.parse::<Digest>() else {
                    return Err(invalid(format!(
                        "the instance {d} of the list is not a digest"
                    )));
                };
                if self.artifact_blob(&list.id, &d_typed).is_some() {
                    let dest = registry("an artifact")?;
                    self.push_artifact(&list.id, &d_typed, dest, opts).await?;
                    if let Some(signing) = &signing {
                        self.sign_digest(signing, dest, d_typed, opts.tls_verify, &opts.access)
                            .await?;
                    }
                    continue;
                }
                let image = match self.db.get_image_by_digest(&d_typed).await {
                    Ok(image) => image,
                    _ if !opts.add_compression.is_empty() => {
                        return Err(ImageError::NotFound(format!(
                            "the instance {d} of the list is not in the store: \
                             its compression variants are made from the store (pull it)"
                        )));
                    }
                    _ => {
                        // Copied from the registry it was added from.
                        let source = list.sources.get(&d).ok_or_else(|| {
                            ImageError::NotFound(format!(
                                "the instance {d} of the list is not in the store"
                            ))
                        })?;
                        let dest =
                            registry("a copy of an instance from the registry it was added from")?;
                        self.copy_remote_manifest(
                            source,
                            &d_typed,
                            dest,
                            opts.tls_verify,
                            &opts.access,
                            opts.sinks.as_deref(),
                        )
                        .await?;
                        if let Some(signing) = &signing {
                            self.sign_digest(signing, dest, d_typed, opts.tls_verify, &opts.access)
                                .await?;
                        }
                        continue;
                    }
                };
                let push = |compression| PushOptions {
                    tls_verify: opts.tls_verify,
                    compression,
                    compression_level: opts.compression_level,
                    destination: dest.as_ref().map(|_| repo.clone()),
                    access: opts.access.clone(),
                    by_digest: true,
                    progress: None,
                    sign: opts.sign.clone(),
                    sign_identity: signing.as_ref().map(|s| s.identity.clone()),
                    sinks: opts.sinks.clone(),
                    path: None,
                    transport: external.map(|scheme| super::TransportPush {
                        scheme: scheme.to_string(),
                        destination: repo.clone(),
                    }),
                };
                let pushed = self.push_with(&image.id, &push(opts.compression)).await?;
                // The registry has it as it was pushed (a layer may have been
                // regenerated): the index names that manifest.
                m["digest"] = json!(pushed.digest);
                m["size"] = json!(pushed.size);
                m["mediaType"] = json!(pushed.media_type);
                let mut digests = vec![pushed.digest];
                for c in &opts.add_compression {
                    let variant = self.push_with(&image.id, &push(Some(*c))).await?;
                    // (an instance that has that compression already)
                    if digests.contains(&variant.digest) {
                        continue;
                    }
                    variants.push(compression_variant(m, &variant, *c));
                    digests.push(variant.digest);
                }
            }
            manifests.extend(variants);
        }
        let body = Bytes::from(serde_json::to_vec(&index)?);
        let media_type = index["mediaType"].as_str().unwrap_or(OCI_INDEX).to_string();
        velarx_types::docker::refuse_written_media_type(&media_type)?;
        if media_type != OCI_INDEX {
            return Err(invalid(format!("unexpected index media type {media_type}")));
        }
        let client = self
            .resolver
            .with_tls_verify(opts.tls_verify)
            .with_access(&opts.access);
        let (tag, alg, staged) = match (&dest, external) {
            (Some(dest), _) => {
                // (refuses a blocked registry or a name that is not valid)
                client.push_target(dest)?;
                let tag = dest
                    .digest
                    .map(|d| d.to_string())
                    .or(dest.tag.clone())
                    .unwrap_or_else(|| "latest".into());
                // (the digest of the bytes in the algorithm of the destination's, if it names one)
                let alg = dest.digest.map_or(list.alg, |d| d.alg());
                let staged = self
                    .staged_push(dest, opts.tls_verify, &opts.access, opts.sinks.as_deref())
                    .await?;
                (tag, alg, staged)
            }
            (None, scheme) => {
                let scheme = scheme.unwrap_or_default();
                let list_at = super::TransportPush {
                    scheme: scheme.to_string(),
                    destination: destination.to_string(),
                };
                let staged = self
                    .staged(
                        super::push::Origin::Transport {
                            transport: &list_at,
                            tls_verify: opts.tls_verify,
                            access: &opts.access,
                        },
                        opts.sinks.as_deref(),
                    )
                    .await?;
                // (the name the destination gives the list; none: its digest)
                let tag = ImageLocation::external_name(destination).unwrap_or_default();
                (tag, list.alg, staged)
            }
        };
        let (digest, placed) =
            super::push::put_manifest_as(&staged, &tag, &media_type, &body, alg).await?;
        staged.finish().await?;
        if let (Some(signing), Some(dest)) = (&signing, &dest) {
            self.sign_digest(signing, dest, digest, opts.tls_verify, &opts.access)
                .await?;
        }
        info!(
            "Pushed the manifest list {} as {} ({digest})",
            list.id,
            dest.as_ref()
                .map_or(ImageLocation::loggable(destination), |d| d.full_name())
        );
        Ok((digest, placed))
    }
}

/// The annotation of the instances of an index whose layers are zstd
/// (containers/image's, which picks them on a pull when it can).
const ZSTD_INSTANCE: &str = "io.github.containers.compression.zstd";

/// The entry of an index for the instance `pushed`, a copy of `instance`
/// in the compression `compression`.
fn compression_variant(
    instance: &Value,
    pushed: &super::PushResult,
    compression: velarx_content::layer::writer::Compression,
) -> Value {
    let mut entry = instance.clone();
    entry["digest"] = json!(pushed.digest);
    entry["size"] = json!(pushed.size);
    entry["mediaType"] = json!(pushed.media_type);
    if let Some(a) = entry["annotations"].as_object_mut() {
        a.remove(ZSTD_INSTANCE);
    }
    if compression == velarx_content::layer::writer::Compression::ZstdChunked {
        entry["annotations"][ZSTD_INSTANCE] = json!("true");
    }
    entry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a_compression_variant_is_its_instance_with_its_digest() {
        use velarx_content::layer::writer::Compression;
        let instance = json!({
            "digest": "sha256:aa", "size": 10, "mediaType": OCI_MANIFEST,
            "platform": {"os": "linux", "architecture": "arm64"},
            "annotations": {ZSTD_INSTANCE: "true", "x": "y"},
        });
        let pushed = super::super::PushResult {
            digest: format!("sha256:{}", "b".repeat(64)).parse().unwrap(),
            size: 20,
            media_type: OCI_MANIFEST.into(),
            blobs_uploaded: 0,
            blobs_mounted: 0,
            blobs_existing: 0,
            layers_regenerated: 0,
            placed: Vec::new(),
        };
        let gzip = compression_variant(&instance, &pushed, Compression::Gzip);
        assert_eq!(gzip["digest"], format!("sha256:{}", "b".repeat(64)));
        assert_eq!(gzip["size"], 20);
        assert_eq!(gzip["platform"], instance["platform"]);
        assert_eq!(gzip["annotations"], json!({"x": "y"}));
        let zstd = compression_variant(&gzip, &pushed, Compression::ZstdChunked);
        assert_eq!(zstd["annotations"][ZSTD_INSTANCE], "true");
        let bare = compression_variant(
            &json!({"digest": "sha256:aa"}),
            &pushed,
            Compression::ZstdChunked,
        );
        assert_eq!(bare["annotations"], json!({ZSTD_INSTANCE: "true"}));
    }

    #[test]
    fn test_instance_edits() {
        let mut e =
            json!({"digest": "sha256:aa", "platform": {"os": "linux", "architecture": "amd64"}});
        let opts = InstanceOptions {
            annotations: [("a".to_string(), "b".to_string())].into(),
            arch: Some("arm64".into()),
            variant: Some("v8".into()),
            features: vec!["sse4".into()],
            ..Default::default()
        };
        edit_instance(&mut e, &opts);
        assert_eq!(e["platform"]["architecture"], "arm64");
        assert_eq!(e["platform"]["os"], "linux");
        assert_eq!(e["platform"]["variant"], "v8");
        assert_eq!(e["platform"]["features"], json!(["sse4"]));
        assert_eq!(e["annotations"]["a"], "b");
        let p = wanted_platform(&InstanceOptions {
            arch: Some("arm64".into()),
            ..Default::default()
        });
        assert_eq!((p.os.as_str(), p.arch.as_str()), ("linux", "arm64"));
    }

    #[test]
    fn test_names() {
        assert_eq!(
            split_name("localhost/abc").unwrap(),
            ("localhost/abc".to_string(), "latest".to_string())
        );
        assert!(split_name("localhost/abc@sha256:00").is_err());
        assert!(split_name("Bad Name").is_err());
    }
}
