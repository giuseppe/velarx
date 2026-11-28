// SPDX-License-Identifier: Apache-2.0
//! The fs-verity digest of the merged EROFS of an image in its manifest, as
//! the OCI sealing specification of composefs-rs (`sealing_spec.rs`, inline
//! mode, digest only) says: the top-level annotation
//! `composefs.merged.erofs.v1.fsverity-sha256-12`, lowercase hex (for an
//! image whose digests are SHA-512, `...fsverity-sha512-12` and 128 digits:
//! the merged EROFS is made of the objects of the layers, which are of one
//! algorithm, so an image whose layers do not all have the algorithm of its
//! manifest has none, and states none).  The
//! merged EROFS is the image of composefs-rs ([`velarx_fuse::canonical`]),
//! which a client makes from the layers and the fs-verity digests of their
//! files.  The images velarx builds get it; an image that has it is taken
//! in (a pull, the completion of a lazy image) only if the image made of its
//! layers has that digest.  It is not used to validate a start, which
//! verifies the layers one by one (`start_lists`).
//!
//! Each layer descriptor states the fs-verity digest of the EROFS image of
//! its layer in the annotation of podman's `composefs-verity` branch,
//! [`LAYER_EROFS_ANNOTATION`]: a comma separated list of `sha256:<hex>`
//! values, one of which is the digest of the image velarx makes.  The
//! image is made from the table of contents of the layer alone, so the
//! digest is checked at the pull, also of a lazy one, before any file is
//! fetched.  A manifest is data: whoever wrote it, the digest it states is
//! compared with the image made here, never taken for it.

use super::*;
use velarx_config::ComposefsDigests;
use velarx_db::LayerRecord;
use velarx_storage::Toc;
use velarx_wire::chain::Chain;

/// The annotation of a layer descriptor with the fs-verity digests of the
/// composefs image of the layer (podman's `composefs-verity` branch).
pub const LAYER_EROFS_ANNOTATION: &str = "io.containers.composefs.digest";

/// The annotation of the merged EROFS of an image whose digests are made
/// with `alg`: the fs-verity hash over blocks of 4096 bytes, as the objects.
pub fn merged_annotation(alg: Algorithm) -> String {
    format!("composefs.merged.erofs.v1.fsverity-{}-12", alg.name())
}

/// Whether `key` is the annotation of a merged EROFS digest, of either
/// algorithm.
pub fn is_merged_annotation(key: &str) -> bool {
    Algorithm::ALL
        .into_iter()
        .any(|a| key == merged_annotation(a))
}

/// The digests the manifest states for the merged EROFS (at most one of
/// each algorithm), lowercase hex of the length of the algorithm.
pub fn expected(manifest: &OciManifest) -> ImageResult<Vec<(Algorithm, String)>> {
    let mut stated = Vec::new();
    for alg in Algorithm::ALL {
        let name = merged_annotation(alg);
        let Some(v) = manifest.annotations.get(&name) else {
            continue;
        };
        if v.len() == alg.len() * 2 && v.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            stated.push((alg, v.clone()));
        } else {
            return Err(ImageError::Manifest(format!(
                "the annotation {name} is not a digest: {v:?}"
            )));
        }
    }
    Ok(stated)
}

/// Whether `id`, the digest of the merged EROFS made of the layers (SHA-256
/// or SHA-512, `alg`), is the one the manifest states, if it states one.
pub fn check(manifest: &OciManifest, alg: Algorithm, id: &str) -> ImageResult<()> {
    match expected(manifest)?.into_iter().find(|(a, _)| *a == alg) {
        Some((_, want)) if want != id => Err(ImageError::Manifest(format!(
            "the merged EROFS of the layers has the fs-verity digest {id}, the manifest says {want} ({})",
            merged_annotation(alg)
        ))),
        _ => Ok(()),
    }
}

/// The digests the descriptor `layer` states for the EROFS image of its
/// layer: none if it has no annotation, or one with no such value.  The
/// annotation is a list that other writers share (podman's
/// `composefs-verity` branch states the digests of its own images in it, and
/// reads any trimmed string): an empty entry, an entry of another algorithm
/// than sha256 and sha512 and anything that is not a digest of its
/// algorithm (lowercase hex of the exact length) are not ours and are
/// ignored, never an error.  Each is the fs-verity digest, with blocks of
/// 4096 bytes, in its algorithm.
pub fn layer_digests(layer: &OciDescriptor) -> Option<Vec<Digest>> {
    let v = layer.annotations.get(LAYER_EROFS_ANNOTATION)?;
    let ours: Vec<Digest> = v
        .split(',')
        .filter_map(|d| velarx_types::digest::parse_composefs_annotation(d.trim()))
        .collect();
    (!ours.is_empty()).then_some(ours)
}

/// The values of a list of stated digests as the records write them
/// (`ALGORITHM:<hex>`).
fn plain(stated: &[Digest]) -> Vec<String> {
    stated.iter().map(Digest::plain).collect()
}

/// What a layer that states no usable digest says of itself in a message:
/// `states no EROFS digest (ANNOTATION)`, with the value when it has one
/// that is all foreign.
fn states_none(layer: &OciDescriptor) -> String {
    match layer.annotations.get(LAYER_EROFS_ANNOTATION) {
        Some(v) => {
            format!(
                "states no sha256:<hex> or sha512:<hex> EROFS digest ({LAYER_EROFS_ANNOTATION} is {v:?})"
            )
        }
        None => format!("states no EROFS digest ({LAYER_EROFS_ANNOTATION})"),
    }
}

/// State `erofs` (`sha256:<hex>`), the digest of the EROFS image of the layer, on its
/// descriptor; a list that has it already is left as it is (it may carry the
/// digests of other writers), one that has not is replaced by `erofs` alone
/// (values that nothing here checked are not stated again).  Whether the
/// descriptor changed.
pub fn state_layer(layer: &mut OciDescriptor, erofs: &str) -> bool {
    if layer_digests(layer).is_some_and(|list| list.iter().any(|d| d.plain() == erofs)) {
        return false;
    }
    layer
        .annotations
        .insert(LAYER_EROFS_ANNOTATION.to_string(), erofs.to_string());
    true
}

/// Whether the digests the layers of `manifest` state are those of the EROFS
/// images made here, `ours` (`sha256:<hex>`, in the order of the layers; none:
/// not known).  Under `require` every layer must state one of ours: one
/// that states none, or only values that are not those of the image made
/// here (foreign: another writer's, or a tampered one), fails.  Otherwise
/// such a layer is held against its own record, like one that states none;
/// a list that has our digest is right.
pub fn check_layers(
    manifest: &OciManifest,
    ours: &[Option<String>],
    mode: ComposefsDigests,
) -> ImageResult<()> {
    if ours.len() != manifest.layers.len() {
        return Err(ImageError::ComposefsDigest(format!(
            "{} EROFS images for the {} layers of the manifest",
            ours.len(),
            manifest.layers.len()
        )));
    }
    let total = manifest.layers.len();
    for (i, (layer, ours)) in manifest.layers.iter().zip(ours).enumerate() {
        check_layer(i, total, layer, ours.as_deref(), mode)?;
    }
    Ok(())
}

/// The check of layer `i` of `total`, whose image has the digest `ours`.
fn check_layer(
    i: usize,
    total: usize,
    layer: &OciDescriptor,
    ours: Option<&str>,
    mode: ComposefsDigests,
) -> ImageResult<()> {
    let at = format!("layer {} of {total} ({})", i + 1, layer.digest);
    let Some(stated) = layer_digests(layer) else {
        if mode == ComposefsDigests::Require {
            return Err(ImageError::ComposefsDigest(format!(
                "{at} {}, and [storage] composefs_digests is \"require\"",
                states_none(layer)
            )));
        }
        return Ok(());
    };
    let Some(ours) = ours else {
        return Err(ImageError::ComposefsDigest(format!(
            "{at}: no EROFS image of the layer to compare with the digest the manifest states ({LAYER_EROFS_ANNOTATION})"
        )));
    };
    if mode == ComposefsDigests::Require && !stated.iter().any(|d| d.plain() == ours) {
        return Err(ImageError::ComposefsDigest(format!(
            "{at}: its EROFS image has the fs-verity digest {ours}, the manifest says {} ({LAYER_EROFS_ANNOTATION}), and [storage] composefs_digests is \"require\"",
            plain(&stated).join(", ")
        )));
    }
    Ok(())
}

/// What makes a start enforce the digests of the manifest: the node's
/// `[storage] composefs_digests = "require"`, or `--security-opt
/// verity=enforce` of the container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enforcing {
    No,
    Node,
    Container,
    /// What the engine holds by default (the image is signed, or was named
    /// by its digest): the manifest need not state a digest, each layer is
    /// held to the digest recorded when its EROFS image was made, or to the
    /// manifest's where it states ours.
    Record,
}

impl Enforcing {
    /// What the node's `[storage] composefs_digests` and the container's
    /// `--security-opt verity=enforce` make of a start's digests.  A driver
    /// that checks them at pull only (`pull_only`) enforces nothing at a
    /// start: a request to enforce was refused at the start of the engine
    /// and at the create of the container, unless best effort is said.
    pub fn of(pull_only: bool, node: ComposefsDigests, container: bool) -> Self {
        match (pull_only, node, container) {
            (true, _, _) => Enforcing::No,
            (_, ComposefsDigests::Require, _) => Enforcing::Node,
            (_, _, true) => Enforcing::Container,
            _ => Enforcing::No,
        }
    }

    /// Whether a manifest must state the digests (asked for by name).
    fn manifest(self) -> bool {
        matches!(self, Enforcing::Node | Enforcing::Container)
    }

    pub fn reason(self) -> &'static str {
        match self {
            Enforcing::No => "",
            Enforcing::Node => "[storage] composefs_digests is \"require\"",
            Enforcing::Container => "--security-opt verity=enforce",
            Enforcing::Record => "the verity chain is held by default",
        }
    }
}

/// The fs-verity digests the EROFS images of the layers of a stored image may
/// have at a start, one list per layer, the lowest first, from the manifest
/// as stored: the manifest must be the one `manifest_digest` and the image
/// `id` name (the store, the database row or an editor may have changed
/// it), its layers those of `layers`, and the digests a layer's record has
/// among the ones it states.  A layer that states none is checked against
/// its record, unless the digests are enforced: then it is an error, and so
/// is an image that is not all in the store.
///
/// The debug log of the start has a link of `chain` for each layer: the
/// manifest, the blob of the layer and the digests its annotation states.
pub fn start_lists(
    id: &str,
    manifest_digest: &Digest,
    manifest: &str,
    layers: &[LayerRecord],
    lazy: bool,
    enforcing: Enforcing,
    chain: &Chain,
) -> ImageResult<Vec<Vec<String>>> {
    start_links(
        id,
        manifest_digest,
        manifest,
        layers,
        lazy,
        enforcing,
        chain,
    )
    .inspect_err(|_| {
        chain.broken(|| {
            (
                "manifest".into(),
                manifest_digest.to_string(),
                "error".into(),
            )
        })
    })
}

fn start_links(
    id: &str,
    manifest_digest: &Digest,
    manifest: &str,
    layers: &[LayerRecord],
    lazy: bool,
    enforcing: Enforcing,
    chain: &Chain,
) -> ImageResult<Vec<Vec<String>>> {
    let short = &id[..id.len().min(12)];
    let have = Digest::of(manifest_digest.alg(), manifest.as_bytes());
    // (the id of an image made here is the digest of its configuration)
    let named_by_config =
        || serde_json::from_str::<OciManifest>(manifest).is_ok_and(|m| m.config.digest.hex() == id);
    if have != *manifest_digest
        || (id.len() == have.hex().len() && id != have.hex() && !named_by_config())
    {
        chain.broken(|| match have != *manifest_digest {
            true => (
                "manifest".into(),
                manifest_digest.to_string(),
                have.to_string(),
            ),
            false => (
                "manifest".into(),
                format!("{}:{id}", have.alg()),
                have.to_string(),
            ),
        });
        return Err(ImageError::Invalid(format!(
            "the stored manifest of image {short} is not the one its id names ({have}): the store was modified; pull the image again"
        )));
    }
    let manifest: OciManifest = serde_json::from_str(manifest).map_err(|e| {
        chain.broken(|| (format!("{have} manifest"), "json".into(), "invalid".into()));
        ImageError::Invalid(format!(
            "the stored manifest of image {short} is not valid: {e}"
        ))
    })?;
    if super::chain::layers_differ(&manifest, layers, chain).is_some() {
        return Err(ImageError::Invalid(format!(
            "the layers of image {short} are not those of its manifest: the store was modified; pull the image again"
        )));
    }
    if enforcing != Enforcing::No && lazy {
        chain.broken(|| ("layers".into(), "complete".into(), "lazy".into()));
        return Err(ImageError::ComposefsDigest(format!(
            "image {short} is not all in the store (a lazy pull) and {} needs the kernel to check every file: let it be fetched whole first",
            enforcing.reason()
        )));
    }
    let total = layers.len();
    manifest
        .layers
        .iter()
        .zip(layers)
        .enumerate()
        .map(|(i, (descriptor, record))| {
            let at = format!("layer {} of {total} ({})", i + 1, descriptor.digest);
            let stated = layer_digests(descriptor);
            match (stated, record.erofs.as_ref()) {
                (Some(stated), Some(recorded))
                    if !stated.iter().any(|d| d.plain() == *recorded)
                        && enforcing.manifest() =>
                {
                    let stated = plain(&stated);
                    chain.broken(|| {
                        (
                            format!("layer {} annotation", i + 1),
                            stated.join(","),
                            recorded.clone(),
                        )
                    });
                    Err(ImageError::ComposefsDigest(format!(
                        "image {short}: {at}: its EROFS image is recorded with the fs-verity digest {recorded}, the manifest says {} ({LAYER_EROFS_ANNOTATION}), and {}",
                        stated.join(", "),
                        enforcing.reason()
                    )))
                }
                // (none of them is the digest of the image made here: they
                // are another writer's, or tampered with, and not enforced
                // they are not looked at)
                (Some(stated), Some(recorded))
                    if !stated.iter().any(|d| d.plain() == *recorded) =>
                {
                    record_link(chain, &have, descriptor, i, recorded);
                    Ok(vec![recorded.clone()])
                }
                (Some(stated), _) => {
                    let stated = plain(&stated);
                    chain.link(|| {
                        format!(
                            "{have} manifest -> {} layer {} blob -> {} annotation",
                            descriptor.digest,
                            i + 1,
                            stated.join(",")
                        )
                    });
                    Ok(stated)
                }
                (None, _) if enforcing.manifest() => {
                    chain.broken(|| {
                        (
                            format!("layer {} annotation", i + 1),
                            "sha256:<hex>".into(),
                            descriptor
                                .annotations
                                .get(LAYER_EROFS_ANNOTATION)
                                .cloned()
                                .unwrap_or_else(|| "none".into()),
                        )
                    });
                    Err(ImageError::ComposefsDigest(format!(
                        "image {short}: {at} {}, and {} (`velarx image push` with a `--compression-format` other than that of its layers writes a manifest that states them)",
                        states_none(descriptor),
                        enforcing.reason()
                    )))
                }
                (None, Some(recorded)) => {
                    record_link(chain, &have, descriptor, i, recorded);
                    Ok(vec![recorded.clone()])
                }
                (None, None) => Err(ImageError::Storage(format!(
                    "image {short}: the EROFS image of {at} is not recorded: `velarx system check --repair` makes it again"
                ))),
            }
        })
        .collect()
}

/// The link of layer `i` held to the digest recorded when its EROFS image
/// was made: the manifest `have` names the blob, the engine's record the
/// EROFS image.
fn record_link(chain: &Chain, have: &Digest, layer: &OciDescriptor, i: usize, recorded: &str) {
    chain.from_record(i + 1);
    chain.link(|| {
        format!(
            "{have} manifest -> {} layer {} blob -> {recorded} record",
            layer.digest,
            i + 1
        )
    });
}

/// Refuse by name a manifest that states a merged EROFS digest its layers
/// (`layers`: the algorithm of each) cannot check: the merged EROFS is made
/// of the objects of the layers, of their algorithm, and nothing hashes
/// content the other way.  Known from the manifest alone: a lazy pull is
/// refused as a complete one is, before any layer.
pub fn check_statable(manifest: &OciManifest, layers: &[Algorithm]) -> ImageResult<()> {
    for (stated, _) in expected(manifest)? {
        if let Some((i, odd)) = layers.iter().enumerate().find(|(_, l)| **l != stated) {
            return Err(ImageError::Manifest(format!(
                "the manifest states a merged EROFS digest ({}), and layer {} of {} has {odd} digests: its objects cannot make a {stated} merged EROFS, so the digest cannot be checked (a mixed image states none)",
                merged_annotation(stated),
                i + 1,
                layers.len()
            )));
        }
    }
    Ok(())
}

/// The digest of the merged EROFS of the layers whose TOCs are `tocs`, in
/// order, whose files are where `objects` says (by their fs-verity digest):
/// an error if it is not the one
/// `want` states (when given).  The merged EROFS is made of the objects of
/// the layers, in one algorithm, so a digest the manifest states (in the
/// algorithm `A` of its annotation) is checked when every layer has `A`
/// (`layers`: the algorithm of each), and refused by name when one has
/// not: nothing hashes content the other way, and a statement that cannot
/// be checked is not taken.  Where the manifest states none, the digest is
/// made in `alg`, the algorithm of the manifest, for an image whose layers
/// all have it; a mixed image has none (None).
pub(super) fn merged_erofs(
    alg: Algorithm,
    layers: &[Algorithm],
    tocs: &[&Toc],
    objects: &dyn Fn(&str) -> Option<std::path::PathBuf>,
    want: Option<&OciManifest>,
) -> ImageResult<Option<(Algorithm, String)>> {
    let stated = want.map(expected).transpose()?.unwrap_or_default();
    let made = |a: Algorithm| {
        crate::storage_driver::composefs::canonical_image_of(a, tocs, objects)
            .map(|(_, id)| id)
            .map_err(|e| ImageError::Storage(format!("cannot make the merged EROFS: {e}")))
    };
    if let Some(m) = want {
        check_statable(m, layers)?;
    }
    let mut result = None;
    for (stated_alg, _) in &stated {
        let id = made(*stated_alg)?;
        if let Some(m) = want {
            check(m, *stated_alg, &id)?;
        }
        result.get_or_insert((*stated_alg, id));
    }
    if result.is_none() && layers.iter().all(|l| *l == alg) {
        result = Some((alg, made(alg)?));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_types::digest::Algorithm;

    fn sha(seed: &str) -> Digest {
        Digest::of(Algorithm::Sha256, seed.as_bytes())
    }

    const MERGED_EROFS_ANNOTATION: &str = "composefs.merged.erofs.v1.fsverity-sha256-12";

    fn manifest(annotation: Option<&str>) -> OciManifest {
        serde_json::from_value(serde_json::json!({
            "schemaVersion": 2,
            "config": {"mediaType": "x", "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000", "size": 1},
            "layers": [],
            "annotations": annotation
                .map(|a| serde_json::json!({MERGED_EROFS_ANNOTATION: a}))
                .unwrap_or_else(|| serde_json::json!({})),
        }))
        .unwrap()
    }

    fn layer(annotation: Option<&str>) -> OciDescriptor {
        let mut d = OciDescriptor {
            media_type: "x".into(),
            digest: sha("aa"),
            size: 1,
            annotations: Default::default(),
        };
        if let Some(a) = annotation {
            d.annotations
                .insert(LAYER_EROFS_ANNOTATION.into(), a.into());
        }
        d
    }

    fn with_layers(layers: Vec<OciDescriptor>) -> OciManifest {
        let mut m = manifest(None);
        m.layers = layers;
        m
    }

    #[test]
    fn the_layer_annotation_is_a_list_of_which_the_sha256_digests_count() {
        let (a, b) = ("ab".repeat(32), "cd".repeat(32));
        let got = |v: &str| {
            layer_digests(&layer(Some(v))).map(|l| l.iter().map(Digest::plain).collect::<Vec<_>>())
        };
        assert_eq!(layer_digests(&layer(None)), None);
        assert_eq!(
            got(&format!("sha256:{a}")),
            Some(vec![format!("sha256:{a}")])
        );
        assert_eq!(
            got(&format!("sha256:{a}, sha256:{b}")),
            Some(vec![format!("sha256:{a}"), format!("sha256:{b}")])
        );
        // the values of other writers are ignored: empty entries, other
        // algorithms (known or not), words, and sha256 values that are not
        // 64 lowercase hex digits (podman reads any string and never
        // matches it)
        assert_eq!(
            got(&format!("sha256:{a},")),
            Some(vec![format!("sha256:{a}")])
        );
        // (a sha512 of 128 digits is a candidate of a sha512 digest)
        assert_eq!(
            got(&format!(
                ",, sha512:{},sha256:{a} ,x-1:{b}",
                "ef".repeat(64)
            )),
            Some(vec![
                format!("sha512:{}", "ef".repeat(64)),
                format!("sha256:{a}")
            ])
        );
        for wrong in [
            format!("sha512:{a}"),
            format!("sha512:{}", "ef".repeat(63)),
            format!("sha512:{}", "EF".repeat(64)),
            format!("sha384:{}", "ef".repeat(48)),
        ] {
            assert_eq!(got(&wrong), None, "{wrong}");
        }
        assert_eq!(
            got(&format!(
                "sha256:{b},sha256:zz,sha256:{},sha256:ab",
                a.to_uppercase()
            )),
            Some(vec![format!("sha256:{b}")])
        );
        // none of ours is none stated
        for foreign in [
            "",
            ",",
            &a,
            "sha256:ab",
            "sha256:zz",
            &format!("sha256:{}", a.to_uppercase()),
            &format!("sha256:{a}0"),
            "nonsense",
        ] {
            assert_eq!(got(foreign), None, "{foreign}");
        }
    }

    #[test]
    fn a_layer_states_its_digest_once_and_keeps_a_list_that_has_it() {
        let a = format!("sha256:{}", "ab".repeat(32));
        let b = format!("sha256:{}", "cd".repeat(32));
        let mut d = layer(None);
        assert!(state_layer(&mut d, &a));
        assert_eq!(d.annotations[LAYER_EROFS_ANNOTATION], a);
        assert!(!state_layer(&mut d, &a));
        let list = format!("{b},{a}");
        d.annotations
            .insert(LAYER_EROFS_ANNOTATION.into(), list.clone());
        assert!(!state_layer(&mut d, &a));
        assert_eq!(d.annotations[LAYER_EROFS_ANNOTATION], list);
        // another one is replaced
        let c = format!("sha256:{}", "ef".repeat(32));
        assert!(state_layer(&mut d, &c));
        assert_eq!(d.annotations[LAYER_EROFS_ANNOTATION], c);
        // a list of other writers' values only: ours alone is stated (what
        // nothing here checked is not stated again)
        d.annotations.insert(
            LAYER_EROFS_ANNOTATION.into(),
            format!("sha512:{},{b},", "ab".repeat(64)),
        );
        assert!(state_layer(&mut d, &a));
        assert_eq!(d.annotations[LAYER_EROFS_ANNOTATION], a);
    }

    /// Which of the node's setting and the container's option enforces the
    /// digests of the manifest at a start; the node's wins the reason, and a
    /// driver that checks at pull only enforces nothing.
    #[test]
    fn the_node_and_the_container_enforce_the_digests() {
        use ComposefsDigests::{Check, Require};
        for (pull_only, node, container, want) in [
            (false, Check, false, Enforcing::No),
            (false, Check, true, Enforcing::Container),
            (false, Require, false, Enforcing::Node),
            (false, Require, true, Enforcing::Node),
            (true, Check, false, Enforcing::No),
            (true, Check, true, Enforcing::No),
            (true, Require, false, Enforcing::No),
            (true, Require, true, Enforcing::No),
        ] {
            assert_eq!(
                Enforcing::of(pull_only, node, container),
                want,
                "{pull_only} {node:?} {container}"
            );
        }
    }

    #[test]
    fn layers_are_checked_against_the_images_made_here() {
        let a = format!("sha256:{}", "ab".repeat(32));
        let b = format!("sha256:{}", "cd".repeat(32));
        let c = format!("sha256:{}", "ef".repeat(32));
        let m = with_layers(vec![
            layer(Some(&a)),
            layer(Some(&format!("{b},{c}"))),
            layer(None),
        ]);
        let ours = [Some(a.clone()), Some(c.clone()), Some(a.clone())];
        // one of a list is enough, no annotation is fine
        check_layers(&m, &ours, ComposefsDigests::Check).unwrap();
        // none of the list is the image made here: another writer's, or
        // tampered with; it fails only where the digests are required,
        // naming the layer
        let wrong = [Some(a.clone()), Some(a.clone()), None];
        check_layers(&m, &wrong, ComposefsDigests::Check).unwrap();
        let e = check_layers(&m, &wrong, ComposefsDigests::Require)
            .unwrap_err()
            .to_string();
        assert!(e.contains("layer 2 of 3") && e.contains(&a), "{e}");
        assert!(e.contains(&format!("{b}, {c}")), "{e}");
        // require: the third states none
        let e = check_layers(&m, &ours, ComposefsDigests::Require)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("layer 3 of 3") && e.contains("composefs_digests"),
            "{e}"
        );
        // a stated digest with no image to compare with is no pass
        assert!(check_layers(&m, &[None, None, None], ComposefsDigests::Check).is_err());
        // as many images as layers, or no pass
        assert!(check_layers(&m, &ours[..2], ComposefsDigests::Check).is_err());
        // values of other writers only (or tampered with): not looked at,
        // unless the digests are required
        let m = with_layers(vec![
            layer(Some("nonsense")),
            layer(Some(&format!("{b},"))),
            layer(Some(&format!("sha512:{},", "ab".repeat(64)))),
        ]);
        let ours = [Some(a.clone()), Some(c.clone()), Some(a.clone())];
        check_layers(&m, &ours, ComposefsDigests::Check).unwrap();
        let e = check_layers(&m, &ours, ComposefsDigests::Require)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("layer 1 of 3")
                && e.contains("states no sha256:<hex>")
                && e.contains("nonsense"),
            "{e}"
        );
        // ... and a list with ours and foreign values is right
        let m = with_layers(vec![layer(Some(&format!(
            "sha512:{},{a},",
            "ab".repeat(64)
        )))]);
        check_layers(&m, &[Some(a.clone())], ComposefsDigests::Require).unwrap();
        let e = check_layers(&m, &[Some(c.clone())], ComposefsDigests::Require)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("layer 1 of 1") && e.contains(&c) && e.contains(&a),
            "{e}"
        );
        check_layers(&m, &[Some(c)], ComposefsDigests::Check).unwrap();
    }

    #[test]
    fn the_annotation_is_a_digest_and_must_match() {
        use Algorithm::{Sha256, Sha512};
        let id = "ab".repeat(32);
        let id512 = "ab".repeat(64);
        let with = |alg: Algorithm, v: &str| {
            let mut m = manifest(None);
            m.annotations.insert(merged_annotation(alg), v.to_string());
            m
        };
        assert_eq!(merged_annotation(Sha256), MERGED_EROFS_ANNOTATION);
        assert_eq!(
            merged_annotation(Sha512),
            "composefs.merged.erofs.v1.fsverity-sha512-12"
        );
        assert!(is_merged_annotation(&merged_annotation(Sha256)));
        assert!(is_merged_annotation(&merged_annotation(Sha512)));
        assert!(!is_merged_annotation(
            "composefs.merged.erofs.v1.fsverity-sha384-12"
        ));
        assert_eq!(expected(&manifest(None)).unwrap(), vec![]);
        assert_eq!(
            expected(&manifest(Some(&id))).unwrap(),
            vec![(Sha256, id.clone())]
        );
        assert_eq!(
            expected(&with(Sha512, &id512)).unwrap(),
            vec![(Sha512, id512.clone())]
        );
        assert!(check(&manifest(None), Sha256, &id).is_ok());
        assert!(check(&manifest(Some(&id)), Sha256, &id).is_ok());
        let err = check(&manifest(Some(&id)), Sha256, &"cd".repeat(32)).unwrap_err();
        assert!(err.to_string().contains(MERGED_EROFS_ANNOTATION), "{err}");
        assert!(check(&with(Sha512, &id512), Sha512, &id512).is_ok());
        let err = check(&with(Sha512, &id512), Sha512, &"cd".repeat(64)).unwrap_err();
        assert!(err.to_string().contains("fsverity-sha512-12"), "{err}");
        // (the annotation of one algorithm is not checked against the
        // digest of the other)
        assert!(check(&with(Sha512, &id512), Sha256, &id).is_ok());
        // the digits are those of the algorithm of the annotation
        for bad in [
            "",
            "AB",
            &id.to_uppercase(),
            &format!("sha256:{id}"),
            &id512,
        ] {
            assert!(expected(&manifest(Some(bad))).is_err(), "{bad}");
        }
        assert!(expected(&with(Sha512, &id)).is_err());
    }

    /// An image whose layers do not all have the algorithm of its manifest
    /// has no merged EROFS: none is made; a manifest that states one is
    /// checked when every layer has the algorithm of the statement, else
    /// refused by name.
    #[test]
    fn a_mixed_image_has_no_merged_erofs() {
        use Algorithm::{Sha256, Sha512};
        let dir = tempfile::tempdir().unwrap();
        let store = velarx_storage::FileStore::new(dir.path()).unwrap();
        let in_store = |d: &str| store.get_path(d);
        let none = Toc {
            version: 1,
            entries: Vec::new(),
            tar_split_digest: None,
        };
        let tocs = [&none];
        // a sha512 manifest over a sha256 layer, and the reverse
        for (alg, layers) in [(Sha512, [Sha256]), (Sha256, [Sha512])] {
            assert_eq!(
                merged_erofs(alg, &layers, &tocs, &in_store, None).unwrap(),
                None
            );
            assert_eq!(
                merged_erofs(alg, &layers, &tocs, &in_store, Some(&manifest(None))).unwrap(),
                None
            );
            // (a digest of the algorithm the manifest has, over layers of
            // the other: it cannot be checked)
            let mut stated = manifest(None);
            stated
                .annotations
                .insert(merged_annotation(alg), "ab".repeat(alg.len()));
            let e = merged_erofs(alg, &layers, &tocs, &in_store, Some(&stated))
                .unwrap_err()
                .to_string();
            assert!(e.contains("a mixed image states none"), "{e}");
            assert!(e.contains("layer 1 of 1 has"), "{e}");
            assert_eq!(check_statable(&stated, &layers).unwrap_err().to_string(), e);
        }
        // a digest of the layers' algorithm is checked, whatever the
        // manifest's
        let (_, id) = merged_erofs(Sha256, &[Sha256], &tocs, &in_store, None)
            .unwrap()
            .unwrap();
        let mut stated = manifest(None);
        stated
            .annotations
            .insert(merged_annotation(Sha256), id.clone());
        assert!(merged_erofs(Sha512, &[Sha256], &tocs, &in_store, Some(&stated)).is_ok());
        stated
            .annotations
            .insert(merged_annotation(Sha256), "cd".repeat(32));
        assert!(merged_erofs(Sha512, &[Sha256], &tocs, &in_store, Some(&stated)).is_err());
        // an image of one algorithm has one, in that algorithm
        for alg in Algorithm::ALL {
            let (got_alg, id) = merged_erofs(alg, &[alg], &tocs, &in_store, None)
                .unwrap()
                .unwrap();
            assert_eq!((got_alg, id.len()), (alg, alg.len() * 2));
        }
    }

    /// A stored image of two layers: the manifest as text, its digest, the
    /// layer records (with `erofs` recorded as the first digests say).
    fn stored(
        annotations: [Option<&str>; 2],
        recorded: [Option<&str>; 2],
    ) -> (Digest, String, Vec<LayerRecord>) {
        let layers: Vec<OciDescriptor> = annotations
            .iter()
            .zip([sha("aa"), sha("bb")])
            .map(|(a, digest)| {
                let mut d = layer(*a);
                d.digest = digest;
                d
            })
            .collect();
        let text = serde_json::to_string(&with_layers(layers)).unwrap();
        let records = recorded
            .iter()
            .zip([sha("aa"), sha("bb")])
            .map(|(erofs, digest)| LayerRecord {
                stream_size: Some(0),
                inline: 0,
                key: velarx_db::LayerKey::Whole(digest),
                blob: Some(digest),
                diff_id: None,
                other_diff_id: None,
                size: 1,
                status: "complete".into(),
                created_at: String::new(),
                registry_ref: None,
                erofs: erofs.map(str::to_string),
                owners: None,
            })
            .collect();
        let digest = Digest::of(Algorithm::Sha256, text.as_bytes());
        (digest, text, records)
    }

    #[test]
    fn a_start_takes_the_digests_from_the_manifest_not_the_record() {
        let d = |c: &str| format!("sha256:{}", c.repeat(64));
        let (one, two, three) = (d("1"), d("2"), d("3"));
        let list = format!("{two},{three}");
        let (digest, text, records) = stored([Some(&one), Some(&list)], [Some(&one), Some(&three)]);
        let id = digest.hex();
        let id = id.as_str();
        for enforcing in [Enforcing::No, Enforcing::Node, Enforcing::Container] {
            let got = start_lists(
                id,
                &digest,
                &text,
                &records,
                false,
                enforcing,
                &Chain::off(),
            )
            .unwrap();
            assert_eq!(got, [vec![one.clone()], vec![two.clone(), three.clone()]]);
        }
        // a record that the manifest does not state: not enforced, the
        // list is another writer's and the layer is held to its record
        let (digest, text, records) = stored([Some(&one), Some(&list)], [Some(&one), Some(&one)]);
        let got = start_lists(
            &digest.hex(),
            &digest,
            &text,
            &records,
            false,
            Enforcing::No,
            &Chain::off(),
        )
        .unwrap();
        assert_eq!(got[1], std::slice::from_ref(&one));
        // enforced, it is refused naming the layer
        for enforcing in [Enforcing::Node, Enforcing::Container] {
            let e = start_lists(
                &digest.hex(),
                &digest,
                &text,
                &records,
                false,
                enforcing,
                &Chain::off(),
            )
            .unwrap_err()
            .to_string();
            assert!(
                e.contains("layer 2 of 2") && e.contains(enforcing.reason()),
                "{e}"
            );
        }
        // nothing of ours in the list at all: as no annotation
        let (digest, text, records) =
            stored([Some(&one), Some("sha512:ab,,")], [Some(&one), Some(&two)]);
        let got = start_lists(
            &digest.hex(),
            &digest,
            &text,
            &records,
            false,
            Enforcing::No,
            &Chain::off(),
        )
        .unwrap();
        assert_eq!(got[1], std::slice::from_ref(&two));
        let e = start_lists(
            &digest.hex(),
            &digest,
            &text,
            &records,
            false,
            Enforcing::Container,
            &Chain::off(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("layer 2 of 2")
                && e.contains("states no sha256:<hex> or sha512:<hex> EROFS digest"),
            "{e}"
        );
    }

    #[test]
    fn a_layer_without_a_digest_is_checked_against_its_record_unless_enforced() {
        let d = |c: &str| format!("sha256:{}", c.repeat(64));
        let (one, two) = (d("1"), d("2"));
        let (digest, text, records) = stored([Some(&one), None], [Some(&one), Some(&two)]);
        let id = digest.hex();
        let id = id.as_str();
        let got = start_lists(
            id,
            &digest,
            &text,
            &records,
            false,
            Enforcing::No,
            &Chain::off(),
        )
        .unwrap();
        assert_eq!(got[1], std::slice::from_ref(&two));
        for (enforcing, reason) in [
            (
                Enforcing::Node,
                "[storage] composefs_digests is \"require\"",
            ),
            (Enforcing::Container, "--security-opt verity=enforce"),
        ] {
            let e = start_lists(
                id,
                &digest,
                &text,
                &records,
                false,
                enforcing,
                &Chain::off(),
            )
            .unwrap_err()
            .to_string();
            assert!(e.contains("layer 2 of 2") && e.contains(reason), "{e}");
            let e = start_lists(id, &digest, &text, &records, true, enforcing, &Chain::off())
                .unwrap_err()
                .to_string();
            assert!(e.contains("lazy") && e.contains(reason), "{e}");
        }
        // no record, none stated
        let (digest, text, records) = stored([Some(&one), None], [Some(&one), None]);
        assert!(start_lists(
            &digest.hex(),
            &digest,
            &text,
            &records,
            false,
            Enforcing::No,
            &Chain::off()
        )
        .is_err());
    }

    /// Held by default, a layer is held to the digest of the manifest where
    /// it states ours, else to the record of the engine, one link each; an
    /// image that is not all in the store, or a layer with no record, is
    /// refused.
    #[test]
    fn by_default_a_layer_is_held_to_its_record_when_the_manifest_states_none() {
        let d = |c: &str| format!("sha256:{}", c.repeat(64));
        let (one, two) = (d("1"), d("2"));
        let (digest, text, records) = stored([Some(&one), None], [Some(&one), Some(&two)]);
        let chain = Chain::off();
        let got = start_lists(
            &digest.hex(),
            &digest,
            &text,
            &records,
            false,
            Enforcing::Record,
            &chain,
        )
        .unwrap();
        assert_eq!(got, [vec![one.clone()], vec![two.clone()]]);
        // (the manifest's link of each layer: the annotation, the record)
        assert_eq!(chain.done(), 2);
        // a list that has none of ours is another writer's: the record
        let (digest, text, records) =
            stored([Some("sha512:ab,,"), Some(&one)], [Some(&two), Some(&one)]);
        let got = start_lists(
            &digest.hex(),
            &digest,
            &text,
            &records,
            false,
            Enforcing::Record,
            &Chain::off(),
        )
        .unwrap();
        assert_eq!(got, [vec![two.clone()], vec![one.clone()]]);
        // no record to go by, and not all in the store
        let (digest, text, records) = stored([None, None], [Some(&one), None]);
        for lazy in [false, true] {
            assert!(start_lists(
                &digest.hex(),
                &digest,
                &text,
                &records,
                lazy,
                Enforcing::Record,
                &Chain::off()
            )
            .is_err());
        }
    }

    #[test]
    fn a_manifest_that_is_not_the_one_the_id_names_is_refused() {
        let d = |c: &str| format!("sha256:{}", c.repeat(64));
        let (one, two) = (d("1"), d("2"));
        let (digest, text, records) = stored([Some(&one), Some(&two)], [Some(&one), Some(&two)]);
        let id = digest.hex();
        let id = id.as_str();
        let edited = text.replacen("\"size\":1", "\"size\":2", 1);
        assert_ne!(edited, text);
        let e = start_lists(
            id,
            &digest,
            &edited,
            &records,
            false,
            Enforcing::No,
            &Chain::off(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("not the one its id names") && e.contains("pull the image again"),
            "{e}"
        );
        // the row and the id changed together with the manifest
        let other = Digest::of(Algorithm::Sha256, edited.as_bytes());
        let e = start_lists(
            id,
            &other,
            &edited,
            &records,
            false,
            Enforcing::No,
            &Chain::off(),
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("not the one its id names"), "{e}");
        start_lists(
            &other.hex(),
            &other,
            &edited,
            &records,
            false,
            Enforcing::No,
            &Chain::off(),
        )
        .unwrap();
        // other layers than the manifest's
        let e = start_lists(
            id,
            &digest,
            &text,
            &records[..1],
            false,
            Enforcing::No,
            &Chain::off(),
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("not those of its manifest"), "{e}");
    }
}
