// SPDX-License-Identifier: Apache-2.0
use super::*;
use velarx_proto::engine::Condition;
use velarx_proto::workload::EventKind;

/// The registry name of `spec`: with or without `docker://`; the other
/// transports are the command line's, not the API's (as podman's).
pub(crate) fn registry_name(spec: &str) -> ApiResult<String> {
    Ok(velarx_types::transport::ImageLocation::registry(
        spec,
        "the REST API",
    )?)
}

pub(super) fn parse_name(name: &str) -> ApiResult<ImageReference> {
    let r = ImageReference::parse(name)?;
    r.validate()
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    Ok(r)
}

pub(super) async fn delete_tag(state: &AppState, repository: String, tag: String) -> ApiResult<()> {
    state
        .image_service
        .refuse_read_only_tag(&ImageTag {
            repository: repository.clone(),
            tag: tag.clone(),
            image_id: String::new(),
        })
        .await?;
    state
        .db
        .delete_image_tag(&repository, &tag)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))
}

/// Remove the names `names` of the image `name` (a name without a
/// registry is localhost's, without a tag `latest`), all of its names if
/// none; `NAME@DIGEST` is the name a pull by digest gave, else a reference
/// to the image (no error).
pub(crate) async fn untag_of(state: &AppState, name: &str, names: &[String]) -> ApiResult<()> {
    let rec = resolve_image(state, name).await?;
    let removed = state
        .image_service
        .untag(&rec.id, names)
        .await
        .map_err(|e| match e {
            velarx_types::ImageError::Invalid(m) if m.ends_with("tag not known") => {
                ApiError::no_such(Kind::Image, m).with_cause("tag not known")
            }
            e => ApiError::from(e),
        })?;
    for n in removed {
        let shown = match n.split_once('@') {
            Some((repository, digest)) => super::display_digest_name(repository, digest),
            None => {
                let (repository, tag) = n.rsplit_once(':').unwrap_or((n.as_str(), "latest"));
                display_name(&ImageTag {
                    repository: repository.to_string(),
                    tag: tag.to_string(),
                    image_id: String::new(),
                })
            }
        };
        state.podman.events.emit(Event::new(
            EventKind::Image,
            "untag",
            &image_id(&rec),
            &shown,
        ));
    }
    Ok(())
}

/// Remove `name`: only the name when the image has others, else the image.
/// Returns the untagged names and the deleted ids.
/// The layers (diff ids) of an image, from its configuration.
pub(super) fn diff_ids(rec: &ImageRecord) -> Vec<String> {
    serde_json::from_str::<Value>(&rec.config)
        .ok()
        .and_then(|c| {
            c["rootfs"]["diff_ids"].as_array().map(|a| {
                a.iter()
                    .filter_map(|d| d.as_str().map(String::from))
                    .collect()
            })
        })
        .unwrap_or_default()
}

/// Whether `parent` is below `child` as libimage's layer tree sees it: its
/// layers start those of the child, all of them only when it was made
/// first.
pub(super) fn is_below(parent: (&[String], &str), child: (&[String], &str)) -> bool {
    let (pl, pc) = parent;
    let (cl, cc) = child;
    !pl.is_empty() && cl.starts_with(pl) && (pl.len() < cl.len() || pc < cc)
}

/// The image `child` was made on: the nearest image below it.
pub(super) fn parent_of<'a>(
    images: &'a [(ImageRecord, Vec<String>)],
    child: (&[String], &str),
    child_id: &str,
) -> Option<&'a (ImageRecord, Vec<String>)> {
    images
        .iter()
        .filter(|(r, l)| r.id != child_id && is_below((l, &r.created_at), child))
        .max_by(|(a, al), (b, bl)| (al.len(), &a.created_at).cmp(&(bl.len(), &b.created_at)))
}

/// After the removal of an image, the images it was made on that are left
/// without a name, a container or another image on them go too, as
/// libimage's removal unless noprune; but not those of the build cache,
/// which a builder prune removes.  Returns their ids.
pub(super) async fn prune_parents(
    state: &AppState,
    removed: &ImageRecord,
) -> ApiResult<Vec<String>> {
    let mut images: Vec<(ImageRecord, Vec<String>)> = Vec::new();
    for rec in state.image_service.list().await? {
        let l = diff_ids(&rec);
        images.push((rec, l));
    }
    // the images of the build cache stay until a builder prune
    let cache = state.image_service.build_lineage().await?;
    let mut pruned = Vec::new();
    let mut child = (
        diff_ids(removed),
        removed.created_at.clone(),
        removed.id.clone(),
    );
    while let Some((parent, layers)) = parent_of(&images, (&child.0, &child.1), &child.2).cloned() {
        let named = state.db.image_is_named(&parent.id).await?;
        let used = containers_using(state, &parent).await? > 0;
        let other_children = images.iter().any(|(r, l)| {
            r.id != parent.id
                && parent_of(&images, (l, &r.created_at), &r.id)
                    .is_some_and(|(p, _)| p.id == parent.id)
        });
        if named || used || other_children || cache.contains_key(&parent.id) {
            break;
        }
        let id = image_id(&parent);
        state.image_service.remove(&parent.id, false).await?;
        state
            .podman
            .events
            .emit(Event::new(EventKind::Image, "remove", &id, ""));
        pruned.push(id);
        images.retain(|(r, _)| r.id != parent.id);
        child = (layers, parent.created_at.clone(), parent.id.clone());
    }
    Ok(pruned)
}

/// containers/storage's words for an image a container uses.
pub(super) fn in_use_message(container: &str) -> String {
    format!(
        "image used by {container}: image is in use by a container: consider listing external containers and force-removing image"
    )
}

/// How an image is removed.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RemoveOptions {
    /// The containers that use it go too
    pub force: bool,
    /// A container that runs is not removed with `force`: the image is
    /// refused (Docker's removal)
    pub spare_running: bool,
    /// Docker's `noprune`: the parents stay
    pub noprune: bool,
    /// An image that is not there is no error
    pub ignore: bool,
    /// The name is a manifest list's, which goes (libpod's
    /// `lookupManifest`)
    pub manifest_list: bool,
}

/// Remove the image `name`: the names untagged and the ids removed, and
/// podman's warnings of the stops of its containers that needed the kill.
pub(crate) async fn remove_of(
    state: &Arc<AppState>,
    name: &str,
    opts: &RemoveOptions,
) -> ApiResult<(Vec<String>, Vec<String>, Vec<String>)> {
    let mut warnings = Vec::new();
    let removed = if opts.manifest_list {
        remove_lookup_manifest(state, name).await
    } else {
        remove_one(
            state,
            name,
            opts.force,
            opts.spare_running,
            opts.noprune,
            true,
            &mut warnings,
        )
        .await
    };
    match removed {
        Ok((untagged, deleted)) => Ok((untagged, deleted, warnings)),
        Err(e) if opts.ignore && e.status.as_u16() == 404 => Ok(Default::default()),
        Err(e) => Err(e),
    }
}

/// Remove the manifest list `name` (its instances stay).
pub(super) async fn remove_manifest_list(
    state: &AppState,
    name: &str,
) -> ApiResult<(Vec<String>, Vec<String>)> {
    let (id, names) = state.image_service.manifest_delete(name).await?;
    for n in &names {
        state
            .podman
            .events
            .emit(Event::new(EventKind::Image, "untag", &id, n));
    }
    state.podman.events.emit(Event::new(
        EventKind::Image,
        "remove",
        &id,
        names.first().map_or("", String::as_str),
    ));
    Ok((names, vec![id]))
}

/// libpod's `lookupManifest`: the name must be a manifest list, which goes
/// (`podman manifest rm`), whatever image has the same name.
pub(super) async fn remove_lookup_manifest(
    state: &AppState,
    name: &str,
) -> ApiResult<(Vec<String>, Vec<String>)> {
    if state.image_service.manifest_lookup(name).await?.is_none() {
        return Err(ApiError::no_such(
            Kind::Image,
            format!("{name}: image is not a manifest list"),
        ));
    }
    remove_manifest_list(state, name).await
}

/// libimage's refusal to remove by ID (or `sha256:` digest) an image that
/// has several names, unless forced.
pub(super) fn refused_by_id(name: &str, id: &str, names: &[String]) -> Option<ApiError> {
    let bare = convert::strip_sha256(name);
    if names.len() < 2 || !velarx_types::digest::is_hex_id(bare) || !id.starts_with(bare) {
        return None;
    }
    let by = if velarx_shape::without_algorithm(name) != name {
        "digest"
    } else {
        "ID"
    };
    Some(
        ApiError::internal(format!(
            "unable to delete image \"{id}\" by {by} with more than one tag ([{}]): please force removal",
            names.join(" ")
        ))
        .with_condition(Condition::NeedsForce),
    )
}

/// The containers that use an image go with a forced removal: as podman, the
/// infra container of a pod goes with its pod (and the other containers of
/// the pod).
async fn remove_image_users(
    state: &std::sync::Arc<AppState>,
    users: Vec<String>,
    warnings: &mut Vec<String>,
) -> ApiResult<()> {
    for c in users {
        match super::super::pods::pod_of_container(state, &c).await {
            Some((pod, _, true)) => {
                warnings.extend(super::super::pods::remove_pod_by_id(state, &pod).await?);
            }
            _ => {
                if let Ok(rec) = super::super::lifecycle::resolve(state, &c).await {
                    // (stopped as `rm -f` stops it: its signal, its timeout)
                    warnings.extend(
                        super::super::lifecycle::remove_with_timeout(
                            state, &rec, true, false, None,
                        )
                        .await?,
                    );
                }
            }
        }
    }
    Ok(())
}

/// Remove a pull in progress: it is cancelled (nothing more is fetched, its
/// staging goes), as an image that is not used by a container, or whose
/// containers go with `force`.
async fn cancel_pull_of(
    state: &std::sync::Arc<AppState>,
    name: &str,
    force: bool,
    warnings: &mut Vec<String>,
) -> ApiResult<(Vec<String>, Vec<String>)> {
    let entry = state
        .image_service
        .pulling(name)
        .ok_or_else(|| ApiError::no_such(Kind::Image, format!("{name}: image not known")))?;
    let users = state
        .db
        .containers_using_image(&entry.pull.id)
        .await
        .map_err(|e| ApiError::db("listing the containers that use an image", e))?;
    if !users.is_empty() {
        if !force {
            return Err(ApiError::invalid_state(in_use_message(&users[0]))
                .with_cause("image is in use by a container"));
        }
        remove_image_users(state, users, warnings).await?;
    }
    state.image_service.cancel_pull(name, force).await?;
    let names = entry
        .pull
        .tags
        .iter()
        .map(|t| format!("{}:{}", t.repository, t.tag))
        .collect();
    Ok((names, vec![entry.pull.id]))
}

pub(super) async fn remove_one(
    state: &std::sync::Arc<AppState>,
    name: &str,
    force: bool,
    compat: bool,
    noprune: bool,
    refuse_by_id: bool,
    warnings: &mut Vec<String>,
) -> ApiResult<(Vec<String>, Vec<String>)> {
    // an image that is being pulled is cancelled; one whose pull ended in the
    // store meanwhile (while its containers went, before or during the
    // cancel) is removed as an image
    if let Err(velarx_types::ImageError::Pulling(_)) = state.image_service.get(name).await {
        match cancel_pull_of(state, name, force, warnings).await {
            Ok(removed) if state.image_service.get(name).await.is_err() => return Ok(removed),
            Ok(_) => {}
            Err(e) if e.status.as_u16() == 404 && state.image_service.get(name).await.is_ok() => {}
            Err(e) => return Err(e),
        }
    }
    let rec = match resolve_image(state, name).await {
        Ok(rec) => rec,
        // A manifest list goes, its instances stay.
        Err(e) if e.status.as_u16() == 404 => {
            if state.image_service.manifest_lookup(name).await?.is_none() {
                return Err(e);
            }
            return remove_manifest_list(state, name).await;
        }
        Err(e) => return Err(e),
    };
    let id = image_id(&rec);
    let tags = state.db.get_tags_for_image(&rec.id).await?;

    // NAME@DIGEST a pull by digest named the image: the name goes, and the
    // image with it when it has no other name
    let digest_names = state.db.get_digest_names_for_image(&rec.id).await?;
    if let Ok(r) = ImageReference::parse(name) {
        if let Some(d) = &r.digest {
            if digest_names.iter().any(|(n, dd)| *n == r.name() && dd == d)
                && (tags.len() + digest_names.len() > 1)
            {
                state.db.delete_image_digest_name(&r.name(), d).await?;
                let n = super::display_digest_name(&r.name(), &d.to_string());
                state
                    .podman
                    .events
                    .emit(Event::new(EventKind::Image, "untag", &id, &n));
                return Ok((vec![n], Vec::new()));
            }
        }
    }

    // NAME@DIGEST of an image that has names: the reference goes (velarx
    // keeps none), the image stays
    if !tags.is_empty()
        && name
            .split_once('@')
            .is_some_and(|(_, d)| d == rec.manifest_digest.to_string())
    {
        state
            .podman
            .events
            .emit(Event::new(EventKind::Image, "untag", &id, name));
        return Ok((vec![name.to_string()], Vec::new()));
    }

    // the name the reference resolved to, short names included
    let by_name = state.image_service.matching_tag(name, &tags);
    let by_name = by_name.as_ref();
    if let Some(t) = by_name {
        if tags.len() > 1 {
            delete_tag(state, t.repository.clone(), t.tag.clone()).await?;
            let n = display_name(t);
            state
                .podman
                .events
                .emit(Event::new(EventKind::Image, "untag", &id, &n));
            return Ok((vec![n], Vec::new()));
        }
    }
    if refuse_by_id && !force && by_name.is_none() {
        let mut names = tags.iter().map(display_name).collect::<Vec<_>>();
        // (the records of one configuration, pulled through several
        // manifests, are one image of podman's with all their names)
        for other in state.db.list_images().await? {
            if other.id != rec.id && other.config_digest == rec.config_digest {
                for t in state.db.get_tags_for_image(&other.id).await? {
                    names.push(display_name(&t));
                }
            }
        }
        if let Some(e) = refused_by_id(name, &id, &names) {
            return Err(e);
        }
    }

    let users = state
        .db
        .containers_using_image(&rec.id)
        .await
        .map_err(|e| ApiError::db("listing the containers that use an image", e))?;
    let mut running = None;
    if compat {
        for c in &users {
            if let Ok(rec) = state.db.get_container(c).await {
                if rec.state.is_alive() {
                    running = Some(c.clone());
                    break;
                }
            }
        }
    }
    if let Some(c) = running {
        return Err(ApiError::invalid_state(in_use_message(&c))
            .with_cause("image is in use by a container"));
    }
    let removes_users = !users.is_empty();
    if removes_users {
        if !force {
            return Err(ApiError::invalid_state(in_use_message(&users[0]))
                .with_cause("image is in use by a container"));
        }
        remove_image_users(state, users, warnings).await?;
    }
    // (the names of now: a container removed may have taken one, --rmi)
    let names = match removes_users {
        true => image_display_names(state, &rec).await?,
        false => tags.iter().map(display_name).collect(),
    };
    state.image_service.remove(&rec.id, force).await?;
    for n in &names {
        state
            .podman
            .events
            .emit(Event::new(EventKind::Image, "untag", &id, n));
    }
    state.podman.events.emit(Event::new(
        EventKind::Image,
        "remove",
        &id,
        names.first().map_or("", String::as_str),
    ));
    let mut deleted = vec![id];
    if !noprune {
        deleted.extend(prune_parents(state, &rec).await?);
    }
    let (mut names, mut deleted) = (names, deleted);
    // An id names every record of the configuration: the others go too.
    let bare = convert::strip_sha256(name);
    if bare.len() >= 3 && velarx_types::digest::is_hex_id(bare) {
        if let Ok(next) = resolve_image(state, name).await {
            if next.config_digest == rec.config_digest {
                let (n, d) = Box::pin(remove_one(
                    state, name, force, compat, noprune, false, warnings,
                ))
                .await?;
                names.extend(n);
                deleted.extend(
                    d.into_iter()
                        .filter(|d| !deleted.contains(d))
                        .collect::<Vec<_>>(),
                );
            }
        }
    }
    Ok((names, deleted))
}

/// How libpod's batch removal removes.
pub(crate) struct RemoveManyOptions {
    pub force: bool,
    pub ignore: bool,
    pub noprune: bool,
    /// Every image and manifest list too
    pub all: bool,
    pub manifest_list: bool,
}

/// Remove the images `images` (and every one with `all`): libpod's report.
pub(crate) async fn remove_many_of(
    state: &Arc<AppState>,
    mut images: Vec<String>,
    opts: RemoveManyOptions,
) -> ApiResult<velarx_proto::workload::ImagesRemoved> {
    let RemoveManyOptions {
        force,
        ignore,
        noprune,
        all,
        manifest_list,
    } = opts;
    let asked = images.len();
    if all {
        for l in state.image_service.manifest_lists().await? {
            images.push(l.id);
        }
        for rec in state.image_service.list().await? {
            images.push(rec.id);
        }
    }
    let (mut untagged, mut deleted, mut errors) = (Vec::new(), Vec::new(), Vec::new());
    let mut warnings = Vec::new();
    let mut exit_code = 0;
    for (i, name) in images.iter().enumerate() {
        let removed = if manifest_list && i < asked {
            remove_lookup_manifest(state, name).await
        } else {
            // (the images of `all` are named by ID, and are not refused)
            remove_one(state, name, force, false, noprune, i < asked, &mut warnings).await
        };
        match removed {
            Ok((u, d)) => {
                untagged.extend(u);
                deleted.extend(d);
            }
            // went with an image made on it
            Err(e) if e.status.as_u16() == 404 && i >= asked => {}
            Err(e) if e.status.as_u16() == 404 => {
                if !ignore {
                    errors.push(format!("{name}: image not known"));
                    if exit_code == 0 {
                        exit_code = 1;
                    }
                }
            }
            Err(e) => {
                exit_code = if e.status.as_u16() == 409 { 2 } else { 125 };
                errors.push(e.message);
            }
        }
    }
    Ok(velarx_proto::workload::ImagesRemoved {
        deleted,
        untagged,
        exit_code,
        errors,
        warnings,
    })
}

/// Remove the unused images (all the unused ones with `all`, and the
/// manifest lists, else the dangling ones) that `filters` (`key=value`)
/// select: the id and the size of each.
/// Remove the directories of RUN --mount=type=cache no step uses: the
/// bytes they took.
pub(crate) async fn prune_build_cache_of(state: &Arc<AppState>) -> ApiResult<u64> {
    let svc = state.build_service.clone();
    tokio::task::spawn_blocking(move || svc.prune_cache_mounts())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .map_err(|e| ApiError::internal(e.to_string()))
}

pub(crate) async fn prune_of(
    state: &Arc<AppState>,
    all: bool,
    filters: &[String],
) -> ApiResult<Vec<velarx_proto::workload::PrunedImage>> {
    use velarx_proto::workload::PrunedImage;
    // (the store's ids are not podman's)
    let mut known = std::collections::HashMap::new();
    for rec in state.image_service.list().await? {
        let id = rec.id.clone();
        let Some(v) = View::load(state, rec).await? else {
            continue;
        };
        known.insert(id, v.id);
    }
    // (the size of each is what its removal freed, not what the image
    // weighed: podman reports the whole image, the layers other images
    // share and the containers hold included)
    let removed = state.image_service.prune(all, filters).await?;
    let mut pruned = Vec::new();
    // unused images include the manifest lists, as for libimage
    if all {
        for l in state.image_service.manifest_lists().await? {
            let (id, _) = state.image_service.manifest_delete(&l.id).await?;
            state
                .podman
                .events
                .emit(Event::new(EventKind::Image, "remove", &id, ""));
            pruned.push(PrunedImage { id, size: 0 });
        }
    }
    for (id, freed) in removed {
        let pid = known
            .remove(&id)
            .unwrap_or_else(|| convert::strip_sha256(&id).to_string());
        state
            .podman
            .events
            .emit(Event::new(EventKind::Image, "remove", &pid, ""));
        pruned.push(PrunedImage {
            id: pid,
            size: freed,
        });
    }
    Ok(pruned)
}
