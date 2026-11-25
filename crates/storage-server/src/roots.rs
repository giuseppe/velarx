// SPDX-License-Identifier: Apache-2.0
//! The roots of containers, the image mounts, and the calls that read or
//! mend what the driver made of the layers: `CreateRoot`,
//! `CreateImageVolume`, `Mounts`, `MountImage`, `WritableRoot`, `Size`, `Exists`,
//! `RemoveRoot`, `Check`, `Repair` and `Collect`.

use crate::service::{capabilities, failed, no_mounts, reply, reply_fds, Call, Server, NAME};
use crate::store::{Container, Store, Volume};
use std::collections::HashSet;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use velarx_db::{ImageRecord, LayerRecord};
use velarx_graph::{
    DriverError, DriverResult, LayerRef, MountRequest, MountsRequest, Planned, Purpose, Remedy,
    StorageDriver, VerityAsk, Writable, WritableOptions,
};
use velarx_storage_client::convert;
use velarx_storage_client::proto;
use velarx_storage_client::request;
use velarx_types::digest::{Algorithm, Digest};
use velarx_wire::varlink::Conn;

type Out = Vec<(Vec<u8>, Vec<OwnedFd>)>;

/// The rows of the layers a request names: missing is `Missing` with the
/// remedy of pulling again.
pub(crate) fn records(store: &Store, layers: &[LayerRef]) -> DriverResult<Vec<LayerRecord>> {
    layers
        .iter()
        .map(|l| {
            store.rt.block_on(store.db.get_layer(&l.key)).map_err(|_| {
                DriverError::missing(
                    NAME,
                    Some(&l.key),
                    format!("the layer {} is not stored", l.key),
                    Remedy::PullAgain,
                )
            })
        })
        .collect()
}

/// The image of a request: what the driver reads of it is its id and the
/// diff ids of its layers.
fn image_of(id: &str, layers: &[LayerRef]) -> ImageRecord {
    let diff_ids: Vec<String> = layers.iter().map(|l| l.diff_id.to_string()).collect();
    let none = Digest::empty(Algorithm::Sha256);
    ImageRecord {
        id: id.to_string(),
        manifest_digest: none,
        config_digest: none,
        manifest: "{}".into(),
        config: serde_json::json!({
            "architecture": "amd64", "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": diff_ids}
        })
        .to_string(),
        created_at: String::new(),
        is_lazy: false,
    }
}

/// What a request asks of a mount, held for the `MountRequest` that borrows
/// it.
struct Ask {
    mapping: Option<velarx_fuse::IdTranslate>,
    accepted: Option<Vec<Vec<String>>>,
    idmap_mount: bool,
    label: Option<String>,
}

impl Ask {
    fn of(a: &proto::MountAsk) -> Self {
        Self {
            mapping: a.mapping.as_ref().map(convert::id_translate),
            accepted: a
                .verity
                .as_ref()
                .map(|v| v.iter().map(|d| d.digests.clone()).collect()),
            idmap_mount: a.idmap_mount,
            label: a.label.clone(),
        }
    }

    fn request<'a>(
        &'a self,
        container: &'a Writable,
        purpose: Purpose,
        image: &'a ImageRecord,
        layers: &'a [LayerRecord],
    ) -> MountRequest<'a> {
        MountRequest {
            container,
            purpose,
            image,
            layers,
            mapping: self.mapping.as_ref(),
            translate: None,
            idmap_mount: self.idmap_mount,
            label: self.label.as_deref(),
            verity: match &self.accepted {
                Some(accepted) => VerityAsk::Enforce {
                    accepted,
                    chain: None,
                },
                None => VerityAsk::Off,
            },
            volatile: false,
        }
    }
}

/// The work directory `CreateRoot` names, where the root of a container is
/// made: the engine's directory for the store (`<graph root>/varlink/work`),
/// so a directory of the client's user that nobody else can enter, named
/// without links.  Anything else is refused: the server makes the roots as
/// its own user, and a client does not choose where else they go.
fn work_directory(named: &str, uid: u32) -> DriverResult<std::path::PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let path = std::path::Path::new(named);
    let canonical = path
        .is_absolute()
        .then(|| std::fs::canonicalize(path).ok())
        .flatten();
    let Some(canonical) = canonical.filter(|c| c == path) else {
        return Err(failed(format!(
            "the work directory {named:?} is not an absolute path without links"
        )));
    };
    let meta = std::fs::symlink_metadata(&canonical).map_err(failed)?;
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
        return Err(failed(format!(
            "the work directory {named:?} is not a directory of uid {uid} that only it can enter (it is uid {}, mode {:04o})",
            meta.uid(),
            meta.mode() & 0o7777
        )));
    }
    Ok(canonical)
}

impl Server {
    fn writable(store: &Store, id: &str) -> DriverResult<(Writable, Container)> {
        let c = store.container(id)?.ok_or_else(|| {
            DriverError::missing(
                NAME,
                None,
                format!("the container {id} has no root here"),
                Remedy::RecreateContainer,
            )
        })?;
        Ok((Writable::new(id, c.bundle.clone()), c))
    }

    pub(crate) fn create_root(&self, call: Call<'_>, conn: &mut Conn) -> DriverResult<Out> {
        let p: request::CreateRoot<String, Vec<proto::LayerRef>, proto::MountAsk> =
            call.params()?;
        let store = self.store(&call, &p.store)?;
        // (the id names a file of the server's and a directory of the work
        // directory: a plain name, refused before anything is made)
        let existing = store.container(&p.container)?;
        let workdir = work_directory(&p.workdir, call.uid)?;
        let bundle = workdir.join(&p.container);
        let refs = crate::service::refs(&p.layers)?;
        let image = p.image.clone();
        let w = Writable::new(p.container.clone(), bundle.clone());
        self.long(conn, "CreateRoot", || {
            std::fs::create_dir_all(&bundle).map_err(failed)?;
            let opts = WritableOptions {
                size_limit: p.size_limit,
            };
            let ask = Ask::of(&p.ask);
            let planned: Option<Planned> = match &image {
                Some(id) => {
                    let layers = records(&store, &refs)?;
                    let img = image_of(id, &refs);
                    let req = ask.request(&w, Purpose::Root, &img, &layers);
                    store.vfs.writable_create(
                        &w,
                        p.owner.map(|o| (o.uid, o.gid)),
                        &opts,
                        Some(&req),
                    )?
                }
                None => {
                    store
                        .vfs
                        .writable_create(&w, p.owner.map(|o| (o.uid, o.gid)), &opts, None)?
                }
            };
            let mut c = existing.unwrap_or_default();
            c.bundle = bundle.clone();
            c.workdir = workdir.clone();
            c.image = image.clone();
            c.layers = p.layers.clone();
            store.save_container(&p.container, &c)?;
            let root = planned
                .map(|pl| convert::mounted(NAME, &pl.plan, pl.idmap, pl.label, &workdir, None))
                .transpose()?;
            Ok(proto::Created {
                progress: None,
                root,
            })
        })
    }

    pub(crate) fn create_image_volume(&self, call: Call<'_>, conn: &mut Conn) -> DriverResult<Out> {
        let p: request::CreateImageVolume<String, Vec<proto::LayerRef>, proto::MountAsk> =
            call.params()?;
        let store = self.store(&call, &p.store)?;
        if capabilities().volume.is_none() {
            return Err(no_mounts());
        }
        let (w, mut c) = Self::writable(&store, &p.container)?;
        let refs = crate::service::refs(&p.layers)?;
        self.long(conn, "CreateImageVolume", || {
            let layers = records(&store, &refs)?;
            let img = image_of(&p.image, &refs);
            let ask = Ask::of(&p.ask);
            let req = ask.request(&w, Purpose::Volume { index: p.index }, &img, &layers);
            let pl = store.vfs.image_volume_create(&req)?;
            c.volumes.insert(
                p.index,
                Volume {
                    image: p.image.clone(),
                    layers: p.layers.clone(),
                },
            );
            store.save_container(&p.container, &c)?;
            let volume = convert::mounted(NAME, &pl.plan, pl.idmap, pl.label, &c.workdir, None)?;
            Ok(proto::VolumeCreated {
                progress: None,
                volume: Some(volume),
            })
        })
    }

    pub(crate) fn mounts(&self, call: Call<'_>) -> DriverResult<Out> {
        let p: request::Mounts<String, proto::MountAsk, Vec<proto::VolumeAsk>> = call.params()?;
        let store = self.store(&call, &p.store)?;
        if !p.volumes.is_empty() && capabilities().volume.is_none() {
            return Err(no_mounts());
        }
        let (w, c) = Self::writable(&store, &p.container)?;
        // (the layers and images the container was made of)
        let root_layers = crate::service::refs(&c.layers)?;
        let root_records = records(&store, &root_layers)?;
        let root_image = image_of(c.image.as_deref().unwrap_or(""), &root_layers);
        let root_ask = p.root.as_ref().map(Ask::of);
        let mut volume_data = Vec::new();
        for v in &p.volumes {
            let vol = c.volumes.get(&v.index).ok_or_else(|| {
                DriverError::missing(
                    NAME,
                    None,
                    format!(
                        "the container {} has no image mount {}: it is removed and created again",
                        p.container, v.index
                    ),
                    Remedy::RecreateContainer,
                )
            })?;
            let refs = crate::service::refs(&vol.layers)?;
            let recs = records(&store, &refs)?;
            volume_data.push((v.index, image_of(&vol.image, &refs), recs, Ask::of(&v.ask)));
        }
        let request = MountsRequest {
            root: match (&root_ask, &c.image) {
                (Some(ask), Some(_)) => {
                    Some(ask.request(&w, Purpose::Root, &root_image, &root_records))
                }
                _ => None,
            },
            volumes: volume_data
                .iter()
                .map(|(index, img, recs, ask)| {
                    ask.request(&w, Purpose::Volume { index: *index }, img, recs)
                })
                .collect(),
        };
        let mounted = store.vfs.mounts(&request)?;
        let mut fds = Vec::new();
        let mut say = |r: velarx_graph::Rootfs| -> DriverResult<proto::Mounted> {
            let position = r.fd.map(|fd| {
                fds.push(fd);
                (fds.len() - 1) as u32
            });
            convert::mounted(NAME, &r.plan, r.idmap, r.label, &c.workdir, position)
        };
        let root = mounted.root.map(&mut say).transpose()?;
        let volumes = mounted
            .volumes
            .into_iter()
            .map(&mut say)
            .collect::<DriverResult<Vec<_>>>()?;
        Ok(reply_fds(&proto::MountsReply { root, volumes }, fds))
    }

    /// `LayerFiles`: the table file of a committed layer, and its tar-split if
    /// it has one, as the descriptors 0 and 1.  The files are the ones the
    /// pull wrote with the layer (`Index` of the feed gave them); the engine
    /// checks them against its own record of the layer.
    pub(crate) fn layer_files(&self, call: Call<'_>) -> DriverResult<Out> {
        use velarx_db::layer_files;
        let p: request::LayerFiles<String> = call.params()?;
        let store = self.store(&call, &p.store)?;
        let key = velarx_types::LayerKey::parse(&p.layer)
            .ok_or_else(|| failed(format!("{:?} is no layer key", p.layer)))?;
        let missing = || {
            DriverError::missing(
                NAME,
                Some(&key),
                format!("the layer {key} is not stored"),
                Remedy::PullAgain,
            )
        };
        // (the files its own row names: the engine checks them against its)
        let Some((Some(toc), tarsplit)) = store
            .rt
            .block_on(store.db.layer_file_digests(&key))
            .map_err(failed)?
        else {
            return Err(missing());
        };
        let root = layer_files::root_of(store.files.root());
        let open = |kind, digest| {
            std::fs::File::open(layer_files::file(root, &key, kind, digest))
                .map(OwnedFd::from)
                .map_err(|_| missing())
        };
        let mut fds = vec![open(layer_files::TOC, &toc)?];
        if let Some(tarsplit) = tarsplit {
            fds.push(open(layer_files::TARSPLIT, &tarsplit)?);
        }
        Ok(reply_fds(&proto::Ack {}, fds))
    }

    /// `MountImage`: the root of the image of the layers as one descriptor.
    /// The server has no overlay of its layers (the vfs driver copies them),
    /// so it keeps a copy of each image it is asked for, made once, named by
    /// the chain id of its top layer, dropped at the collection that no longer
    /// keeps one of its layers; the mount is a read-only clone of it where
    /// the process may make one, and the directory itself where it may not.
    pub(crate) fn mount_image(&self, call: Call<'_>) -> DriverResult<Out> {
        use rustix::mount::{open_tree, OpenTreeFlags};
        let p: request::MountImage<String, Vec<proto::LayerRef>> = call.params()?;
        let store = self.store(&call, &p.store)?;
        let refs = crate::service::refs(&p.layers)?;
        let Some(top) = refs.last() else {
            return Err(failed("MountImage names no layer"));
        };
        let id = format!("{}{}", crate::store::READ_PREFIX, top.chain_id.hex());
        let bundle = store.dir.join("read").join(&id);
        let w = Writable::new(&id, &bundle);
        // (made, and opened, while no other call makes it or a collection
        // drops it)
        let dir = {
            let _making = store.reading.lock().unwrap_or_else(|e| e.into_inner());
            if store.container(&id)?.is_none() || !store.vfs.writable_exists(&w)? {
                let layers = records(&store, &refs)?;
                std::fs::create_dir_all(&bundle).map_err(failed)?;
                let img = image_of(&id, &refs);
                let ask = Ask {
                    mapping: None,
                    accepted: None,
                    idmap_mount: false,
                    label: None,
                };
                let req = ask.request(&w, Purpose::Root, &img, &layers);
                store
                    .vfs
                    .writable_create(&w, None, &WritableOptions::default(), Some(&req))?;
                store.save_container(
                    &id,
                    &Container {
                        bundle: bundle.clone(),
                        workdir: store.dir.join("read"),
                        image: None,
                        layers: p.layers.clone(),
                        volumes: Default::default(),
                    },
                )?;
            }
            store.vfs.writable_root(&w)?
        };
        let fd = match open_tree(
            &dir,
            "",
            OpenTreeFlags::OPEN_TREE_CLONE
                | OpenTreeFlags::OPEN_TREE_CLOEXEC
                | OpenTreeFlags::AT_EMPTY_PATH,
        ) {
            Ok(tree) => {
                velarx_sys::mount::setattr_fd(
                    std::os::fd::AsFd::as_fd(&tree),
                    &velarx_sys::mount::MountAttr {
                        attr_set: libc::MOUNT_ATTR_RDONLY,
                        ..Default::default()
                    },
                )
                .map_err(failed)?;
                tree
            }
            // (a process that may not mount hands the directory: the engine
            // only reads below it)
            Err(_) => dir,
        };
        Ok(reply_fds(&proto::Ack {}, vec![fd]))
    }

    pub(crate) fn container_call(&self, method: &str, call: Call<'_>) -> DriverResult<Out> {
        let p: request::OfContainer<String> = call.params()?;
        let store = self.store(&call, &p.store)?;
        if method == "RemoveRoot" {
            // (idempotent: a root that is not there is removed)
            if let Some(c) = store.container(&p.container)? {
                let w = Writable::new(&p.container, c.bundle.clone());
                store.vfs.writable_remove(&w)?;
                match velarx_base::tree::remove_dir_all_confined(&c.bundle) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(failed(e)),
                    _ => {}
                }
                store.forget_container(&p.container)?;
            }
            return Ok(reply(&proto::Ack {}));
        }
        let Some(c) = store.container(&p.container)? else {
            return match method {
                "Exists" => Ok(reply(&proto::ExistsReply { exists: false })),
                "Size" => Ok(reply(&proto::SizeReply { bytes: 0 })),
                _ => Err(DriverError::missing(
                    NAME,
                    None,
                    format!("the container {} has no root here", p.container),
                    Remedy::RecreateContainer,
                )),
            };
        };
        let w = Writable::new(&p.container, c.bundle.clone());
        match method {
            "Exists" => Ok(reply(&proto::ExistsReply {
                exists: store.vfs.writable_exists(&w)?,
            })),
            "Size" => Ok(reply(&proto::SizeReply {
                bytes: store.vfs.writable_size(&w)?,
            })),
            _ => {
                let fd = store.vfs.writable_root(&w)?;
                Ok(reply_fds(&proto::Ack {}, vec![fd]))
            }
        }
    }

    pub(crate) fn check(&self, call: Call<'_>, conn: &mut Conn) -> DriverResult<Out> {
        let p: request::Check<String, Vec<proto::LayerRef>> = call.params()?;
        let store = self.store(&call, &p.store)?;
        let refs = crate::service::refs(&p.layers)?;
        self.long(conn, "Check", || {
            let layers = records(&store, &refs)?;
            let image = image_of(&p.image, &refs);
            let problems = store
                .rt
                .block_on(store.vfs.check(&image, &layers, p.full))?;
            Ok(proto::Checked {
                progress: None,
                problems: Some(problems.iter().map(convert::problem_to_wire).collect()),
            })
        })
    }

    pub(crate) fn repair(&self, call: Call<'_>, conn: &mut Conn) -> DriverResult<Out> {
        let p: request::Repair<String, Vec<proto::LayerRef>> = call.params()?;
        let store = self.store(&call, &p.store)?;
        let refs = crate::service::refs(&p.layers)?;
        self.long(conn, "Repair", || {
            let made = store.rt.block_on(store.vfs.repair(&refs))?;
            for (key, a) in &made {
                store
                    .rt
                    .block_on(store.db.set_layer_erofs(key, &a.image_digest, &a.owners))
                    .map_err(failed)?;
            }
            Ok(proto::Repaired {
                progress: None,
                artifacts: Some(
                    made.iter()
                        .map(|(k, a)| convert::artifact_to_wire(k, a))
                        .collect(),
                ),
            })
        })
    }

    pub(crate) fn collect(&self, mut call: Call<'_>, conn: &mut Conn) -> DriverResult<Out> {
        let p: request::Collect<String> = call.params()?;
        let store = self.store(&call, &p.store)?;
        let keep = Self::keep_of(&mut call, p.keep_length)?;
        self.long(conn, "Collect", || {
            let (freed, errors) = collect_store(&store, &keep)?;
            Ok(proto::Collection {
                progress: None,
                bytes_freed: Some(freed),
                errors,
            })
        })
    }
}

/// What the engine's collection does for a store of its own, and the driver's
/// part: the layers the keep set does not name (and no live pull holds) are
/// forgotten, the objects no layer names that nothing has touched for the
/// grace period go, and the driver removes what it made of the layers.
fn collect_store(
    store: &Arc<Store>,
    keep: &velarx_graph::Keep,
) -> DriverResult<(u64, Vec<String>)> {
    let held: HashSet<String> = {
        let st = store.state();
        st.claimed_layers().cloned().collect()
    };
    let kept: HashSet<String> = keep
        .layers
        .iter()
        .map(ToString::to_string)
        .chain(held)
        .collect();
    let rows = store.rt.block_on(store.db.list_layers()).map_err(failed)?;
    let gone: Vec<String> = rows
        .iter()
        .map(|l| l.key.to_string())
        .filter(|k| !kept.contains(k))
        .collect();
    forget_layers(store, gone)?;
    // (the files of the layers the rows of which are gone, those of a pull
    // that was not committed, and what a writer that died left; a layer of
    // a live pull is kept.  The engine asks for a collection holding the
    // lock of the store exclusive: no writer is between its files and its
    // row)
    let named = kept
        .iter()
        .filter_map(|k| velarx_types::LayerKey::parse(k))
        .map(|k| k.file_stem())
        .collect();
    let swept =
        velarx_db::layer_files::sweep(velarx_db::layer_files::root_of(store.files.root()), &named)
            .map_err(failed)?;
    let mut recorded: HashSet<String> = HashSet::new();
    for l in rows.iter().filter(|l| kept.contains(&l.key.to_string())) {
        let refs = store
            .rt
            .block_on(store.db.get_layer_file_refs(&l.key))
            .map_err(failed)?;
        recorded.extend(refs.into_iter().map(|r| r.file_digest));
    }
    // (the objects a live pull staged are not recorded yet)
    recorded.extend(store.state().live_keys());
    let mut freed = swept;
    let mut errors = Vec::new();
    let found = velarx_graph::objects::objects(store.files.root(), &recorded, keep.grace)
        .map_err(failed)?;
    for path in found.orphans {
        let size = std::fs::metadata(&path).map_or(0, |m| m.len());
        match std::fs::remove_file(&path) {
            Ok(()) => freed += size,
            Err(e) => errors.push(format!("Failed to remove {}: {e}", path.display())),
        }
    }
    store.forget_dangling_aliases();
    forget_image_copies(store, &kept);
    let rest = store.vfs.collect(&velarx_graph::Keep {
        layers: kept
            .iter()
            .filter_map(|k| velarx_types::LayerKey::parse(k))
            .collect(),
        ..keep.clone()
    })?;
    errors.extend(rest.errors);
    Ok((freed + rest.bytes_freed, errors))
}

/// Delete the rows of `gone` layers, and with them (the schema cascades)
/// their file references, in one transaction: a failure leaves every layer
/// with its references.
fn forget_layers(store: &Store, gone: Vec<String>) -> DriverResult<()> {
    store
        .rt
        .block_on(store.db.conn().call(move |conn| {
            let tx = conn.transaction()?;
            for k in &gone {
                tx.execute("DELETE FROM layers WHERE id = ?1", [k])?;
            }
            tx.commit()?;
            Ok(())
        }))
        .map_err(failed)
}

/// The copies of images the server reads for `MountImage` that have a layer
/// the collection no longer keeps.
fn forget_image_copies(store: &Arc<Store>, kept: &HashSet<String>) {
    // (not while a `MountImage` makes or opens one: a descriptor handed
    // over keeps the files of a copy dropped after it)
    let _making = store.reading.lock().unwrap_or_else(|e| e.into_inner());
    for id in store.image_copies() {
        let Ok(Some(c)) = store.container(&id) else {
            continue;
        };
        if c.layers.iter().all(|l| kept.contains(&l.key.to_string())) {
            continue;
        }
        let w = Writable::new(&id, c.bundle.clone());
        let _ = store.vfs.writable_remove(&w);
        let _ = velarx_base::tree::remove_dir_all_confined(&c.bundle);
        let _ = store.forget_container(&id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Stores;

    /// A failure while a layer is forgotten leaves the layer and its file
    /// references, not the layer without them.
    #[test]
    fn a_failed_forget_leaves_the_layer_with_its_references() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        let stores = Stores::new(root.path(), rt.handle().clone());
        let store = stores
            .get(1000, "0123456789abcdef0123456789abcdef")
            .unwrap();
        let count = |table: &'static str| -> i64 {
            rt.block_on(store.db.conn().call(move |conn| {
                Ok(conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?)
            }))
            .unwrap()
        };
        rt.block_on(store.db.conn().call(|conn| {
            conn.execute_batch(
                "INSERT INTO layers (id, blob, size, stream_size, created_at) VALUES ('l', 'b', 1, 1, 't');
                 INSERT INTO files (digest, size, created_at) VALUES ('f', 1, 't');
                 INSERT INTO file_refs (layer_id, file_digest) VALUES ('l', 'f');
                 CREATE TRIGGER injected BEFORE DELETE ON layers
                 BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )?;
            Ok(())
        }))
        .unwrap();
        assert!(forget_layers(&store, vec!["l".into()]).is_err());
        assert_eq!((count("layers"), count("file_refs")), (1, 1));
        rt.block_on(store.db.conn().call(|conn| {
            conn.execute_batch("DROP TRIGGER injected")?;
            Ok(())
        }))
        .unwrap();
        forget_layers(&store, vec!["l".into()]).unwrap();
        assert_eq!((count("layers"), count("file_refs")), (0, 0));
    }
}
