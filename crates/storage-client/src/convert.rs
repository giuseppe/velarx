// SPDX-License-Identifier: Apache-2.0
//! The engine's types as the wire has them, and back.  A value of an enum in
//! a reply that this build does not know is a `Storage` error that names it
//! (`DriverError::unknown_value`), never a protocol error.

use crate::proto::{self, word, Open};
use serde::Serialize;
use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use velarx_db::{ImageRecord, LayerRecord};
use velarx_fuse::plan::{Directory, MountFd, RootfsPlan};
use velarx_graph::{
    assign_fds, Capabilities, DriverError, DriverResult, IdmapDone, IdmapWay, LabelDone,
    LayerArtifact, LayerRef, Limits, MountCaps, MountRequest, Planned, Prefs, Problem, ProblemKind,
    VerityAsk, VerityEnforcement,
};
use velarx_types::digest::Digest;
use velarx_types::LayerKey;

/// The name of a value of a wire enum.
fn name_of<E: Serialize>(e: &E) -> String {
    match serde_json::to_value(e) {
        Ok(serde_json::Value::String(s)) => s,
        _ => String::new(),
    }
}

/// The value of an open enum, or the `Storage` error that names the one that
/// is not known.
pub fn known<E>(driver: &str, what: &str, v: Open<E>) -> DriverResult<E> {
    v.known()
        .map_err(|name| DriverError::unknown_value(driver, what, format!("{name:?}")))
}

pub fn wire_ref(l: &LayerRef) -> proto::LayerRef {
    proto::LayerRef {
        key: l.key.to_string(),
        diff_id: l.diff_id.to_string(),
        chain_id: l.chain_id.to_string(),
    }
}

pub fn wire_refs(layers: &[LayerRef]) -> Vec<proto::LayerRef> {
    layers.iter().map(wire_ref).collect()
}

/// The layers of a mount request as the wire names them: the key and diff id
/// of each, and its chain id, which the engine computes from the diff ids of
/// the configuration of the image (a layer made here, by a commit, has its
/// diff id in its record).
pub fn refs_of(image: &ImageRecord, layers: &[LayerRecord]) -> Vec<LayerRef> {
    let from_config = serde_json::from_str::<velarx_types::OciConfig>(&image.config)
        .ok()
        .map(|c| c.rootfs.diff_ids)
        .filter(|d| d.len() == layers.len());
    refs_with(layers, from_config)
}

/// The same for layers whose image is not at hand: the diff ids their records
/// have.
pub fn refs_of_layers(layers: &[LayerRecord]) -> Vec<LayerRef> {
    refs_with(layers, None)
}

fn refs_with(layers: &[LayerRecord], from_config: Option<Vec<Digest>>) -> Vec<LayerRef> {
    let diff_ids: Vec<Digest> = match from_config {
        Some(d) => d,
        None => layers
            .iter()
            .map(|l| l.diff_id.unwrap_or(*l.key.digest()))
            .collect(),
    };
    let chains = velarx_types::chain_ids(&diff_ids);
    layers
        .iter()
        .zip(diff_ids)
        .zip(chains)
        .map(|((l, diff_id), chain_id)| LayerRef {
            key: l.key,
            diff_id,
            chain_id,
        })
        .collect()
}

fn mapping(m: &velarx_fuse::IdTranslate) -> proto::Mapping {
    let ids = |v: &[velarx_proto::pod::IdMapping]| {
        v.iter()
            .map(|i| proto::IdMap {
                container_id: i.container_id,
                host_id: i.host_id,
                size: i.size,
            })
            .collect()
    };
    proto::Mapping {
        uid: ids(&m.uid),
        gid: ids(&m.gid),
        squash: m.squash,
    }
}

/// What the engine asks of one mount.
pub fn mount_ask(req: &MountRequest<'_>) -> proto::MountAsk {
    proto::MountAsk {
        mapping: req.mapping.map(mapping),
        idmap_mount: req.idmap_mount,
        label: req.label.map(str::to_string),
        verity: match &req.verity {
            VerityAsk::Off => None,
            VerityAsk::Enforce { accepted, .. } => Some(
                accepted
                    .iter()
                    .map(|digests| proto::Accepted {
                        digests: digests.clone(),
                    })
                    .collect(),
            ),
        },
    }
}

/// The name a driver gives itself, for the logs and the messages: a short
/// word (letters, digits, `.`, `_`, `-`), never text that could pass for
/// another line or a terminal's escape.
pub fn driver_name(name: &str) -> DriverResult<String> {
    if !velarx_base::ipc::is_service_name(name) {
        return Err(DriverError::storage(
            "varlink",
            format!(
                "the storage service calls itself {:?}: a name is 1 to 64 letters, digits, `.`, `_` or `-`",
                name.chars().take(80).collect::<String>()
            ),
        ));
    }
    Ok(name.to_string())
}

/// The directory a driver made for a root, as the monitor takes it: `path`
/// is relative to the work directory of the store (`workdir`), which is the
/// base the monitor checks; the driver cannot name any other place of the
/// host (an absolute path, `..`, an empty or `.` component are refused here
/// and again by the monitor, which resolves it beneath the base without
/// following a link).
fn directory(driver: &str, workdir: &Path, path: Option<&str>) -> DriverResult<RootfsPlan> {
    let bad = |why: String| DriverError::storage(driver, format!("the root directory: {why}"));
    let path = path.ok_or_else(|| bad("a directory mount has no path".into()))?;
    if path.starts_with('/') {
        return Err(bad(format!(
            "{path:?} is not relative to the work directory of the store"
        )));
    }
    let plan = Directory {
        beneath: workdir.to_path_buf(),
        path: PathBuf::from(path),
    };
    plan.validate().map_err(bad)?;
    Ok(RootfsPlan::Directory(plan))
}

/// What a mount is, from what the driver said of it.  `fd` is whether the
/// reply carries its descriptor: a `mount_fd` has one in a reply of
/// `Mounts`, and none anywhere else; a `directory` never has one.
fn rootfs_parts(
    driver: &str,
    workdir: &Path,
    m: proto::Mounted,
    root: bool,
    with_fd: bool,
) -> DriverResult<(RootfsPlan, Option<usize>, IdmapDone, LabelDone)> {
    let kind = known(driver, "the kind of a mount", m.kind)?;
    let idmap = match known(driver, "the idmap of a mount", m.idmap)? {
        proto::Idmap::None => IdmapDone::None,
        proto::Idmap::Applied => IdmapDone::Applied,
        proto::Idmap::Mount => IdmapDone::Mount,
    };
    let label = match known(driver, "the label of a mount", m.label)? {
        proto::Label::None => LabelDone::None,
        proto::Label::MountContext => LabelDone::MountContext,
        proto::Label::Files => LabelDone::Files,
    };
    let (plan, position) = match kind {
        proto::MountKind::Directory => {
            if !root {
                return Err(DriverError::storage(
                    driver,
                    "the storage service answered a directory for an image mount: only a root may be one",
                ));
            }
            if m.fd.is_some() {
                return Err(DriverError::storage(
                    driver,
                    "the storage service answered a directory mount with a descriptor",
                ));
            }
            (directory(driver, workdir, m.path.as_deref())?, None)
        }
        proto::MountKind::MountFd => {
            let position = match (m.fd, with_fd) {
                (Some(p), true) => Some(p as usize),
                (None, true) => {
                    return Err(DriverError::storage(
                        driver,
                        "the storage service answered a mount_fd mount without the position of its descriptor",
                    ))
                }
                (None, false) => None,
                (Some(_), false) => {
                    return Err(DriverError::storage(
                        driver,
                        "the storage service named a descriptor in a reply that has none: the mounts are made at create, the descriptors come with Mounts",
                    ))
                }
            };
            (
                RootfsPlan::MountFd(MountFd {
                    server: false,
                    fd_index: 0,
                    idmap: idmap == IdmapDone::Mount,
                }),
                position,
            )
        }
    };
    Ok((plan, position, idmap, label))
}

/// What a mount is going to be (the reply of `CreateRoot` and
/// `CreateImageVolume`), with no descriptor.
pub fn planned(
    driver: &str,
    workdir: &Path,
    m: proto::Mounted,
    root: bool,
) -> DriverResult<Planned> {
    let (plan, _, idmap, label) = rootfs_parts(driver, workdir, m, root, false)?;
    Ok(Planned { plan, idmap, label })
}

/// The mounts of a reply of `Mounts` with the descriptors they name: the
/// root if there is one, then the volumes, each given its descriptor by the
/// position it says (`assign_fds`).
pub fn rootfs_list(
    driver: &str,
    workdir: &Path,
    mounted: Vec<(proto::Mounted, bool)>,
    fds: Vec<OwnedFd>,
) -> DriverResult<Vec<velarx_graph::Rootfs>> {
    let mut parts = Vec::with_capacity(mounted.len());
    for (m, root) in mounted {
        parts.push(rootfs_parts(driver, workdir, m, root, true)?);
    }
    let positions: Vec<Option<usize>> = parts.iter().map(|p| p.1).collect();
    let fds = assign_fds(driver, &positions, fds)?;
    Ok(parts
        .into_iter()
        .zip(fds)
        .map(|((plan, _, idmap, label), fd)| velarx_graph::Rootfs {
            plan,
            fd,
            idmap,
            label,
            verity: velarx_graph::VerityDone::None,
            measured: Vec::new(),
            server: None,
        })
        .collect())
}

pub fn problem(driver: &str, p: proto::Problem) -> DriverResult<Problem> {
    let kind = match p.kind {
        Open::Known(k) => ProblemKind::from_wire(driver, &name_of(&k))?,
        Open::Unknown(name) => ProblemKind::from_wire(driver, &name)?,
    };
    Ok(Problem {
        kind,
        message: p.message,
        layer: match p.layer.as_deref() {
            Some(l) => Some(LayerKey::parse(l).ok_or_else(|| {
                DriverError::storage(driver, format!("the problem names the layer {l:?}"))
            })?),
            None => None,
        },
        path: p.path.map(PathBuf::from),
        repair: p.repair,
    })
}

pub fn artifacts(
    driver: &str,
    list: Vec<proto::Artifact>,
) -> DriverResult<HashMap<LayerKey, LayerArtifact>> {
    list.into_iter()
        .map(|a| {
            let key = LayerKey::parse(&a.key).ok_or_else(|| {
                DriverError::storage(driver, format!("the artifact of the layer {:?}", a.key))
            })?;
            Ok((
                key,
                LayerArtifact {
                    image_digest: a.image_digest,
                    // (`[[uids], [gids]]` is what the engine records)
                    owners: serde_json::to_string(&[a.owners.uids, a.owners.gids])
                        .map_err(|e| DriverError::storage(driver, e.to_string()))?,
                },
            ))
        })
        .collect()
}

fn mount_caps(driver: &str, c: proto::MountCaps) -> DriverResult<MountCaps> {
    let idmap = c
        .idmap
        .into_iter()
        .map(|w| {
            Ok(match known(driver, "a way to map the ids", w)? {
                proto::IdmapWay::MonitorMount => IdmapWay::MonitorMount,
                proto::IdmapWay::DriverMount => IdmapWay::DriverMount,
                proto::IdmapWay::AtCopy => IdmapWay::AtCopy,
                proto::IdmapWay::Translate => IdmapWay::Translate,
            })
        })
        .collect::<DriverResult<Prefs<_>>>()?;
    Ok(MountCaps { idmap })
}

/// The capabilities a driver stated, and the limits in force (the driver's,
/// never above what this build takes).  A word this build does not know is
/// ignored; a limit the driver does not state is what this build takes.
pub fn capabilities(driver: &str, info: &proto::Info) -> DriverResult<Capabilities> {
    let can = |w: &str| info.can(w);
    let verity = info
        .capabilities
        .iter()
        .filter_map(|w| match w.as_str() {
            word::VERITY_PULL_ONLY => Some(VerityEnforcement::PullOnly),
            word::VERITY_ON_OPEN => Some(VerityEnforcement::OnOpen),
            word::VERITY_KERNEL => Some(VerityEnforcement::Kernel),
            _ => None,
        })
        .collect::<Prefs<_>>();
    let stated = |name: &str, build: u64| info.limits.get(name).copied().unwrap_or(build);
    let l = crate::conn::clamp(&info.limits);
    if l.message < 4096 || l.fds < 1 || l.wants < 1 || l.ranges < 1 {
        return Err(DriverError::storage(
            driver,
            format!(
                "the limits the storage service states are too small to work with: max_message {}, max_fds {}, max_wants {}, max_ranges {}",
                stated("max_message", proto::MAX_MESSAGE as u64),
                stated("max_fds", proto::MAX_FDS as u64),
                stated("max_wants", proto::MAX_WANTS),
                stated("max_ranges", proto::MAX_RANGES),
            ),
        ));
    }
    Ok(Capabilities {
        // (the client does not serve images whose files are partly missing
        // yet: `remake_staged` is `Unsupported`, so a
        // lazy pull is refused up front, by name, whatever the driver says)
        lazy: false,
        serve_content: can(word::SERVE_CONTENT),
        rootless: can(word::ROOTLESS),
        verity,
        shared_stores: can(word::SHARED_STORES),
        layer_chain: can(word::LAYER_CHAIN),
        max_layers: info.limits.get("max_layers").map(|m| *m as usize),
        // (a store behind a socket has no path of the engine's to name the
        // upper directory of an overlay by: it hands the root over with
        // `Mounts` and `WritableRoot`)
        overlay_upper: false,
        writable_size_limit: can(word::SIZE_LIMIT),
        root: mount_caps(driver, info.mounts.root.clone())?,
        volume: info
            .mounts
            .volume
            .clone()
            .map(|v| mount_caps(driver, v))
            .transpose()?,
        limits: Limits {
            message: l.message as usize,
            fds: l.fds as usize,
            wants: l.wants as usize,
            ranges: l.ranges as usize,
        },
    })
}

// The other direction: what a server says of its driver's types, and what it
// reads of a request.

/// The wire error of a driver's error: the names of `DriverError::from_wire`.
/// The verdicts of the engine are never sent by a driver, so they are
/// `Failed` here; so are the errors of the driver's own I/O.
pub fn error_to_wire(e: &DriverError) -> proto::StorageError {
    use velarx_graph::DriverErrorKind as K;
    let reason = e.message().to_string();
    let wire_remedy = |r: velarx_graph::Remedy| match r {
        velarx_graph::Remedy::PullAgain => proto::Remedy::PullAgain,
        velarx_graph::Remedy::Repair => proto::Remedy::Repair,
        velarx_graph::Remedy::RecreateContainer => proto::Remedy::RecreateContainer,
    };
    match &e.kind {
        K::Missing { remedy } => proto::StorageError::Missing {
            reason,
            layer: e.layer.clone(),
            remedy: wire_remedy(*remedy),
        },
        K::Corrupt { remedy } => proto::StorageError::Corrupt {
            reason,
            layer: e.layer.clone(),
            remedy: wire_remedy(*remedy),
        },
        // (digests that are asked and cannot be checked: the engine's verdict
        // is its own to give, a driver says it cannot)
        K::Unsupported | K::DigestEnforced => proto::StorageError::Unsupported { reason },
        K::NotFound => proto::StorageError::NotFound { reason },
        K::Busy => proto::StorageError::Busy { reason },
        K::LabelRefused => proto::StorageError::LabelRefused { reason },
        K::Unavailable => proto::StorageError::Unavailable { reason },
        _ => proto::StorageError::Failed { reason },
    }
}

fn open_caps(c: &MountCaps) -> proto::MountCaps {
    proto::MountCaps {
        idmap: c
            .idmap
            .iter()
            .map(|w| {
                Open::Known(match w {
                    IdmapWay::MonitorMount => proto::IdmapWay::MonitorMount,
                    IdmapWay::DriverMount => proto::IdmapWay::DriverMount,
                    IdmapWay::AtCopy => proto::IdmapWay::AtCopy,
                    IdmapWay::Translate => proto::IdmapWay::Translate,
                })
            })
            .collect(),
    }
}

/// What `GetInfo` says of a driver: its words, its limits and its mounts.
pub fn info_to_wire(name: &str, version: &str, c: &Capabilities, objects: bool) -> proto::Info {
    let mut words = Vec::new();
    for (on, w) in [
        (c.serve_content, word::SERVE_CONTENT),
        (c.rootless, word::ROOTLESS),
        (c.shared_stores, word::SHARED_STORES),
        (c.layer_chain, word::LAYER_CHAIN),
        (c.writable_size_limit, word::SIZE_LIMIT),
        (objects, word::OBJECTS),
    ] {
        if on {
            words.push(w.to_string());
        }
    }
    words.extend(c.verity.iter().map(|v| {
        match v {
            VerityEnforcement::PullOnly => word::VERITY_PULL_ONLY,
            VerityEnforcement::OnOpen => word::VERITY_ON_OPEN,
            VerityEnforcement::Kernel => word::VERITY_KERNEL,
        }
        .to_string()
    }));
    let mut limits = limits_to_wire(&c.limits);
    if let Some(m) = c.max_layers {
        limits.insert("max_layers".to_string(), m as u64);
    }
    proto::Info {
        name: name.to_string(),
        version: version.to_string(),
        proto: proto::PROTO,
        capabilities: words,
        limits,
        mounts: proto::MountWays {
            root: open_caps(&c.root),
            volume: c.volume.as_ref().map(open_caps),
        },
    }
}

/// The limits a driver states.
pub fn limits_to_wire(l: &Limits) -> std::collections::BTreeMap<String, u64> {
    [
        ("max_message", l.message),
        ("max_fds", l.fds),
        ("max_wants", l.wants),
        ("max_ranges", l.ranges),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v as u64))
    .collect()
}

/// A mount as the wire says it.  `rel` is the path of a `directory` mount
/// relative to the work directory; `fd` the position of the descriptor of a
/// `mount_fd` in the reply that carries it.
pub fn mounted(
    driver: &str,
    plan: &RootfsPlan,
    idmap: IdmapDone,
    label: LabelDone,
    base: &Path,
    fd: Option<u32>,
) -> DriverResult<proto::Mounted> {
    let (kind, path) = match plan {
        RootfsPlan::Directory(d) => {
            let full = d.beneath.join(&d.path);
            let rel = full.strip_prefix(base).map_err(|_| {
                DriverError::storage(
                    driver,
                    format!(
                        "the root {} is not beneath the work directory {}",
                        full.display(),
                        base.display()
                    ),
                )
            })?;
            let rel = rel
                .to_str()
                .ok_or_else(|| DriverError::storage(driver, "the path of a root is not UTF-8"))?;
            (proto::MountKind::Directory, Some(rel.to_string()))
        }
        RootfsPlan::MountFd(_) => (proto::MountKind::MountFd, None),
    };
    Ok(proto::Mounted {
        kind: kind.into(),
        fd: if kind == proto::MountKind::MountFd {
            fd
        } else {
            None
        },
        path,
        idmap: match idmap {
            IdmapDone::None => proto::Idmap::None,
            IdmapDone::Applied => proto::Idmap::Applied,
            IdmapDone::Mount => proto::Idmap::Mount,
        }
        .into(),
        label: match label {
            LabelDone::None => proto::Label::None,
            LabelDone::MountContext => proto::Label::MountContext,
            LabelDone::Files => proto::Label::Files,
        }
        .into(),
    })
}

pub fn problem_to_wire(p: &Problem) -> proto::Problem {
    proto::Problem {
        // (the name of the kind on the wire, which is what the enum is)
        kind: Open::Unknown(p.kind.as_str().to_string()),
        message: p.message.clone(),
        layer: p.layer.as_ref().map(ToString::to_string),
        path: p.path.as_ref().map(|p| p.to_string_lossy().into_owned()),
        repair: p.repair,
    }
}

pub fn artifact_to_wire(key: &LayerKey, a: &LayerArtifact) -> proto::Artifact {
    let [uids, gids] = serde_json::from_str::<[Vec<u32>; 2]>(&a.owners).unwrap_or_default();
    proto::Artifact {
        key: key.to_string(),
        image_digest: a.image_digest.clone(),
        owners: proto::Owners { uids, gids },
    }
}

/// A layer a request names.
pub fn layer_ref(l: &proto::LayerRef) -> DriverResult<LayerRef> {
    let bad = |what: &str, v: &str| {
        DriverError::storage(
            "varlink",
            format!("the layer reference has {what} {v:?}, which is not one"),
        )
    };
    Ok(LayerRef {
        key: LayerKey::parse(&l.key).ok_or_else(|| bad("the key", &l.key))?,
        diff_id: l
            .diff_id
            .parse()
            .map_err(|_| bad("the diff id", &l.diff_id))?,
        chain_id: l
            .chain_id
            .parse()
            .map_err(|_| bad("the chain id", &l.chain_id))?,
    })
}

/// The user namespace of a request.
pub fn id_translate(m: &proto::Mapping) -> velarx_fuse::IdTranslate {
    let ids = |v: &[proto::IdMap]| {
        v.iter()
            .map(|i| velarx_proto::pod::IdMapping {
                container_id: i.container_id,
                host_id: i.host_id,
                size: i.size,
            })
            .collect()
    };
    velarx_fuse::IdTranslate {
        uid: ids(&m.uid),
        gid: ids(&m.gid),
        squash: m.squash,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> proto::Info {
        info_to_wire(
            "hostile",
            "1",
            &Capabilities {
                lazy: false,
                serve_content: false,
                rootless: true,
                verity: Prefs::new(&[VerityEnforcement::PullOnly]),
                shared_stores: false,
                layer_chain: false,
                max_layers: None,
                overlay_upper: false,
                writable_size_limit: false,
                root: MountCaps {
                    idmap: Prefs::new(&[IdmapWay::AtCopy]),
                },
                volume: None,
                limits: Limits::V1,
            },
            false,
        )
    }

    fn parse(c: &proto::Info) -> DriverResult<Capabilities> {
        capabilities("hostile", c)
    }

    /// A service that repeats its ways, more of them than a list holds:
    /// each is kept once, at its first place, in the order it said them.
    #[test]
    fn repeated_ways_from_a_service_are_kept_once_in_order() {
        use proto::IdmapWay as W;
        let mut c = base();
        c.capabilities = [
            "verity_kernel",
            "verity_kernel",
            "verity_pull_only",
            "verity_kernel",
            "verity_on_open",
            "verity_pull_only",
        ]
        .map(String::from)
        .into();
        let ways = [
            W::Translate,
            W::AtCopy,
            W::Translate,
            W::MonitorMount,
            W::AtCopy,
            W::DriverMount,
            W::MonitorMount,
            W::Translate,
        ];
        c.mounts.root.idmap = ways.map(Open::Known).into();
        c.mounts.volume = Some(proto::MountCaps {
            idmap: ways.map(Open::Known).into(),
        });
        let caps = parse(&c).unwrap();
        assert_eq!(
            caps.verity,
            Prefs::new(&[
                VerityEnforcement::Kernel,
                VerityEnforcement::PullOnly,
                VerityEnforcement::OnOpen
            ])
        );
        let all = Prefs::new(&[
            IdmapWay::Translate,
            IdmapWay::AtCopy,
            IdmapWay::MonitorMount,
            IdmapWay::DriverMount,
        ]);
        assert_eq!(caps.root.idmap, all);
        assert_eq!(caps.volume.map(|v| v.idmap), Some(all));
        // (and the engine says them back as it took them)
        let again = parse(&info_to_wire("hostile", "1", &caps, false)).unwrap();
        assert_eq!(again, caps);
    }

    /// A way to map the ids that this build does not know refuses the driver
    /// with an error that names it; a capability word or a limit it does not
    /// know is ignored.
    #[test]
    fn an_unknown_way_is_an_error_that_names_it() {
        fn unknown<E>() -> Open<E> {
            Open::Unknown("by_magic".to_string())
        }
        let mut c = base();
        c.capabilities.push("by_magic".into());
        c.limits.insert("max_magic".into(), 1);
        assert!(parse(&c).is_ok());
        let mut c = base();
        c.mounts.root.idmap.insert(0, unknown());
        let e = parse(&c).unwrap_err();
        assert_eq!(e.driver, "hostile");
        assert!(e.to_string().contains("\"by_magic\""), "{e}");
        let mut c = base();
        c.mounts.volume = Some(proto::MountCaps {
            idmap: vec![Open::Known(proto::IdmapWay::AtCopy), unknown()],
        });
        assert!(parse(&c).unwrap_err().to_string().contains("by_magic"));
    }
}
