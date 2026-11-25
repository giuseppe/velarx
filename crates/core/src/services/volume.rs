// SPDX-License-Identifier: Apache-2.0
//! Named volumes, and the parsing of `-v` and `--mount` into the mounts of a
//! container (the semantics are podman's: `libpod/runtime_volume_common.go`,
//! `pkg/specgen/volumes.go`).

use crate::container::{ImageMountConfig, MountConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, info, warn};
use velarx_db::Database;

#[derive(Error, Debug)]
pub enum VolumeError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("database error: {0}")]
    Database(String),
    #[error("volume not found: {0}")]
    NotFound(String),
    #[error("volume already exists: {0}")]
    AlreadyExists(String),
    #[error("volume in use: {0}")]
    InUse(String),
    #[error("invalid volume name: {0}")]
    InvalidName(String),
    #[error("{0}")]
    Parse(String),
    /// An option the driver refuses, in podman's words.
    #[error("{0}")]
    InvalidOption(String),
    #[error("{0}")]
    Ids(#[from] velarx_base::ids::IdsError),
}

pub type VolumeResult<T> = Result<T, VolumeError>;

/// The directory of the data of a volume in its own directory.
pub const VOLUME_DATA: &str = "_data";

/// Volume driver type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum VolumeDriver {
    /// Local filesystem volume
    #[default]
    Local,
    /// Named pipe or device
    Named,
    /// Custom driver
    Custom(String),
}

/// Volume mount options
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VolumeMountOptions {
    /// Read-only mount
    pub read_only: bool,
    /// SELinux relabeling option (z or Z)
    pub selinux_relabel: Option<SelinuxRelabel>,
    /// Bind propagation mode
    pub propagation: BindPropagation,
    /// No copy (don't copy contents from container)
    pub nocopy: bool,
    /// Overlay mount (lowerdir)
    pub overlay: bool,
    /// `upperdir=` and `workdir=` of an overlay volume: where its changes
    /// are kept (else they are discarded when the container stops)
    #[serde(default)]
    pub upperdir: Option<String>,
    #[serde(default)]
    pub workdir: Option<String>,
    /// `idmap` or `idmap=uids=A-B-C;gids=...`
    pub idmap: Option<String>,
    /// `U`: change the owner of the source to the user of the container
    #[serde(default)]
    pub chown: bool,
    /// Other options of the OCI mount that are kept as given (`nosuid`...)
    #[serde(default)]
    pub extra: Vec<String>,
    /// Only a directory of the volume or of the image
    #[serde(default)]
    pub subpath: Option<String>,
    /// `bind-nonrecursive`
    #[serde(default)]
    pub non_recursive: bool,
    /// Options of a tmpfs (`size=`, `mode=`...)
    #[serde(default)]
    pub tmpfs: Vec<String>,
    /// Read-write image mount
    #[serde(default)]
    pub image_rw: bool,
}

/// SELinux relabeling mode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SelinuxRelabel {
    /// Shared label (z) - multiple containers can share
    Shared,
    /// Private label (Z) - only this container
    Private,
}

/// Bind mount propagation mode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum BindPropagation {
    /// Private (default)
    Private,
    /// Rprivate (recursive private)
    #[default]
    Rprivate,
    /// Shared
    Shared,
    /// Rshared (recursive shared)
    Rshared,
    /// Slave
    Slave,
    /// Rslave (recursive slave)
    Rslave,
    /// Unbindable
    Unbindable,
    /// Runbindable (recursive unbindable)
    Runbindable,
}

impl BindPropagation {
    pub(crate) fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "private" => Self::Private,
            "rprivate" => Self::Rprivate,
            "shared" => Self::Shared,
            "rshared" => Self::Rshared,
            "slave" => Self::Slave,
            "rslave" => Self::Rslave,
            "unbindable" => Self::Unbindable,
            "runbindable" => Self::Runbindable,
            _ => return None,
        })
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Rprivate => "rprivate",
            Self::Shared => "shared",
            Self::Rshared => "rshared",
            Self::Slave => "slave",
            Self::Rslave => "rslave",
            Self::Unbindable => "unbindable",
            Self::Runbindable => "runbindable",
        }
    }
}

/// What a volume has still to get from its first container
/// (podman's `NeedsCopyUp` and `NeedsChown`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct VolumeState {
    /// The content of the image directory is copied in at the first use
    #[serde(default)]
    pub needs_copy_up: bool,
    /// The owner is set to the user of the first container
    #[serde(default)]
    pub needs_chown: bool,
    /// The content was copied in
    #[serde(default)]
    pub copied_up: bool,
    /// Created for a container (`-v /path`, or the `VOLUME` of its image)
    #[serde(default)]
    pub anonymous: bool,
    /// The container whose create made it (an anonymous volume of the
    /// engine's create): it goes with what a crash leaves of that container
    /// when no row names it (`ContainerService::sweep_unowned`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// The owner the volume was created with (`uid=` and `gid=`)
    #[serde(default)]
    pub uid: u32,
    #[serde(default)]
    pub gid: u32,
}

/// Named volume record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Volume {
    /// Unique name of the volume
    pub name: String,
    /// Volume driver
    pub driver: VolumeDriver,
    /// Path on host filesystem
    pub mountpoint: PathBuf,
    /// Volume labels
    pub labels: HashMap<String, String>,
    /// Volume options (driver-specific)
    pub options: HashMap<String, String>,
    /// Creation timestamp
    pub created_at: String,
    /// Scope (local or global for swarm)
    pub scope: String,
    #[serde(default)]
    pub state: VolumeState,
}

/// The file of a volume directory (next to `_data`) that says what the
/// directory alone does not: the directory is the volume, the row of the
/// database only a copy.  Its name is the directory's, its mount point
/// `_data`, its driver and scope `local`.
pub const VOLUME_META: &str = "volume.json";

/// What `volume.json` holds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VolumeMeta {
    pub labels: HashMap<String, String>,
    pub options: HashMap<String, String>,
    pub created_at: String,
    pub state: VolumeState,
}

impl VolumeMeta {
    pub fn of(volume: &Volume) -> Self {
        Self {
            labels: volume.labels.clone(),
            options: volume.options.clone(),
            created_at: volume.created_at.clone(),
            state: volume.state.clone(),
        }
    }

    /// The file of the volume directory `dir`.
    pub fn read(dir: &Path) -> io::Result<Self> {
        Ok(serde_json::from_slice(&fs::read(dir.join(VOLUME_META))?)?)
    }

    /// Replace the file of `dir`: a reader sees the old one or the new one.
    /// It is not synced, as the directory is not.
    pub fn write(&self, dir: &Path) -> io::Result<()> {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new_in(dir)?;
        file.write_all(&serde_json::to_vec(self)?)?;
        file.persist(dir.join(VOLUME_META))?;
        Ok(())
    }
}

/// A mount specification parsed from -v or --mount
#[derive(Debug, Clone)]
pub struct MountSpec {
    /// Mount type
    pub mount_type: MountType,
    /// Source (host path or volume name)
    pub source: Option<String>,
    /// Target path in container
    pub target: String,
    /// Mount options
    pub options: VolumeMountOptions,
}

/// Mount type
#[derive(Debug, Clone, PartialEq)]
pub enum MountType {
    /// Bind mount from host
    Bind,
    /// Named volume
    Volume,
    /// Tmpfs mount
    Tmpfs,
    /// Ramfs mount: memory that is never swapped and has no size limit
    Ramfs,
    /// Device mount
    Device,
    /// Image mount (mount from image layer)
    Image,
}

/// A volume name: what podman allows (`[a-zA-Z0-9][a-zA-Z0-9_.-]*`).
pub fn valid_volume_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && name.len() <= 255
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// The destination of a mount: absolute, cleaned, not the root.
pub fn clean_target(target: &str) -> VolumeResult<String> {
    if !target.starts_with('/') || target.contains('\0') {
        return Err(VolumeError::Parse(format!(
            "invalid container path `{target}`, it must be an absolute path"
        )));
    }
    let mut parts: Vec<&str> = Vec::new();
    for c in target.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    if parts.is_empty() {
        return Err(VolumeError::Parse(
            "a mount cannot replace the root of the container".into(),
        ));
    }
    Ok(format!("/{}", parts.join("/")))
}

/// A boolean option value: `--mount ...,ro`, `ro=true`, `ro=false`.
fn bool_value(key: &str, value: Option<&str>) -> VolumeResult<bool> {
    match value {
        None | Some("true") | Some("1") => Ok(true),
        Some("false") | Some("0") => Ok(false),
        Some(v) => Err(VolumeError::Parse(format!(
            "invalid value `{v}` for the mount option `{key}`"
        ))),
    }
}

/// OCI mount options that are passed to the runtime unchanged.
const PASSTHROUGH: &[&str] = &[
    "suid",
    "nosuid",
    "dev",
    "nodev",
    "exec",
    "noexec",
    "sync",
    "dirsync",
    "async",
    "atime",
    "noatime",
    "diratime",
    "nodiratime",
    "relatime",
    "norelatime",
    "strictatime",
    "nostrictatime",
    "symfollow",
    "nosymfollow",
    // every mount below a read-only bind mount is read-only too (the CRI's
    // `recursive_read_only`; needs the runtime and a kernel with
    // `mount_setattr`, and the runtime says if it has not)
    "rro",
];

/// Options of other tools that mean nothing here.
const IGNORED: &[&str] = &["delegated", "cached", "consistent", "default"];

impl MountSpec {
    /// A bind mount given as values: its source is a path whatever
    /// characters it has, its options are those of `-v`, one each.
    pub fn bind(source: &str, target: &str, options: &[String]) -> VolumeResult<Self> {
        let spec = MountSpec {
            mount_type: MountType::Bind,
            source: Some(source.to_string()),
            target: clean_target(target)?,
            options: Self::parse_option_list(options.iter().map(String::as_str))?,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Only the directory or file `subpath` of the source of a bind mount
    /// (a hostPath of kube play): the start looks it up inside the source
    /// again, so a link cannot lead out of it.  Not an option of `--mount`.
    pub fn in_subpath(mut self, subpath: &str) -> VolumeResult<Self> {
        self.options.subpath = Some(subpath.to_string());
        self.validate()?;
        Ok(self)
    }

    /// A mount of an image (or a directory of it) given as values.
    pub fn image(image: &str, target: &str, subpath: Option<&str>) -> VolumeResult<Self> {
        let spec = MountSpec {
            mount_type: MountType::Image,
            source: Some(image.to_string()),
            target: clean_target(target)?,
            options: VolumeMountOptions {
                subpath: subpath.filter(|s| !s.is_empty()).map(String::from),
                ..Default::default()
            },
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Parse a -v/--volume argument
    /// Formats:
    ///   - /host/path:/container/path[:options]
    ///   - volume_name:/container/path[:options]
    ///   - /container/path (anonymous volume)
    pub fn parse_volume_arg(arg: &str) -> VolumeResult<Self> {
        let parts: Vec<&str> = arg.split(':').collect();

        match parts.len() {
            1 => {
                // Anonymous volume: /container/path
                Ok(MountSpec {
                    mount_type: MountType::Volume,
                    source: None,
                    target: clean_target(parts[0])?,
                    options: VolumeMountOptions::default(),
                })
            }
            2 | 3 => {
                let source = parts[0];
                let target = clean_target(parts[1])?;
                let opts_str = parts.get(2).copied().unwrap_or("");

                let (mount_type, source) = if source.starts_with('/') {
                    // Host path bind mount
                    (MountType::Bind, source.to_string())
                } else if source.starts_with('.') || source.starts_with('~') {
                    // The daemon does not know where the client was.
                    return Err(VolumeError::Parse(format!(
                        "the source `{source}` is a relative path, use an absolute one"
                    )));
                } else if valid_volume_name(source) {
                    (MountType::Volume, source.to_string())
                } else {
                    return Err(VolumeError::InvalidName(source.to_string()));
                };

                let options = Self::parse_options(opts_str)?;

                let spec = MountSpec {
                    mount_type,
                    source: Some(source),
                    target,
                    options,
                };
                spec.validate()?;
                Ok(spec)
            }
            _ => Err(VolumeError::Parse(format!("Invalid volume spec: {}", arg))),
        }
    }

    /// Parse a --mount argument
    /// Format: type=bind,source=/src,target=/dst,readonly,bind-propagation=shared
    pub fn parse_mount_arg(arg: &str) -> VolumeResult<Self> {
        let mut mount_type = MountType::Bind;
        let mut source = None;
        let mut target = None;
        let mut options = VolumeMountOptions::default();
        // (the options of a tmpfs, for the words of a ramfs that has one)
        let mut memory_option = None;
        let mut devpts_option = None;

        for part in arg.split(',').filter(|p| !p.is_empty()) {
            let (key, value) = match part.split_once('=') {
                Some((k, v)) => (k, Some(v)),
                None => (part, None),
            };

            match key {
                "type" => {
                    mount_type = match value {
                        Some("bind") => MountType::Bind,
                        Some("volume") => MountType::Volume,
                        Some("tmpfs") => MountType::Tmpfs,
                        Some("ramfs") => MountType::Ramfs,
                        Some("devpts") => MountType::Device,
                        Some("image") => MountType::Image,
                        Some(t) => {
                            return Err(VolumeError::Parse(format!("Unknown mount type: {}", t)))
                        }
                        None => MountType::Bind,
                    };
                }
                "source" | "src" => {
                    source = value.map(String::from);
                }
                "target" | "dst" | "destination" => {
                    target = value.map(String::from);
                }
                "readonly" | "ro" => {
                    options.read_only = bool_value(key, value)?;
                    // For an image, `rw` is a separate option.
                }
                "rw" | "readwrite" => {
                    let rw = bool_value(key, value)?;
                    options.read_only = !rw;
                    options.image_rw = rw;
                }
                "bind-propagation" => {
                    options.propagation =
                        value.and_then(BindPropagation::parse).ok_or_else(|| {
                            VolumeError::Parse(format!(
                                "invalid bind-propagation `{}`",
                                value.unwrap_or("")
                            ))
                        })?;
                }
                "bind-nonrecursive" => {
                    options.non_recursive = bool_value(key, value)?;
                }
                "relabel" => {
                    options.selinux_relabel = match value {
                        Some("shared") | Some("z") => Some(SelinuxRelabel::Shared),
                        Some("private") | Some("Z") => Some(SelinuxRelabel::Private),
                        v => {
                            return Err(VolumeError::Parse(format!(
                                "invalid relabel `{}`: shared or private",
                                v.unwrap_or("")
                            )))
                        }
                    };
                }
                "noswap" => {
                    if velarx_base::conf::rootless()? {
                        return Err(VolumeError::Parse(
                            "the 'noswap' option is only allowed with rootful tmpfs mounts: must provide an argument for option"
                                .into(),
                        ));
                    }
                    options.extra.push("noswap".into());
                }
                "z" => options.selinux_relabel = Some(SelinuxRelabel::Shared),
                "Z" => options.selinux_relabel = Some(SelinuxRelabel::Private),
                "nocopy" | "volume-nocopy" => {
                    options.nocopy = bool_value(key, value)?;
                }
                "copy" => {
                    options.nocopy = !bool_value(key, value)?;
                }
                "U" | "chown" => {
                    options.chown = bool_value(key, value)?;
                }
                "idmap" => {
                    options.idmap = Some(match value {
                        Some(v) => format!("idmap={v}"),
                        None => "idmap".to_string(),
                    });
                }
                "subpath" => {
                    options.subpath = value.map(String::from);
                }
                "tmpfs-size" | "size" => {
                    let v = value.ok_or_else(|| VolumeError::Parse("size needs a value".into()))?;
                    options.tmpfs.push(format!("size={v}"));
                    memory_option.get_or_insert(key);
                }
                "tmpfs-mode" | "mode" => {
                    let v = value.ok_or_else(|| VolumeError::Parse("mode needs a value".into()))?;
                    options.tmpfs.push(format!("mode={v}"));
                    memory_option.get_or_insert(key);
                }
                "uid" | "gid" | "ptmxmode" | "newinstance" | "max" => {
                    devpts_option.get_or_insert(key);
                    options.extra.push(match value {
                        Some(v) => format!("{key}={v}"),
                        None => key.to_string(),
                    });
                }
                "no-dereference" => {
                    if bool_value(key, value)? {
                        options.extra.push("copy-symlink".into());
                    }
                }
                k if PASSTHROUGH.contains(&k) => options.extra.push(k.to_string()),
                k if IGNORED.contains(&k) => {}
                _ => {
                    return Err(VolumeError::Parse(format!("invalid mount option `{key}`")));
                }
            }
        }

        if let Some(key) = devpts_option.filter(|_| mount_type != MountType::Device) {
            return Err(VolumeError::Parse(format!("invalid mount option `{key}`")));
        }
        // (a devpts mount takes its options and a destination only, as
        // podman's getDevptsMount: `ro`, a source... are refused)
        if mount_type == MountType::Device {
            for part in arg.split(',').filter(|p| !p.is_empty()) {
                let key = part.split_once('=').map_or(part, |(k, _)| k);
                if !matches!(
                    key,
                    "type"
                        | "target"
                        | "dst"
                        | "destination"
                        | "uid"
                        | "gid"
                        | "mode"
                        | "ptmxmode"
                        | "newinstance"
                        | "max"
                ) {
                    return Err(VolumeError::Parse(format!(
                        "invalid mount option `{key}` for a devpts mount"
                    )));
                }
            }
        }
        // (podman's words)
        if let Some(key) = memory_option.filter(|_| mount_type == MountType::Ramfs) {
            return Err(VolumeError::Parse(format!(
                "{key:?} option not supported for \"ramfs\" mount types"
            )));
        }
        if mount_type != MountType::Tmpfs && options.extra.iter().any(|e| e == "noswap") {
            return Err(VolumeError::Parse(
                "the 'noswap' option is only allowed with tmpfs mounts: invalid mount option"
                    .into(),
            ));
        }
        // (the sub path of a bind mount is kube play's, not an option)
        if mount_type == MountType::Bind && options.subpath.is_some() {
            return Err(VolumeError::Parse(
                "subpath is for volumes and images".into(),
            ));
        }
        let target = clean_target(
            &target.ok_or_else(|| VolumeError::Parse("must set volume destination".to_string()))?,
        )?;
        let spec = MountSpec {
            mount_type,
            source,
            target,
            options,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// `--tmpfs /path[:options]`
    pub fn parse_tmpfs_arg(arg: &str) -> VolumeResult<Self> {
        let (target, opts) = arg.split_once(':').unwrap_or((arg, ""));
        let mut options = VolumeMountOptions::default();
        for o in opts.split(',').filter(|o| !o.is_empty()) {
            match o {
                "ro" => options.read_only = true,
                "rw" => options.read_only = false,
                "U" => options.chown = true,
                o if PASSTHROUGH.contains(&o) => options.extra.push(o.to_string()),
                o => options.tmpfs.push(o.to_string()),
            }
        }
        Ok(MountSpec {
            mount_type: MountType::Tmpfs,
            source: None,
            target: clean_target(target)?,
            options,
        })
    }

    /// Checks that depend on the type.
    fn validate(&self) -> VolumeResult<()> {
        let o = &self.options;
        match self.mount_type {
            MountType::Bind => {
                if self.source.as_deref().is_none_or(|s| !s.starts_with('/')) {
                    return Err(VolumeError::Parse(
                        "a bind mount needs an absolute source path".into(),
                    ));
                }
            }
            MountType::Volume => {
                if let Some(s) = &self.source {
                    if !valid_volume_name(s) {
                        return Err(VolumeError::InvalidName(s.clone()));
                    }
                }
            }
            MountType::Image => {
                if self.source.as_deref().is_none_or(str::is_empty) {
                    return Err(VolumeError::Parse("an image mount needs a source".into()));
                }
            }
            MountType::Tmpfs | MountType::Ramfs | MountType::Device => {}
        }
        if o.extra.iter().any(|e| e == "rro") {
            if !matches!(self.mount_type, MountType::Bind | MountType::Volume) {
                return Err(VolumeError::Parse(
                    "`rro` (recursive read-only) is for bind mounts".into(),
                ));
            }
            if !o.read_only || o.non_recursive {
                return Err(VolumeError::Parse(
                    "`rro` (recursive read-only) needs a read-only recursive bind mount".into(),
                ));
            }
        }
        if o.overlay && !matches!(self.mount_type, MountType::Bind | MountType::Volume) {
            return Err(VolumeError::Parse(
                "overlay volumes (`O`) are for host directories and named volumes".into(),
            ));
        }
        if o.overlay && self.source.is_none() {
            return Err(VolumeError::Parse(
                "an overlay volume (`O`) needs a source".into(),
            ));
        }
        if o.overlay && o.subpath.is_some() {
            return Err(VolumeError::Parse(
                "an overlay volume (`O`) takes no subpath".into(),
            ));
        }
        if o.subpath.is_some()
            && !matches!(
                self.mount_type,
                MountType::Volume | MountType::Image | MountType::Bind
            )
        {
            return Err(VolumeError::Parse(
                "subpath is for volumes and images".into(),
            ));
        }
        if o.subpath.is_some() && o.chown && self.mount_type == MountType::Bind {
            return Err(VolumeError::Parse(
                "the `U` option is not supported with the subpath of a bind mount".into(),
            ));
        }
        if o.chown && o.idmap.is_some() {
            return Err(VolumeError::Parse(
                "the `U` and `idmap` options cannot be used together: the ids would be mapped twice"
                    .into(),
            ));
        }
        if o.idmap.is_some()
            && matches!(
                self.mount_type,
                MountType::Tmpfs | MountType::Ramfs | MountType::Device
            )
        {
            return Err(VolumeError::Parse(
                "the idmap option is for bind mounts and volumes".into(),
            ));
        }
        // (podman's words: those of its tmpfs, and of an option it does not
        // know for an image)
        match (&self.mount_type, &o.selinux_relabel) {
            (MountType::Tmpfs, Some(_)) => {
                return Err(VolumeError::Parse(
                    "the 'z' and 'Z' options are not allowed with tmpfs mounts: invalid mount \
                     option"
                        .into(),
                ))
            }
            (MountType::Image, Some(r)) => {
                let letter = if *r == SelinuxRelabel::Shared {
                    'z'
                } else {
                    'Z'
                };
                return Err(VolumeError::Parse(format!(
                    "{letter}: invalid mount option"
                )));
            }
            (MountType::Ramfs, Some(_)) => {
                return Err(VolumeError::Parse(
                    "the SELinux relabeling is for bind mounts and volumes".into(),
                ))
            }
            _ => {}
        }
        if let Some(sub) = &o.subpath {
            check_subpath(sub)?;
        }
        Ok(())
    }

    /// Parse mount options string (e.g., "ro,z,rslave")
    fn parse_options(opts_str: &str) -> VolumeResult<VolumeMountOptions> {
        Self::parse_option_list(opts_str.split(','))
    }

    /// The options of a mount, one each.
    fn parse_option_list<'a>(
        opts: impl Iterator<Item = &'a str>,
    ) -> VolumeResult<VolumeMountOptions> {
        let mut options = VolumeMountOptions::default();
        let mut recursion_given = false;
        for opt in opts.filter(|o| !o.is_empty()) {
            // Case-sensitive options: z, Z for SELinux, O for overlay, U for chown
            match opt {
                "z" => {
                    options.selinux_relabel = Some(SelinuxRelabel::Shared);
                    continue;
                }
                "Z" => {
                    options.selinux_relabel = Some(SelinuxRelabel::Private);
                    continue;
                }
                "O" => {
                    options.overlay = true;
                    continue;
                }
                o if o.starts_with("upperdir=") => {
                    options.upperdir = Some(o["upperdir=".len()..].to_string());
                    continue;
                }
                o if o.starts_with("workdir=") => {
                    options.workdir = Some(o["workdir=".len()..].to_string());
                    continue;
                }
                "U" => {
                    options.chown = true;
                    continue;
                }
                "idmap" => {
                    options.idmap = Some("idmap".into());
                    continue;
                }
                o if o.starts_with("idmap=") => {
                    options.idmap = Some(o.to_string());
                    continue;
                }
                "no-dereference" => {
                    options.extra.push("copy-symlink".into());
                    continue;
                }
                _ => {}
            }
            // Other options are case-insensitive
            let lower = opt.to_lowercase();
            match lower.as_str() {
                "ro" | "readonly" => options.read_only = true,
                "rw" => options.read_only = false,
                "nocopy" => options.nocopy = true,
                "copy" => options.nocopy = false,
                // (as podman: a bind mount is recursive unless `bind` says
                // it is not, and only one of the two is given)
                "bind" | "rbind" if std::mem::replace(&mut recursion_given, true) => {
                    return Err(VolumeError::Parse(
                        "only one of 'rbind' and 'bind' can be used".into(),
                    ))
                }
                "bind" => options.non_recursive = true,
                "rbind" => options.non_recursive = false,
                o if BindPropagation::parse(o).is_some() => {
                    options.propagation = BindPropagation::parse(o).unwrap_or_default()
                }
                o if PASSTHROUGH.contains(&o) => options.extra.push(o.to_string()),
                o if IGNORED.contains(&o) => {}
                _ => return Err(VolumeError::Parse(format!("invalid mount option `{opt}`"))),
            }
        }

        if (options.upperdir.is_some() || options.workdir.is_some()) && !options.overlay {
            return Err(VolumeError::Parse(
                "upperdir and workdir are options of overlay volumes (`O`)".into(),
            ));
        }
        if options.upperdir.is_some() != options.workdir.is_some() {
            return Err(VolumeError::Parse(
                "upperdir and workdir of an overlay volume go together".into(),
            ));
        }
        for d in [&options.upperdir, &options.workdir].into_iter().flatten() {
            if !d.starts_with('/') || d.contains(':') {
                return Err(VolumeError::Parse(format!(
                    "the upperdir and workdir of an overlay volume are absolute paths: `{d}`"
                )));
            }
        }
        if options.overlay
            && (options.selinux_relabel.is_some() || options.chown || options.idmap.is_some())
        {
            // the files of an overlay show the container's label, and its
            // lower layer is not changed
            return Err(VolumeError::Parse(
                "an overlay volume (`O`) takes none of z, Z, U and idmap".into(),
            ));
        }
        Ok(options)
    }

    /// The OCI mount and the engine's own options for it.
    pub fn to_mount_config(&self, volumes_dir: &Path) -> VolumeResult<MountConfig> {
        let oci = self.to_oci_mount(volumes_dir)?;
        let named = match (&self.mount_type, &self.source) {
            (MountType::Volume, Some(name)) => Some(name.clone()),
            _ => None,
        };
        let image = (self.mount_type == MountType::Image).then(|| ImageMountConfig {
            image: self.source.clone().unwrap_or_default(),
            subpath: self.options.subpath.clone(),
            rw: self.options.image_rw,
            digest: None,
        });
        let o = &self.options;
        Ok(MountConfig {
            source: if image.is_some() {
                String::new()
            } else {
                oci.source
            },
            target: oci.destination,
            mount_type: Some(oci.mount_type),
            options: oci.options,
            volume: named,
            subpath: if image.is_some() {
                None
            } else {
                o.subpath.clone()
            },
            image,
            chown: o.chown,
            nocopy: o.nocopy,
            relabel: o.selinux_relabel.as_ref().map(|r| {
                match r {
                    SelinuxRelabel::Shared => "z",
                    SelinuxRelabel::Private => "Z",
                }
                .to_string()
            }),
            idmap: o.idmap.clone(),
            uid_mappings: Vec::new(),
            gid_mappings: Vec::new(),
            overlay: o.overlay.then(|| crate::container::OverlayMountConfig {
                upperdir: o.upperdir.clone(),
                workdir: o.workdir.clone(),
                ..Default::default()
            }),
            subpath_root: None,
            secret_owner: None,
            engine: false,
        })
    }

    /// Convert to OCI mount specification
    pub fn to_oci_mount(&self, volumes_dir: &Path) -> VolumeResult<OciMount> {
        let source = match (&self.mount_type, &self.source) {
            (MountType::Bind, Some(src)) => src.clone(),
            (MountType::Volume, Some(name)) => volumes_dir.join(name).to_string_lossy().to_string(),
            (MountType::Volume, None) => String::new(),
            (MountType::Tmpfs, _) => "tmpfs".to_string(),
            (MountType::Ramfs, _) => "ramfs".to_string(),
            (MountType::Device, Some(src)) => src.clone(),
            (MountType::Device, None) => "devpts".to_string(),
            (MountType::Image, Some(src)) => src.clone(),
            _ => return Err(VolumeError::Parse("Invalid mount source".to_string())),
        };

        let mount_type = match self.mount_type {
            MountType::Bind | MountType::Volume => "bind",
            MountType::Tmpfs => "tmpfs",
            MountType::Ramfs => "ramfs",
            MountType::Device => "devpts",
            MountType::Image => "bind",
        };

        let mut options = Vec::new();

        if self.mount_type == MountType::Tmpfs {
            options.push(if self.options.read_only { "ro" } else { "rw" }.to_string());
            let given = || self.options.extra.iter().chain(&self.options.tmpfs);
            // The defaults of podman for a tmpfs: it starts with what the
            // image has there.
            for (d, opposite) in [
                ("nosuid", "suid"),
                ("nodev", "dev"),
                ("tmpcopyup", "notmpcopyup"),
            ] {
                if !given().any(|e| e == d || e == opposite) {
                    options.push(d.to_string());
                }
            }
            // (`notmpcopyup` is no option of the runtime: it only drops
            // that copy)
            options.extend(given().filter(|e| *e != "notmpcopyup").cloned());
            return Ok(OciMount {
                destination: self.target.clone(),
                source,
                mount_type: mount_type.to_string(),
                options,
            });
        }

        // a devpts mount has the options it is given (uid, gid, mode,
        // ptmxmode, newinstance, max), as podman's
        if self.mount_type == MountType::Device {
            options.extend(self.options.tmpfs.iter().cloned());
            options.extend(self.options.extra.iter().cloned());
            return Ok(OciMount {
                destination: self.target.clone(),
                source,
                mount_type: mount_type.to_string(),
                options,
            });
        }

        if self.mount_type == MountType::Ramfs {
            options.push(if self.options.read_only { "ro" } else { "rw" }.to_string());
            options.extend(self.options.extra.iter().cloned());
            return Ok(OciMount {
                destination: self.target.clone(),
                source,
                mount_type: mount_type.to_string(),
                options,
            });
        }

        if matches!(
            self.mount_type,
            MountType::Bind | MountType::Volume | MountType::Image
        ) {
            options.push(
                if self.options.non_recursive {
                    "bind"
                } else {
                    "rbind"
                }
                .to_string(),
            );
        }

        if self.options.read_only || self.mount_type == MountType::Image && !self.options.image_rw {
            options.push("ro".to_string());
        } else {
            options.push("rw".to_string());
        }

        options.push(self.options.propagation.as_str().to_string());
        // A volume is mounted nosuid and nodev unless the options say suid
        // or dev, as podman's (a bind mount keeps what its host file system
        // has)
        if self.mount_type == MountType::Volume {
            for (d, opposite) in [("nosuid", "suid"), ("nodev", "dev")] {
                if !self.options.extra.iter().any(|e| e == d || e == opposite) {
                    options.push(d.to_string());
                }
            }
        }
        // An image mount is nodev unless the options say dev: a device node
        // of an image is not to open (the runtime clears the flags the
        // monitor mounted it with, unless the spec says them)
        if self.mount_type == MountType::Image
            && !self
                .options
                .extra
                .iter()
                .any(|e| e == "nodev" || e == "dev")
        {
            options.push("nodev".to_string());
        }
        options.extend(self.options.extra.iter().cloned());

        Ok(OciMount {
            destination: self.target.clone(),
            source,
            mount_type: mount_type.to_string(),
            options,
        })
    }
}

/// A sub path is relative and stays inside: no `..`, no NUL.
pub fn check_subpath(sub: &str) -> VolumeResult<()> {
    let bad = sub.is_empty() || sub.contains('\0') || sub.split('/').any(|c| c == "..");
    if bad {
        return Err(VolumeError::Parse(format!("invalid subpath `{sub}`")));
    }
    Ok(())
}

/// OCI mount specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciMount {
    pub destination: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub source: String,
    #[serde(rename = "type")]
    pub mount_type: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub options: Vec<String>,
}

/// What a volume created through the local driver asks to be mounted.
#[derive(Debug, PartialEq, Eq)]
pub struct VolumeMount {
    pub fstype: String,
    pub device: String,
    pub flags: Vec<String>,
    pub data: String,
}

/// The options of the local driver that podman accepts.
const LOCAL_OPTIONS: &[&str] = &[
    "type", "device", "o", "uid", "gid", "size", "inodes", "noquota", "copy", "nocopy",
];

/// The owner of a local volume: the `uid`/`gid` options, or `uid=`/`gid=`
/// in its `o` option (podman takes both).
pub fn local_volume_owner(options: &HashMap<String, String>, key: &str) -> Option<u32> {
    let get = |k: &str| {
        options
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(k))
            .map(|(_, v)| v.as_str())
    };
    get(key).and_then(|v| v.parse().ok()).or_else(|| {
        get("o")?
            .split(',')
            .find_map(|o| o.strip_prefix(key)?.strip_prefix('='))
            .and_then(|v| v.parse().ok())
    })
}

/// Check the options of a local volume and what mounting it takes: `None` for
/// a plain directory.
pub fn local_volume_mount(options: &HashMap<String, String>) -> VolumeResult<Option<VolumeMount>> {
    for k in options.keys() {
        if !LOCAL_OPTIONS.contains(&k.to_lowercase().as_str()) {
            return Err(VolumeError::Parse(format!(
                "invalid mount option {k} for driver 'local'"
            )));
        }
    }
    let get = |k: &str| {
        options
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(k))
            .map(|(_, v)| v.as_str())
    };
    for k in ["uid", "gid"] {
        if let Some(v) = get(k) {
            v.parse::<u32>()
                .map_err(|_| VolumeError::Parse(format!("invalid {k} `{v}`")))?;
        }
    }
    // uid= and gid= in `o` are the owner of the volume, not mount options.
    let mount_opts: Vec<&str> = get("o")
        .unwrap_or("")
        .split(',')
        .filter(|o| !o.is_empty())
        .filter(|o| {
            let Some((k, v)) = o.split_once('=') else {
                return true;
            };
            !(matches!(k, "uid" | "gid") && v.parse::<u32>().is_ok())
        })
        .collect();
    for o in get("o").unwrap_or("").split(',') {
        if let Some((k @ ("uid" | "gid"), v)) = o.split_once('=') {
            v.parse::<u32>()
                .map_err(|_| VolumeError::Parse(format!("invalid {k} `{v}`")))?;
        }
    }
    let fstype = get("type").unwrap_or("");
    let device = get("device").unwrap_or("");
    let size = get("size");
    if (size.is_some() || get("inodes").is_some()) && fstype != "tmpfs" {
        return Err(VolumeError::Parse(
            "volume options size and inodes need a tmpfs volume: quotas are not supported".into(),
        ));
    }
    if fstype.is_empty() && device.is_empty() && mount_opts.is_empty() {
        return Ok(None);
    }
    let mut flags = Vec::new();
    let mut data = Vec::new();
    // A mounted file system gets them too (the owner of a tmpfs root).
    for o in get("o").unwrap_or("").split(',').filter(|o| !o.is_empty()) {
        match o {
            "ro" | "rw" | "nosuid" | "suid" | "nodev" | "dev" | "noexec" | "exec" | "noatime"
            | "relatime" | "sync" | "dirsync" | "bind" | "rbind" => flags.push(o.to_string()),
            // Everything else is for the file system.
            _ => data.push(o.to_string()),
        }
    }
    if let Some(s) = size {
        data.push(format!("size={s}"));
    }
    let bind = flags.iter().any(|f| f == "bind" || f == "rbind") || fstype == "bind";
    if fstype.is_empty() && !bind {
        return Err(VolumeError::Parse(
            "a volume with mount options needs a type, or the bind option".into(),
        ));
    }
    if fstype != "tmpfs" && device.is_empty() {
        return Err(VolumeError::Parse(
            "a volume that is not a tmpfs needs a device".into(),
        ));
    }
    if bind && !device.starts_with('/') {
        return Err(VolumeError::Parse(
            "the device of a bind volume is an absolute path".into(),
        ));
    }
    Ok(Some(VolumeMount {
        fstype: if bind {
            "bind".into()
        } else {
            fstype.to_string()
        },
        device: if device.is_empty() {
            "tmpfs".into()
        } else {
            device.to_string()
        },
        flags,
        data: data.join(","),
    }))
}

/// Whether `path` is a mount point of this process.  A path that is not
/// there is not one; any other failure of the lookup is an error, for the
/// caller to refuse what it was about to do (never "not mounted").
pub fn is_mount_point(path: &Path) -> io::Result<bool> {
    match velarx_sys::statmount::is_mount_point(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        r => r,
    }
}

/// Volume service for managing named volumes
pub struct VolumeService {
    db: Database,
    volumes_dir: PathBuf,
    /// `<root>/volumes.lock`: held shared by whoever changes a volume
    /// directory or a row and by a container create while it names
    /// volumes, exclusive by `rename` and by the check, after the lock of
    /// the store when both are taken
    lock: PathBuf,
}

/// What to create.
#[derive(Debug, Default, Clone)]
pub struct CreateVolume {
    pub name: Option<String>,
    pub labels: HashMap<String, String>,
    pub options: HashMap<String, String>,
    /// For a container: removed with it
    pub anonymous: bool,
    /// The container whose create makes it
    pub container: Option<String>,
}

/// Move the directory `from` to `to`, which must not be there.
fn move_into_place(from: &Path, to: &Path, name: &str) -> VolumeResult<()> {
    use rustix::fs::{renameat_with, RenameFlags, CWD};
    renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE).map_err(|e| match e {
        rustix::io::Errno::EXIST | rustix::io::Errno::NOTEMPTY => {
            VolumeError::AlreadyExists(name.to_string())
        }
        e => io::Error::from(e).into(),
    })
}

/// Remove the directory of a volume nothing was put into: `volume.json`,
/// the empty `_data`, itself.  Never a tree.
fn discard(dir: &Path) {
    let _ = fs::remove_file(dir.join(VOLUME_META));
    let _ = fs::remove_dir(dir.join(VOLUME_DATA));
    let _ = fs::remove_dir(dir);
}

fn random_name() -> String {
    format!(
        "{}{}",
        velarx_base::random::token(),
        velarx_base::random::token()
    )
}

impl VolumeService {
    /// The directory of the volumes the service made.
    pub fn volumes_dir(&self) -> &Path {
        &self.volumes_dir
    }

    pub fn new(db: Database, volumes_dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&volumes_dir).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "cannot create the volumes directory {}: {e}",
                    volumes_dir.display()
                ),
            )
        })?;

        let lock = volumes_dir
            .parent()
            .unwrap_or(&volumes_dir)
            .join("volumes.lock");
        Ok(Self {
            db,
            volumes_dir,
            lock,
        })
    }

    /// The lock file of the volumes.
    pub fn lock_path(&self) -> &Path {
        &self.lock
    }

    /// Hold the lock shared: a change of a volume is not seen half done.
    /// (`remove` and `prune` hold it shared too, so a create may still name
    /// a volume that is being removed: the user asked for the removal, and
    /// an exclusive hold would stall every create while a tree is deleted)
    pub(crate) async fn changing(&self) -> VolumeResult<velarx_storage::StorageLock> {
        Ok(velarx_storage::StorageLock::shared(&self.lock).await?)
    }

    /// Create a new named volume
    pub async fn create(
        &self,
        name: &str,
        driver: VolumeDriver,
        labels: HashMap<String, String>,
        options: HashMap<String, String>,
    ) -> VolumeResult<Volume> {
        if driver != VolumeDriver::Local {
            return Err(VolumeError::Parse(
                "only the local volume driver is supported".into(),
            ));
        }
        self.create_with(CreateVolume {
            name: Some(name.to_string()),
            labels,
            options,
            anonymous: false,
            container: None,
        })
        .await
    }

    pub async fn create_with(&self, c: CreateVolume) -> VolumeResult<Volume> {
        let name = match c.name {
            Some(n) => n,
            None => random_name(),
        };
        if !valid_volume_name(&name) {
            return Err(VolumeError::InvalidName(name));
        }
        let _lock = self.changing().await?;
        if let Some(m) = local_volume_mount(&c.options)? {
            // podman checks that what a bind volume binds is there
            if m.fstype == "bind" {
                if let Err(e) = rustix::fs::access(m.device.as_str(), rustix::fs::Access::EXISTS) {
                    let why = if e == rustix::io::Errno::NOENT {
                        "no such file or directory".to_string()
                    } else {
                        e.to_string()
                    };
                    return Err(VolumeError::InvalidOption(format!(
                        "invalid volume option device for driver 'local': faccessat {}: {why}",
                        m.device
                    )));
                }
            }
        }

        let (uid, gid) = (
            local_volume_owner(&c.options, "uid"),
            local_volume_owner(&c.options, "gid"),
        );

        // The data of the volume is in `_data` of its directory, as
        // podman's; the directory is the daemon's only.  The volume is
        // built under a name no volume has and moves into place whole, so
        // a directory is a volume or is not there.
        let dir = self.volumes_dir.join(&name);
        let mountpoint = dir.join(VOLUME_DATA);
        let volume = Volume {
            name: name.clone(),
            driver: VolumeDriver::Local,
            mountpoint,
            labels: c.labels,
            options: c.options,
            created_at: chrono::Utc::now().to_rfc3339(),
            scope: "local".to_string(),
            state: VolumeState {
                needs_copy_up: true,
                // An owner given at creation is the owner: the first
                // container does not change it.
                needs_chown: uid.is_none() && gid.is_none(),
                copied_up: false,
                anonymous: c.anonymous,
                container: c.container,
                uid: uid.unwrap_or(0),
                gid: gid.unwrap_or(0),
            },
        };
        let building = self.volumes_dir.join(format!(".new-{}", random_name()));
        let build = || -> VolumeResult<()> {
            fs::create_dir(&building)?;
            fs::set_permissions(&building, fs::Permissions::from_mode(0o700))?;
            let data = building.join(VOLUME_DATA);
            fs::create_dir(&data)?;
            fs::set_permissions(&data, fs::Permissions::from_mode(0o755))?;
            if uid.is_some() || gid.is_some() {
                std::os::unix::fs::chown(&data, uid, gid)?;
            }
            // what every container can use: the file type at the level s0
            if crate::container::selinux::enabled() {
                use crate::container::selinux;
                let c = selinux::Contexts::host();
                let label = format!("{}:{}:{}:s0", c.file_user, c.file_role, c.file_type);
                selinux::relabel_path(&data, &label, &[])?;
            }
            VolumeMeta::of(&volume).write(&building)?;
            Ok(())
        };
        let placed = build().and_then(|()| move_into_place(&building, &dir, &name));
        if let Err(e) = placed {
            discard(&building);
            return Err(e);
        }
        if let Err(e) = self.store_volume(&volume).await {
            discard(&dir);
            return Err(e);
        }

        info!("Created volume: {}", name);
        Ok(volume)
    }

    /// Get a volume by name
    pub async fn get(&self, name: &str) -> VolumeResult<Volume> {
        let name_clone = name.to_string();
        self.db
            .conn()
            .call(move |conn| velarx_db::volumes::get(conn, &name_clone))
            .await
            .map(Volume::from)
            .map_err(|e| match e {
                tokio_rusqlite::Error::Rusqlite(rusqlite::Error::QueryReturnedNoRows) => {
                    VolumeError::NotFound(name.to_string())
                }
                // (a database that cannot be read, or a row that cannot be
                // decoded, is not a volume that is not there)
                e => VolumeError::Database(e.to_string()),
            })
    }

    /// List all volumes
    pub async fn list(&self) -> VolumeResult<Vec<Volume>> {
        self.db
            .conn()
            .call(velarx_db::volumes::list)
            .await
            .map(|rows| rows.into_iter().map(Volume::from).collect())
            .map_err(|e| VolumeError::Database(e.to_string()))
    }

    /// Remove a volume
    pub async fn remove(&self, name: &str, force: bool) -> VolumeResult<()> {
        let _lock = self.changing().await?;
        let volume = self.get(name).await?;

        if !force {
            let in_use = self.is_volume_in_use(name).await?;
            if in_use {
                return Err(VolumeError::InUse(name.to_string()));
            }
        }

        // The data of a volume that is a mount is not ours to delete.
        self.unmount_path(&volume.mountpoint)?;
        match is_mount_point(&volume.mountpoint) {
            Ok(false) => {}
            Ok(true) => {
                return Err(VolumeError::InUse(format!(
                    "{name}: still mounted at {}",
                    volume.mountpoint.display()
                )))
            }
            Err(e) => {
                return Err(VolumeError::InUse(format!(
                    "{name}: cannot tell whether it is mounted at {}: {e}",
                    volume.mountpoint.display()
                )))
            }
        }

        // Remove the volume directory (the one of `_data` too), its data
        // off the async threads
        let dirs: Vec<_> = std::iter::once(volume.mountpoint.clone())
            .chain(self.own_dir(&volume))
            .collect();
        crate::off_thread(move || {
            for d in dirs.iter().filter(|d| d.exists()) {
                velarx_base::tree::remove_dir_all_confined(d)?;
            }
            Ok(())
        })
        .await?;

        let name_clone = name.to_string();
        self.db
            .conn()
            .call(move |conn| velarx_db::volumes::delete(conn, &name_clone))
            .await
            .map_err(|e| VolumeError::Database(e.to_string()))?;

        info!("Removed volume: {}", name);
        Ok(())
    }

    /// Rename a volume that no container uses (podman's RenameVolume); its
    /// data directory moves with it when it is in the volumes directory.
    pub async fn rename(&self, name: &str, new_name: &str) -> VolumeResult<Volume> {
        if !valid_volume_name(new_name) {
            return Err(VolumeError::InvalidName(new_name.to_string()));
        }
        // (a create holds the lock shared from its mounts to its row: no
        // container starts to use the volume between the users and the move)
        let _lock = velarx_storage::StorageLock::exclusive(&self.lock).await?;
        let mut volume = self.get(name).await?;
        if volume.name == new_name {
            return Ok(volume);
        }
        if volume.driver != VolumeDriver::Local {
            return Err(VolumeError::Parse(format!(
                "renaming volume {name}: rename is not supported for this driver"
            )));
        }
        let users = self.users(&volume.name).await?;
        if !users.is_empty() {
            return Err(VolumeError::InUse(format!(
                "volume {name} is being used by the following container(s): {}",
                users.join(", ")
            )));
        }
        if is_mount_point(&volume.mountpoint)? {
            return Err(VolumeError::InUse(format!(
                "{name}: volume is currently mounted"
            )));
        }
        // The directory first: once it moved the volume is `new_name`,
        // whatever the rows say, and one transaction replaces its row.  A
        // crash before it leaves a volume directory no row names and a row
        // no directory has, which the check completes.
        let old_dir = self.volumes_dir.join(name);
        let new_dir = self.volumes_dir.join(new_name);
        if new_dir.exists() {
            return Err(VolumeError::AlreadyExists(new_name.to_string()));
        }
        // (a volume made for a container is a named one once renamed: said
        // before it moves, so a crash keeps the volume rather than leaving
        // a renamed one that goes with a container; a failure says it back)
        let anonymous = volume.state.anonymous;
        let undo = |dir: &Path, volume: &Volume| {
            if anonymous {
                let mut meta = VolumeMeta::of(volume);
                meta.state.anonymous = true;
                if let Err(e) = meta.write(dir) {
                    warn!("rename volume {name}: mark it anonymous again: {e}");
                }
            }
        };
        if anonymous {
            volume.state.anonymous = false;
            VolumeMeta::of(&volume).write(&old_dir)?;
        }
        if let Err(e) = move_into_place(&old_dir, &new_dir, new_name) {
            undo(&old_dir, &volume);
            return Err(e);
        }
        volume.name = new_name.to_string();
        volume.mountpoint = new_dir.join(VOLUME_DATA);
        let (from, row) = (
            name.to_string(),
            velarx_db::volumes::VolumeRow::from(&volume),
        );
        let stored = self
            .db
            .conn()
            .call(move |conn| velarx_db::volumes::rename(conn, &from, &row))
            .await;
        if let Err(e) = stored {
            match move_into_place(&new_dir, &old_dir, name) {
                Ok(()) => undo(&old_dir, &volume),
                Err(u) => warn!("rename volume {name}: move its directory back: {u}"),
            }
            return Err(VolumeError::Database(e.to_string()));
        }
        info!("Renamed volume {} to {}", name, volume.name);
        Ok(volume)
    }

    /// Prune unused volumes
    pub async fn prune(&self) -> VolumeResult<Vec<String>> {
        let volumes = self.list().await?;
        let mut pruned = Vec::new();

        for vol in volumes {
            if !self.is_volume_in_use(&vol.name).await? {
                if let Err(e) = self.remove(&vol.name, false).await {
                    warn!("Failed to prune volume {}: {}", vol.name, e);
                } else {
                    pruned.push(vol.name);
                }
            }
        }

        Ok(pruned)
    }

    /// The ids of the containers that mount the volume.
    pub async fn users(&self, name: &str) -> VolumeResult<Vec<String>> {
        let mountpoint = match self.get(name).await {
            Ok(v) => v.mountpoint.to_string_lossy().to_string(),
            Err(VolumeError::NotFound(_)) => self
                .volumes_dir
                .join(name)
                .join(VOLUME_DATA)
                .to_string_lossy()
                .to_string(),
            Err(e) => return Err(e),
        };
        let containers = self
            .db
            .list_containers(true)
            .await
            .map_err(|e| VolumeError::Database(e.to_string()))?;
        Ok(containers
            .into_iter()
            .filter(|c| {
                // (a container whose configuration cannot be read may use
                // the volume: it is counted, the volume is not removed
                // under it)
                serde_json::from_str::<crate::container::ContainerConfig>(&c.config).map_or_else(
                    |e| {
                        warn!("Cannot read the configuration of container {}: {e}", c.id);
                        true
                    },
                    |cfg| {
                        cfg.mounts.iter().any(|m| {
                            m.volume.as_deref() == Some(name)
                                || m.source == mountpoint
                                || (m.mount_type.as_deref() == Some("volume") && m.source == name)
                        })
                    },
                )
            })
            .map(|c| c.id)
            .collect())
    }

    /// Check if a volume is in use by any container
    async fn is_volume_in_use(&self, name: &str) -> VolumeResult<bool> {
        Ok(!self.users(name).await?.is_empty())
    }

    /// Store a volume in the database
    async fn store_volume(&self, volume: &Volume) -> VolumeResult<()> {
        let row = velarx_db::volumes::VolumeRow::from(volume);
        self.db
            .conn()
            .call(move |conn| velarx_db::volumes::upsert(conn, &row))
            .await
            .map_err(|e| VolumeError::Database(e.to_string()))
    }

    /// Replace the state of a volume: its file, then its row.
    pub async fn set_state(&self, name: &str, state: &VolumeState) -> VolumeResult<()> {
        let _lock = self.changing().await?;
        let dir = self.volumes_dir.join(name);
        let mut meta = VolumeMeta::read(&dir)?;
        meta.state = state.clone();
        meta.write(&dir)?;
        let (name, json) = (
            name.to_string(),
            serde_json::to_string(state).map_err(std::io::Error::from)?,
        );
        self.db
            .conn()
            .call(move |conn| {
                conn.execute(
                    "UPDATE volumes SET state = ?2 WHERE name = ?1",
                    [&name, &json],
                )?;
                Ok(())
            })
            .await
            .map_err(|e| VolumeError::Database(e.to_string()))
    }

    /// Mount what the options of the volume ask for (`type`, `device`, `o`)
    /// at its mount point, if it is not mounted already; the path.
    pub async fn mount(&self, name: &str) -> VolumeResult<PathBuf> {
        let volume = self.get(name).await?;
        if let Some(m) = local_volume_mount(&volume.options)? {
            if !is_mount_point(&volume.mountpoint)? {
                mount_volume(&m, &volume.mountpoint)?;
            }
        }
        Ok(volume.mountpoint)
    }

    /// Unmount a volume that `mount` mounted; it is no error when it was not.
    pub async fn unmount(&self, name: &str) -> VolumeResult<()> {
        let volume = self.get(name).await?;
        if !self.users(name).await?.is_empty() {
            return Err(VolumeError::InUse(name.to_string()));
        }
        self.unmount_path(&volume.mountpoint)
    }

    /// Unmount what is mounted at `path` (a volume mounted more than once
    /// has them all taken, the last on top first); busy is an error.
    fn unmount_path(&self, path: &Path) -> VolumeResult<()> {
        // (`is_mount_point` does not follow a link at the end: neither
        // does the unmount)
        while is_mount_point(path)? {
            rustix::mount::unmount(path, rustix::mount::UnmountFlags::NOFOLLOW)
                .map_err(io::Error::from)?;
        }
        Ok(())
    }

    /// The mount of a `-v` or `--mount` for a container: named volumes are
    /// created when missing (anonymous ones when there is no name) and mounted
    /// when their options ask for it, a bind source has to exist.  Images are
    /// resolved later, by the container service.
    pub async fn resolve_mount(&self, spec: MountSpec) -> VolumeResult<MountConfig> {
        Ok(self.resolve_mount_new(spec, None).await?.0)
    }

    /// `resolve_mount` for the create of `container` (an anonymous volume
    /// says it was made for it), and whether it created the volume.
    pub async fn resolve_mount_new(
        &self,
        spec: MountSpec,
        container: Option<&str>,
    ) -> VolumeResult<(MountConfig, bool)> {
        let mut spec = spec;
        let mut created = false;
        match spec.mount_type {
            MountType::Volume => {
                let name = match spec.source.clone() {
                    Some(n) => n,
                    None => {
                        let v = self
                            .create_with(CreateVolume {
                                anonymous: true,
                                container: container.map(str::to_string),
                                ..Default::default()
                            })
                            .await?;
                        spec.source = Some(v.name.clone());
                        created = true;
                        v.name
                    }
                };
                if self.get(&name).await.is_err() {
                    match self
                        .create_with(CreateVolume {
                            name: Some(name.clone()),
                            ..Default::default()
                        })
                        .await
                    {
                        Ok(_) => created = true,
                        // Another container made it first.
                        Err(VolumeError::AlreadyExists(_)) => {}
                        Err(e) => return Err(e),
                    }
                }
                let mountpoint = self.mount(&name).await?;
                let mut cfg = spec.to_mount_config(&self.volumes_dir)?;
                cfg.source = mountpoint.to_string_lossy().to_string();
                cfg.volume = Some(name);
                Ok((cfg, created))
            }
            MountType::Bind => {
                let src = spec.source.as_deref().unwrap_or_default();
                if let Err(e) = fs::metadata(src) {
                    // (as the system says it, in the words of podman's `statfs`)
                    let why = e.to_string();
                    let why = why.split(" (os error").next().unwrap_or(&why);
                    let mut why = why.to_string();
                    if let Some(first) = why.get_mut(..1) {
                        first.make_ascii_lowercase();
                    }
                    return Err(VolumeError::Parse(format!("statfs {src}: {why}")));
                }
                Ok((spec.to_mount_config(&self.volumes_dir)?, false))
            }
            _ => Ok((spec.to_mount_config(&self.volumes_dir)?, false)),
        }
    }

    /// The directory of a volume of this service (its data is in `_data`).
    #[cfg(test)]
    pub fn volume_path(&self, name: &str) -> PathBuf {
        self.volumes_dir.join(name)
    }

    /// The directory the service made for a volume: `NAME` holding `_data`.
    fn own_dir(&self, volume: &Volume) -> Option<PathBuf> {
        let dir = self.volumes_dir.join(&volume.name);
        (volume.mountpoint == dir.join(VOLUME_DATA)).then_some(dir)
    }
}

impl From<velarx_db::volumes::VolumeRow> for Volume {
    fn from(row: velarx_db::volumes::VolumeRow) -> Self {
        Volume {
            name: row.name,
            driver: serde_json::from_str(&row.driver).unwrap_or(VolumeDriver::Local),
            mountpoint: PathBuf::from(row.mountpoint),
            labels: serde_json::from_str(&row.labels).unwrap_or_default(),
            options: serde_json::from_str(&row.options).unwrap_or_default(),
            created_at: row.created_at,
            scope: row.scope,
            state: row
                .state
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default(),
        }
    }
}

impl From<&Volume> for velarx_db::volumes::VolumeRow {
    fn from(volume: &Volume) -> Self {
        fn json(v: &impl Serialize) -> String {
            serde_json::to_string(v).unwrap_or_default()
        }
        Self {
            name: volume.name.clone(),
            driver: json(&volume.driver),
            mountpoint: volume.mountpoint.to_string_lossy().to_string(),
            labels: json(&volume.labels),
            options: json(&volume.options),
            created_at: volume.created_at.clone(),
            scope: volume.scope.clone(),
            state: Some(json(&volume.state)),
        }
    }
}

/// Mount a local-driver volume.
fn mount_volume(m: &VolumeMount, target: &Path) -> VolumeResult<()> {
    use rustix::mount::{mount, mount_bind, MountFlags};
    let err = |e: rustix::io::Errno| {
        VolumeError::Io(std::io::Error::other(format!(
            "mounting {} at {}: {}",
            m.device,
            target.display(),
            std::io::Error::from_raw_os_error(e.raw_os_error())
        )))
    };
    if m.fstype == "bind" {
        mount_bind(m.device.as_str(), target).map_err(err)?;
        if m.flags.iter().any(|f| f == "ro") {
            let flags = MountFlags::BIND | MountFlags::RDONLY;
            rustix::mount::mount_remount(target, flags, "").map_err(err)?;
        }
        return Ok(());
    }
    let mut flags = MountFlags::empty();
    for f in &m.flags {
        flags |= match f.as_str() {
            "ro" => MountFlags::RDONLY,
            "nosuid" => MountFlags::NOSUID,
            "nodev" => MountFlags::NODEV,
            "noexec" => MountFlags::NOEXEC,
            "noatime" => MountFlags::NOATIME,
            "relatime" => MountFlags::RELATIME,
            "sync" => MountFlags::SYNCHRONOUS,
            "dirsync" => MountFlags::DIRSYNC,
            _ => MountFlags::empty(),
        };
    }
    debug!("mount -t {} {} {}", m.fstype, m.device, target.display());
    let data = std::ffi::CString::new(m.data.as_str())
        .map_err(|_| VolumeError::Parse("a NUL in the mount options".into()))?;
    mount(
        m.device.as_str(),
        target,
        m.fstype.as_str(),
        flags,
        Some(data.as_c_str()),
    )
    .map_err(err)
}

#[cfg(test)]
mod tests {
    /// A host path of a mount given as values is the path, whatever it
    /// holds; the text of `-v` cannot say a colon in it.
    #[test]
    fn a_bind_mount_of_values_keeps_a_colon_and_a_comma_in_its_path() {
        let ro = ["ro".to_string(), "rslave".to_string()];
        for path in ["/data/a:b", "/data/a:b:c", "/data/a,b", "/data/:ro"] {
            let m = MountSpec::bind(path, "/m", &ro).unwrap();
            assert_eq!(m.mount_type, MountType::Bind);
            assert_eq!(m.source.as_deref(), Some(path));
            assert_eq!(m.target, "/m");
            assert!(m.options.read_only);
            assert_eq!(m.options.propagation, BindPropagation::Rslave);
        }
        // (the text of -v read the colon as the end of the path)
        assert!(MountSpec::parse_volume_arg("/data/a:b:/m:ro").is_err());
        assert!(MountSpec::bind("relative", "/m", &[]).is_err());
        assert!(MountSpec::bind("/h", "/m", &["nonsense".to_string()]).is_err());
    }

    #[test]
    fn an_image_mount_of_values_has_its_subpath_and_a_comma_is_a_name() {
        let m = MountSpec::image("sha256:abc", "/i,x", Some("a,b")).unwrap();
        assert_eq!(m.mount_type, MountType::Image);
        assert_eq!(
            (m.source.as_deref(), m.target.as_str()),
            (Some("sha256:abc"), "/i,x")
        );
        assert_eq!(m.options.subpath.as_deref(), Some("a,b"));
        assert_eq!(
            MountSpec::image("i", "/i", Some(""))
                .unwrap()
                .options
                .subpath,
            None
        );
        assert!(MountSpec::image("", "/i", None).is_err());
    }

    use super::*;

    fn volume(arg: &str) -> MountSpec {
        MountSpec::parse_volume_arg(arg).unwrap()
    }

    fn mount(arg: &str) -> MountSpec {
        MountSpec::parse_mount_arg(arg).unwrap()
    }

    #[test]
    fn a_volume_is_mounted_nosuid_and_nodev() {
        let opts = |m: MountSpec| m.to_oci_mount(Path::new("/v")).unwrap().options;
        let has = |o: &[String], w: &str| o.iter().any(|x| x == w);
        for m in [
            volume("v:/x"),
            volume("/anon"),
            mount("type=volume,source=v,target=/x"),
        ] {
            let o = opts(m);
            assert!(has(&o, "nosuid") && has(&o, "nodev"), "{o:?}");
        }
        // suid and dev ask for them
        let o = opts(volume("v:/x:suid,dev"));
        assert!(!has(&o, "nosuid") && !has(&o, "nodev"), "{o:?}");
        let o = opts(volume("v:/x:suid"));
        assert!(!has(&o, "nosuid") && has(&o, "nodev"), "{o:?}");
        // a bind mount keeps the flags of its host file system
        let o = opts(volume("/h:/x"));
        assert!(!has(&o, "nosuid") && !has(&o, "nodev"), "{o:?}");
    }

    #[test]
    fn an_image_mount_is_nodev() {
        let opts = |m: MountSpec| m.to_oci_mount(Path::new("/v")).unwrap().options;
        let has = |o: &[String], w: &str| o.iter().any(|x| x == w);
        let o = opts(mount("type=image,source=img,target=/x"));
        assert!(
            has(&o, "nodev") && has(&o, "ro") && !has(&o, "nosuid"),
            "{o:?}"
        );
        let o = opts(mount("type=image,source=img,target=/x,dev"));
        assert!(!has(&o, "nodev"), "{o:?}");
    }

    #[test]
    fn a_devpts_mount_has_the_options_it_is_given() {
        let o = mount("type=devpts,destination=/dev/pts2,mode=620,gid=5,ptmxmode=666,newinstance")
            .to_oci_mount(Path::new("/v"))
            .unwrap();
        assert_eq!(
            (
                o.mount_type.as_str(),
                o.source.as_str(),
                o.destination.as_str()
            ),
            ("devpts", "devpts", "/dev/pts2")
        );
        assert_eq!(
            o.options,
            ["mode=620", "gid=5", "ptmxmode=666", "newinstance"]
        );
        assert!(MountSpec::parse_mount_arg("type=bind,src=/h,dst=/x,gid=5").is_err());
        assert!(MountSpec::parse_mount_arg("type=devpts,dst=/x,bogus=1").is_err());
        for bad in ["ro", "src=x", "readonly", "bind-propagation=shared"] {
            let e = MountSpec::parse_mount_arg(&format!("type=devpts,dst=/x,{bad}")).unwrap_err();
            assert!(e.to_string().contains("for a devpts mount"), "{bad}: {e}");
        }
        assert!(MountSpec::parse_mount_arg("type=devpts").is_err());
    }

    #[test]
    fn test_volume_names() {
        for ok in ["a", "data", "my_vol.1-x", "0abc", "A"] {
            assert!(valid_volume_name(ok), "{ok}");
        }
        for bad in ["", "-x", ".x", "_x", "a b", "a/b", "a:b", "../x", "é"] {
            assert!(!valid_volume_name(bad), "{bad}");
        }
        assert!(!valid_volume_name(&"a".repeat(256)));
    }

    #[test]
    fn test_volume_arg_forms() {
        let s = volume("/data");
        assert_eq!(
            (s.mount_type, s.source, s.target),
            (MountType::Volume, None, "/data".into())
        );
        let s = volume("vol:/data/");
        assert_eq!(
            (s.mount_type, s.source.as_deref(), s.target.as_str()),
            (MountType::Volume, Some("vol"), "/data")
        );
        let s = volume("/h:/a/../b//c:ro,z");
        assert_eq!((s.mount_type, s.target.as_str()), (MountType::Bind, "/b/c"));
        assert!(s.options.read_only);
        for bad in [
            "",
            "vol:data",
            "vol:/",
            ":/x",
            "/a:/b:c:d",
            "a b:/x",
            "./rel:/x",
            "~/x:/y",
            "/h:/x:bogus",
        ] {
            assert!(MountSpec::parse_volume_arg(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn test_volume_options() {
        let o = volume("/h:/x:U").options;
        assert!(o.chown && o.idmap.is_none());
        let o = volume("v:/x:idmap").options;
        assert_eq!(o.idmap.as_deref(), Some("idmap"));
        let o = volume("v:/x:idmap=uids=0-1000-1;gids=0-1000-1,nocopy").options;
        assert_eq!(
            o.idmap.as_deref(),
            Some("idmap=uids=0-1000-1;gids=0-1000-1")
        );
        assert!(o.nocopy);
        let o = volume("v:/x:copy").options;
        assert!(!o.nocopy);
        let o = volume("/h:/x:nosuid,noexec,rslave,Z").options;
        assert_eq!(o.extra, ["nosuid", "noexec"]);
        assert_eq!(o.propagation, BindPropagation::Rslave);
        assert_eq!(o.selinux_relabel, Some(SelinuxRelabel::Private));
        // recursive read-only: the OCI option after `ro`, on a recursive bind mount
        let oci = volume("/h:/x:ro,rro")
            .to_oci_mount(Path::new("/v"))
            .unwrap();
        let pos = |n: &str| oci.options.iter().position(|o| o == n).unwrap();
        assert!(pos("rbind") < pos("ro") && pos("ro") < pos("rro"));
        for bad in ["/h:/x:rro", "/h:/x:rw,rro", "/h:/x:ro,bind,rro"] {
            assert!(MountSpec::parse_volume_arg(bad).is_err(), "{bad}");
        }
        // recursive unless `bind` says otherwise, as podman's `-v`
        for (arg, recursion) in [
            ("/h:/x", "rbind"),
            ("/h:/x:rbind", "rbind"),
            ("/h:/x:ro,bind", "bind"),
            ("v:/x:bind", "bind"),
        ] {
            let oci = volume(arg).to_oci_mount(Path::new("/v")).unwrap();
            assert_eq!(oci.options[0], recursion, "{arg}: {:?}", oci.options);
            let other = if recursion == "bind" { "rbind" } else { "bind" };
            assert!(!oci.options.iter().any(|o| o == other), "{arg}");
        }
        for twice in ["/h:/x:bind,rbind", "/h:/x:rbind,rbind"] {
            assert!(MountSpec::parse_volume_arg(twice).is_err(), "{twice}");
        }
        assert!(
            MountSpec::parse_mount_arg("type=bind,src=/h,dst=/x,ro,bind-nonrecursive,rro").is_err()
        );
        assert!(MountSpec::parse_mount_arg("type=tmpfs,dst=/x,ro,rro").is_err());
        // Options of other tools that mean nothing here.
        volume("/h:/x:delegated,cached");
        // `U` and `idmap` would map the ids twice.
        assert!(MountSpec::parse_mount_arg("type=bind,src=/h,dst=/x,U,idmap").is_err());
    }

    #[test]
    fn test_mount_arg() {
        let s = mount("type=bind,source=/src,target=/dest,readonly,bind-propagation=shared");
        assert_eq!(s.mount_type, MountType::Bind);
        assert!(s.options.read_only);
        assert_eq!(s.options.propagation, BindPropagation::Shared);
        let s = mount("type=bind,src=/s,dst=/d,ro=false,U=true,relabel=shared");
        assert!(!s.options.read_only && s.options.chown);
        assert_eq!(s.options.selinux_relabel, Some(SelinuxRelabel::Shared));
        let s = mount("type=volume,src=v,dst=/d,volume-nocopy,subpath=a/b");
        assert!(s.options.nocopy);
        assert_eq!(s.options.subpath.as_deref(), Some("a/b"));
        let s = mount("type=bind,src=/s,dst=/d,idmap=uids=0-1-1;gids=0-1-1");
        assert_eq!(
            s.options.idmap.as_deref(),
            Some("idmap=uids=0-1-1;gids=0-1-1")
        );
        let s = mount("type=tmpfs,destination=/t,tmpfs-size=10m,tmpfs-mode=700");
        assert_eq!(s.options.tmpfs, ["size=10m", "mode=700"]);
        let s = mount("type=ramfs,destination=/r,nosuid,ro");
        let oci = s.to_oci_mount(Path::new("/v")).unwrap();
        assert_eq!(
            (
                oci.mount_type.as_str(),
                oci.source.as_str(),
                oci.options.as_slice()
            ),
            (
                "ramfs",
                "ramfs",
                ["ro".to_string(), "nosuid".to_string()].as_slice()
            )
        );
        assert_eq!(
            mount("type=bind,src=/s,dst=/d,Z").options.selinux_relabel,
            Some(SelinuxRelabel::Private)
        );
        let s = mount("type=image,source=alpine,destination=/img,subpath=/etc,rw");
        assert_eq!(s.mount_type, MountType::Image);
        assert!(s.options.image_rw);
        for bad in [
            "type=bind,src=/s",
            "type=bind,dst=/d",
            "type=bind,src=rel,dst=/d",
            "type=weird,src=/s,dst=/d",
            "type=bind,src=/s,dst=/d,unknown=1",
            "type=bind,src=/s,dst=/d,bind-propagation=x",
            "type=bind,src=/s,dst=/d,ro=maybe",
            "type=bind,src=/s,dst=/d,subpath=x",
            "type=tmpfs,dst=/t,subpath=x",
            "type=volume,src=v,dst=/d,subpath=../x",
            "type=volume,src=v,dst=/d,subpath=",
            "type=tmpfs,dst=/t,idmap",
            "type=ramfs,dst=/t,tmpfs-size=1m",
            "type=tmpfs,dst=/t,relabel=shared",
            "type=image,dst=/i",
            "type=volume,src=bad/name,dst=/d",
            "type=bind,src=/s,dst=relative",
            "type=bind,src=/s,dst=/",
        ] {
            assert!(MountSpec::parse_mount_arg(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn test_tmpfs_arg() {
        let s = MountSpec::parse_tmpfs_arg("/run/x:size=1m,mode=1777,ro,noexec").unwrap();
        let c = s.to_mount_config(Path::new("/v")).unwrap();
        assert_eq!(c.mount_type.as_deref(), Some("tmpfs"));
        assert_eq!(c.target, "/run/x");
        assert!(c.options.contains(&"ro".to_string()));
        assert!(c.options.contains(&"noexec".to_string()));
        assert!(c.options.contains(&"size=1m".to_string()));
        // the defaults that the user did not override, podman's: no noexec
        for d in ["nosuid", "nodev", "tmpcopyup"] {
            assert!(c.options.contains(&d.to_string()), "{d}");
        }
        assert_eq!(c.options.iter().filter(|o| *o == "noexec").count(), 1);
        let c = MountSpec::parse_tmpfs_arg("/t:exec,notmpcopyup")
            .unwrap()
            .to_mount_config(Path::new("/v"))
            .unwrap();
        assert!(
            c.options.contains(&"exec".to_string()) && !c.options.contains(&"noexec".to_string())
        );
        assert!(
            !c.options.iter().any(|o| o.ends_with("tmpcopyup")),
            "{:?}",
            c.options
        );
        assert!(MountSpec::parse_tmpfs_arg("rel").is_err());
    }

    #[test]
    fn test_mount_config() {
        let c = volume("v:/data:ro,U,nocopy,z")
            .to_mount_config(Path::new("/vols"))
            .unwrap();
        assert_eq!((c.target.as_str(), c.source.as_str()), ("/data", "/vols/v"));
        assert_eq!(c.volume.as_deref(), Some("v"));
        assert!(c.chown && c.nocopy);
        assert_eq!(c.relabel.as_deref(), Some("z"));
        assert_eq!(c.options, ["rbind", "ro", "rprivate", "nosuid", "nodev"]);
        let c = volume("/h:/data:idmap")
            .to_mount_config(Path::new("/vols"))
            .unwrap();
        assert_eq!(c.idmap.as_deref(), Some("idmap"));
        assert!(c.volume.is_none());
        let c = mount("type=image,source=alpine,target=/i,subpath=/etc")
            .to_mount_config(Path::new("/vols"))
            .unwrap();
        assert_eq!(c.options, ["rbind", "ro", "rprivate", "nodev"]);
        let i = c.image.unwrap();
        assert_eq!(
            (i.image.as_str(), i.subpath.as_deref(), i.rw),
            ("alpine", Some("/etc"), false)
        );
        assert!(c.subpath.is_none());
        let c = mount("type=volume,source=v,target=/i,subpath=sub")
            .to_mount_config(Path::new("/vols"))
            .unwrap();
        assert_eq!(c.subpath.as_deref(), Some("sub"));
        let c = MountSpec::bind("/h", "/i", &[])
            .unwrap()
            .in_subpath("sub")
            .unwrap()
            .to_mount_config(Path::new("/vols"))
            .unwrap();
        assert_eq!(
            (c.source.as_str(), c.subpath.as_deref(), c.volume.as_deref()),
            ("/h", Some("sub"), None)
        );
        // the sub path of a bind mount is checked as that of a volume, and
        // takes no `U` (nothing would give it to the user)
        let bind = |o: &[&str]| {
            let o: Vec<String> = o.iter().map(|s| s.to_string()).collect();
            MountSpec::bind("/h", "/i", &o).unwrap()
        };
        assert!(bind(&[]).in_subpath("../x").is_err());
        assert!(bind(&[]).in_subpath("").is_err());
        assert!(bind(&["U"]).in_subpath("x").is_err());
        let o = volume("/s:/d:ro").to_oci_mount(Path::new("/v")).unwrap();
        assert_eq!(
            (
                o.source.as_str(),
                o.destination.as_str(),
                o.mount_type.as_str()
            ),
            ("/s", "/d", "bind")
        );
    }

    #[test]
    fn test_local_volume_options() {
        let o = |kv: &[(&str, &str)]| {
            local_volume_mount(
                &kv.iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            )
        };
        assert_eq!(o(&[]).unwrap(), None);
        assert_eq!(o(&[("uid", "1000"), ("gid", "100")]).unwrap(), None);
        let m = o(&[
            ("type", "tmpfs"),
            ("device", "tmpfs"),
            ("o", "nosuid,size=1m,mode=700"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(
            (m.fstype.as_str(), m.flags.as_slice(), m.data.as_str()),
            ("tmpfs", &["nosuid".to_string()][..], "size=1m,mode=700")
        );
        let m = o(&[("type", "tmpfs"), ("size", "10m")]).unwrap().unwrap();
        assert_eq!((m.device.as_str(), m.data.as_str()), ("tmpfs", "size=10m"));
        let m = o(&[("type", "bind"), ("device", "/srv/x"), ("o", "ro")])
            .unwrap()
            .unwrap();
        assert_eq!((m.fstype.as_str(), m.device.as_str()), ("bind", "/srv/x"));
        let m = o(&[("device", "/srv/x"), ("o", "bind")]).unwrap().unwrap();
        assert_eq!(m.fstype, "bind");
        for bad in [
            vec![("bogus", "1")],
            vec![("uid", "x")],
            vec![("type", "ext4")],
            vec![("type", "ext4"), ("size", "1m"), ("device", "/dev/x")],
            vec![("o", "ro")],
            vec![("type", "bind"), ("device", "rel")],
            vec![("inodes", "10")],
            vec![("o", "uid=x")],
        ] {
            assert!(o(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn test_owner_in_the_o_option_is_not_a_mount() {
        let opts = |v: &[(&str, &str)]| -> HashMap<String, String> {
            v.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        // podman: `--opt o=uid=1000,gid=1000` only sets the owner.
        let m = opts(&[("o", "uid=1000,gid=100"), ("copy", "")]);
        assert!(local_volume_mount(&m).unwrap().is_none());
        assert_eq!(local_volume_owner(&m, "uid"), Some(1000));
        assert_eq!(local_volume_owner(&m, "gid"), Some(100));
        // The plain options win.
        let m = opts(&[("uid", "5"), ("o", "uid=1000")]);
        assert_eq!(local_volume_owner(&m, "uid"), Some(5));
        assert_eq!(local_volume_owner(&m, "gid"), None);
        // With a type they are passed to the file system as well.
        let m = local_volume_mount(&opts(&[("type", "tmpfs"), ("o", "uid=1000,size=1m")]))
            .unwrap()
            .unwrap();
        assert!(
            m.data.contains("uid=1000") && m.data.contains("size=1m"),
            "{m:?}"
        );
    }

    #[test]
    fn a_mount_point_is_the_root_of_a_mount() {
        assert!(is_mount_point(Path::new("/proc")).unwrap());
        assert!(!is_mount_point(Path::new("/proc/self/cwd/definitely-not")).unwrap());
    }

    /// A directory with each of the bytes the kernel's mount table writes
    /// as an octal escape (space, tab, newline, backslash) or that are not
    /// UTF-8: every mount stacked on it is found and unmounted, the top one
    /// first, and a directory next to it is not taken.
    #[test]
    fn mounts_at_a_path_of_any_bytes_are_found_and_taken() {
        velarx_base::testing::in_child(|| {
            use rustix::mount::{mount, MountFlags};
            use std::os::unix::ffi::OsStrExt;
            if !velarx_base::testing::private_namespace() {
                return;
            }
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let (svc, dir) = rt.block_on(service());
            let tmpfs = |at: &Path| mount("t", at, "tmpfs", MountFlags::empty(), None).unwrap();
            for name in [&b"a b"[..], b"a\tb\n\\c", b"x\xffy"] {
                let at = dir.path().join(std::ffi::OsStr::from_bytes(name));
                let next = dir
                    .path()
                    .join(std::ffi::OsStr::from_bytes(&[name, b"2"].concat()));
                fs::create_dir(&at).unwrap();
                fs::create_dir(&next).unwrap();
                assert!(!is_mount_point(&at).unwrap());
                tmpfs(&at);
                tmpfs(&at);
                tmpfs(&next);
                assert!(is_mount_point(&at).unwrap(), "{at:?}");
                fs::write(at.join("top"), b"").unwrap();
                svc.unmount_path(&at).unwrap();
                assert!(!is_mount_point(&at).unwrap(), "{at:?}");
                assert!(!at.join("top").exists());
                assert!(is_mount_point(&next).unwrap(), "{next:?}");
            }
        });
    }

    /// A mount point that cannot be looked up (a loop of links above it) is
    /// not "not mounted": the removal is refused and the data stays.
    #[tokio::test]
    async fn a_failing_lookup_does_not_remove_the_data() {
        let (svc, _dir) = service().await;
        let v = svc
            .create("v", VolumeDriver::Local, HashMap::new(), HashMap::new())
            .await
            .unwrap();
        fs::write(v.mountpoint.join("keep"), b"x").unwrap();
        let dir = svc.volume_path("v");
        let real = svc.volume_path("real");
        fs::rename(&dir, &real).unwrap();
        std::os::unix::fs::symlink("v", &dir).unwrap();
        assert!(is_mount_point(&v.mountpoint).is_err());
        assert!(svc.remove("v", true).await.is_err());
        assert!(svc.get("v").await.is_ok());
        assert_eq!(fs::read(real.join("_data/keep")).unwrap(), b"x");
    }

    /// A link at the end of the path of a volume is not followed by the
    /// unmount, as `is_mount_point` does not: the mount it points to stays.
    #[test]
    fn a_link_at_the_end_does_not_unmount_what_it_points_to() {
        velarx_base::testing::in_child(|| {
            use rustix::mount::{mount, MountFlags};
            if !velarx_base::testing::private_namespace() {
                return;
            }
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let (svc, dir) = rt.block_on(service());
            let other = dir.path().join("other");
            let link = dir.path().join("link");
            fs::create_dir(&other).unwrap();
            mount("t", &other, "tmpfs", MountFlags::empty(), None).unwrap();
            std::os::unix::fs::symlink(&other, &link).unwrap();
            assert!(!is_mount_point(&link).unwrap());
            svc.unmount_path(&link).unwrap();
            assert!(is_mount_point(&other).unwrap());
        });
    }

    async fn service() -> (VolumeService, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open_in_memory().await.unwrap();
        (
            VolumeService::new(db, dir.path().join("volumes")).unwrap(),
            dir,
        )
    }

    /// A volume that is not there is `NotFound`; a database that cannot be
    /// read is an error of its own, and a create does not take it for a
    /// name that is free.
    #[tokio::test]
    async fn a_database_that_cannot_be_read_is_not_a_missing_volume() {
        let (svc, _dir) = service().await;
        assert!(matches!(svc.get("a").await, Err(VolumeError::NotFound(_))));
        svc.db
            .conn()
            .call(|c| {
                c.execute("ALTER TABLE volumes RENAME TO hidden", [])?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(matches!(svc.get("a").await, Err(VolumeError::Database(_))));
        assert!(matches!(
            svc.create("a", VolumeDriver::Local, HashMap::new(), HashMap::new())
                .await,
            Err(VolumeError::Database(_))
        ));
    }

    #[tokio::test]
    async fn test_rename() {
        let (svc, _dir) = service().await;
        let v = svc
            .create("a", VolumeDriver::Local, HashMap::new(), HashMap::new())
            .await
            .unwrap();
        fs::write(v.mountpoint.join("f"), "x").unwrap();
        svc.create("b", VolumeDriver::Local, HashMap::new(), HashMap::new())
            .await
            .unwrap();
        assert!(matches!(
            svc.rename("a", "b").await,
            Err(VolumeError::AlreadyExists(_))
        ));
        assert!(matches!(
            svc.rename("a", "../x").await,
            Err(VolumeError::InvalidName(_))
        ));
        assert!(matches!(
            svc.rename("nope", "c").await,
            Err(VolumeError::NotFound(_))
        ));
        let r = svc.rename("a", "c").await.unwrap();
        assert_eq!(r.name, "c");
        assert_eq!(fs::read_to_string(r.mountpoint.join("f")).unwrap(), "x");
        assert!(svc.get("a").await.is_err());
        assert_eq!(svc.get("c").await.unwrap().mountpoint, r.mountpoint);
        assert!(!v.mountpoint.exists());
        assert!(r.mountpoint.ends_with("c/_data"));
        // the directories go with the volume
        svc.remove("c", false).await.unwrap();
        assert!(!svc.volume_path("c").exists());
    }

    /// A rename that dies after the directory moved and before its row:
    /// the directory has the new name, the row the old one, and the
    /// directory is the volume.
    #[tokio::test]
    async fn a_rename_killed_before_its_row_leaves_the_new_directory() {
        let (svc, _dir) = service().await;
        let v = svc
            .create("a", VolumeDriver::Local, HashMap::new(), HashMap::new())
            .await
            .unwrap();
        fs::write(v.mountpoint.join("f"), "x").unwrap();
        ignore(&svc, "DELETE").await;
        ignore(&svc, "INSERT").await;
        svc.rename("a", "c").await.unwrap();
        assert_eq!(entries(&svc), ["c"]);
        assert_eq!(
            fs::read_to_string(svc.volume_path("c").join("_data/f")).unwrap(),
            "x"
        );
        assert!(VolumeMeta::read(&svc.volume_path("c")).is_ok());
        assert_eq!(svc.get("a").await.unwrap().mountpoint, v.mountpoint);
        assert!(matches!(svc.get("c").await, Err(VolumeError::NotFound(_))));
    }

    /// A database that refuses the row gets the directory back, as it was.
    #[tokio::test]
    async fn a_rename_the_database_refuses_moves_the_directory_back() {
        let (svc, _dir) = service().await;
        let v = svc
            .create_with(CreateVolume {
                name: Some("a".into()),
                anonymous: true,
                ..Default::default()
            })
            .await
            .unwrap();
        fs::write(v.mountpoint.join("f"), "x").unwrap();
        svc.db
            .conn()
            .call(|conn| {
                conn.execute_batch(
                    "CREATE TRIGGER refused BEFORE INSERT ON volumes \
                     BEGIN SELECT RAISE(FAIL, 'refused'); END",
                )?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(matches!(
            svc.rename("a", "c").await,
            Err(VolumeError::Database(_))
        ));
        assert_eq!(entries(&svc), ["a"]);
        assert_eq!(fs::read_to_string(v.mountpoint.join("f")).unwrap(), "x");
        assert_eq!(svc.get("a").await.unwrap().mountpoint, v.mountpoint);
        assert_eq!(
            VolumeMeta::read(&svc.volume_path("a")).unwrap(),
            VolumeMeta::of(&v)
        );
    }

    /// A move that fails changes nothing: the row was not touched.
    #[tokio::test]
    async fn a_rename_whose_directory_is_gone_changes_nothing() {
        let (svc, _dir) = service().await;
        let v = svc
            .create("a", VolumeDriver::Local, HashMap::new(), HashMap::new())
            .await
            .unwrap();
        fs::remove_dir_all(svc.volume_path("a")).unwrap();
        assert!(matches!(
            svc.rename("a", "c").await,
            Err(VolumeError::Io(_))
        ));
        assert_eq!(svc.get("a").await.unwrap().mountpoint, v.mountpoint);
        assert!(matches!(svc.get("c").await, Err(VolumeError::NotFound(_))));
        assert!(entries(&svc).is_empty());
    }

    /// A name a directory has is refused before anything moves, whether or
    /// not a row names it; the file of an anonymous volume is not touched.
    #[tokio::test]
    async fn a_rename_to_an_existing_directory_moves_nothing() {
        let (svc, _dir) = service().await;
        svc.create_with(CreateVolume {
            name: Some("a".into()),
            anonymous: true,
            ..Default::default()
        })
        .await
        .unwrap();
        fs::create_dir(svc.volume_path("c")).unwrap();
        let before = fs::read(svc.volume_path("a").join(VOLUME_META)).unwrap();
        assert!(matches!(
            svc.rename("a", "c").await,
            Err(VolumeError::AlreadyExists(_))
        ));
        assert_eq!(entries(&svc), ["a", "c"]);
        assert_eq!(
            fs::read(svc.volume_path("a").join(VOLUME_META)).unwrap(),
            before
        );
        assert!(svc.get("a").await.unwrap().state.anonymous);
        // a link is a name taken too, found by the move itself
        std::os::unix::fs::symlink("nowhere", svc.volume_path("d")).unwrap();
        assert!(matches!(
            svc.rename("a", "d").await,
            Err(VolumeError::AlreadyExists(_))
        ));
        assert_eq!(entries(&svc), ["a", "c", "d"]);
        assert!(
            VolumeMeta::read(&svc.volume_path("a"))
                .unwrap()
                .state
                .anonymous
        );
    }

    /// A volume made for a container is a named one after a rename, in its
    /// file as in its row.
    #[tokio::test]
    async fn a_renamed_anonymous_volume_is_not_anonymous_in_its_file() {
        let (svc, _dir) = service().await;
        svc.create_with(CreateVolume {
            name: Some("a".into()),
            anonymous: true,
            ..Default::default()
        })
        .await
        .unwrap();
        svc.rename("a", "c").await.unwrap();
        assert!(
            !VolumeMeta::read(&svc.volume_path("c"))
                .unwrap()
                .state
                .anonymous
        );
        assert!(!svc.get("c").await.unwrap().state.anonymous);
    }

    #[tokio::test]
    async fn test_create_state_and_options() {
        let (svc, _dir) = service().await;
        let v = svc
            .create_with(CreateVolume {
                name: Some("data".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(v.state.needs_copy_up && v.state.needs_chown && !v.state.anonymous);
        assert_eq!(
            fs::metadata(&v.mountpoint).unwrap().permissions().mode() & 0o777,
            0o755
        );
        let got = svc.get("data").await.unwrap();
        assert_eq!(got.state, v.state);
        // The same name again.
        assert!(matches!(
            svc.create_with(CreateVolume {
                name: Some("data".into()),
                ..Default::default()
            })
            .await,
            Err(VolumeError::AlreadyExists(_))
        ));
        // An owner at creation: kept by the first container.
        let uid = rustix::process::getuid().as_raw().to_string();
        let o = svc
            .create_with(CreateVolume {
                name: Some("owned".into()),
                options: HashMap::from([("uid".to_string(), uid)]),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(!o.state.needs_chown);
        // Anonymous volumes have a random name.
        let a = svc
            .create_with(CreateVolume {
                anonymous: true,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(a.name.len(), 64);
        assert!(a.state.anonymous);
        // What a bind volume binds has to be there (podman's words)
        let r = svc
            .create_with(CreateVolume {
                name: Some("bound".into()),
                options: HashMap::from([
                    ("type".to_string(), "bind".to_string()),
                    ("device".to_string(), "/nonexistent-velarx".to_string()),
                ]),
                ..Default::default()
            })
            .await;
        assert_eq!(
            r.unwrap_err().to_string(),
            "invalid volume option device for driver 'local': faccessat /nonexistent-velarx: no such file or directory"
        );
        // Bad ones are refused and leave nothing.
        for (name, opt) in [
            ("../x", None),
            ("ok", Some(("bogus", "1"))),
            ("sz", Some(("size", "1m"))),
        ] {
            let r = svc
                .create_with(CreateVolume {
                    name: Some(name.into()),
                    options: opt
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .into_iter()
                        .collect(),
                    ..Default::default()
                })
                .await;
            assert!(r.is_err(), "{name}");
        }
        assert_eq!(svc.list().await.unwrap().len(), 3);
        assert!(!svc.volume_path("ok").exists());
        // A state update is stored.
        let mut st = got.state.clone();
        st.needs_copy_up = false;
        svc.set_state("data", &st).await.unwrap();
        assert!(!svc.get("data").await.unwrap().state.needs_copy_up);
        svc.remove("data", false).await.unwrap();
        assert!(svc.get("data").await.is_err());
        assert!(!svc.volume_path("data").exists());
    }

    /// A change of a volume waits for the holder of the lock, exclusive,
    /// with nothing done: a check never sees one half done.  Changes share
    /// it.
    #[tokio::test]
    async fn a_change_waits_while_the_volumes_are_locked_exclusive() {
        let (svc, _dir) = service().await;
        let svc = std::sync::Arc::new(svc);
        svc.create("a", VolumeDriver::Local, HashMap::new(), HashMap::new())
            .await
            .unwrap();
        let lock = svc.lock_path().to_path_buf();
        for change in ["create", "set_state", "rename", "remove"] {
            let held = velarx_storage::StorageLock::exclusive(&lock).await.unwrap();
            let before = entries(&svc);
            let task = tokio::spawn({
                let svc = svc.clone();
                async move {
                    let none = HashMap::new;
                    match change {
                        "create" => svc
                            .create("b", VolumeDriver::Local, none(), none())
                            .await
                            .map(drop),
                        "set_state" => svc.set_state("a", &VolumeState::default()).await,
                        "rename" => svc.rename("a", "c").await.map(drop),
                        _ => svc.remove("c", true).await,
                    }
                }
            });
            // (asleep in the lock, and so not ended while it is held)
            let waiter = lock.clone();
            let waits = tokio::task::spawn_blocking(move || {
                velarx_base::testing::wait_lock_waiter(&waiter, std::time::Duration::from_secs(20))
            });
            assert!(waits.await.unwrap(), "{change} does not take the lock");
            assert!(!task.is_finished());
            assert_eq!(entries(&svc), before, "{change}");
            drop(held);
            task.await.unwrap().unwrap();
        }
        assert_eq!(entries(&svc), ["b"]);
        let first = svc.changing().await.unwrap();
        svc.set_state("b", &VolumeState::default()).await.unwrap();
        drop(first);
    }

    /// A rename waits for every holder of the lock, shared as well, and a
    /// change that asks for it again meanwhile is not held back by the
    /// rename that waits: a create holds it shared and calls the changes.
    #[tokio::test]
    async fn a_rename_waits_for_a_shared_holder() {
        let (svc, _dir) = service().await;
        let svc = std::sync::Arc::new(svc);
        svc.create("a", VolumeDriver::Local, HashMap::new(), HashMap::new())
            .await
            .unwrap();
        let held = svc.changing().await.unwrap();
        let task = tokio::spawn({
            let svc = svc.clone();
            async move { svc.rename("a", "c").await.map(drop) }
        });
        let lock = svc.lock_path().to_path_buf();
        let waits = tokio::task::spawn_blocking(move || {
            velarx_base::testing::wait_lock_waiter(&lock, std::time::Duration::from_secs(20))
        });
        assert!(waits.await.unwrap(), "rename does not take the lock");
        assert!(!task.is_finished());
        assert_eq!(entries(&svc), ["a"]);
        // (the shared lock is granted while an exclusive one waits)
        svc.set_state("a", &VolumeState::default()).await.unwrap();
        drop(held);
        task.await.unwrap().unwrap();
        assert_eq!(entries(&svc), ["c"]);
    }

    /// What is in the volumes directory, by name.
    fn entries(svc: &VolumeService) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(svc.volumes_dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// Make the statements of `kind` (`INSERT`, `DELETE`) on the rows of
    /// the volumes do nothing and say nothing: the process that dies
    /// between the directory and the row, with no error to clean up.
    async fn ignore(svc: &VolumeService, kind: &str) {
        let sql = format!(
            "CREATE TRIGGER ignored_{kind} BEFORE {kind} ON volumes \
             BEGIN SELECT RAISE(IGNORE); END"
        );
        svc.db
            .conn()
            .call(move |conn| Ok(conn.execute_batch(&sql)?))
            .await
            .unwrap();
    }

    /// The directory says what the volume is: labels, options, creation
    /// time and state are in `volume.json`, and it reads back as made.
    #[tokio::test]
    async fn a_volume_directory_holds_what_the_row_holds() {
        let (svc, _dir) = service().await;
        let v = svc
            .create_with(CreateVolume {
                name: Some("a".into()),
                labels: HashMap::from([("k".to_string(), "v".to_string())]),
                options: HashMap::from([("type".to_string(), "tmpfs".to_string())]),
                anonymous: true,
                container: Some("c1".into()),
            })
            .await
            .unwrap();
        let meta = VolumeMeta::read(&svc.volume_path("a")).unwrap();
        assert_eq!(meta, VolumeMeta::of(&v));
        assert_eq!(meta.labels["k"], "v");
        assert_eq!(meta.options["type"], "tmpfs");
        assert!(meta.state.anonymous && meta.state.needs_copy_up);
        assert_eq!(meta.state.container.as_deref(), Some("c1"));
        let mode = fs::metadata(svc.volume_path("a").join(VOLUME_META))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(entries(&svc), ["a"]);
    }

    /// A create that dies after the directory moved into place and before
    /// the row: a whole volume directory, no row.
    #[tokio::test]
    async fn a_create_killed_before_its_row_leaves_a_whole_directory() {
        let (svc, _dir) = service().await;
        ignore(&svc, "INSERT").await;
        svc.create("a", VolumeDriver::Local, HashMap::new(), HashMap::new())
            .await
            .unwrap();
        assert!(matches!(svc.get("a").await, Err(VolumeError::NotFound(_))));
        let dir = svc.volume_path("a");
        assert!(dir.join(VOLUME_DATA).is_dir());
        assert!(!VolumeMeta::read(&dir).unwrap().created_at.is_empty());
        assert_eq!(entries(&svc), ["a"]);
    }

    /// The directory decides whether a name is taken: one no row names is,
    /// and nothing of it is touched; a row whose directory is gone is not.
    #[tokio::test]
    async fn the_directory_decides_that_a_name_is_taken() {
        let (svc, _dir) = service().await;
        let v = svc
            .create("a", VolumeDriver::Local, HashMap::new(), HashMap::new())
            .await
            .unwrap();
        fs::write(v.mountpoint.join("f"), "x").unwrap();
        let before = fs::read(svc.volume_path("a").join(VOLUME_META)).unwrap();
        svc.db
            .conn()
            .call(|c| velarx_db::volumes::delete(c, "a"))
            .await
            .unwrap();
        assert!(matches!(
            svc.create("a", VolumeDriver::Local, HashMap::new(), HashMap::new())
                .await,
            Err(VolumeError::AlreadyExists(_))
        ));
        assert_eq!(fs::read_to_string(v.mountpoint.join("f")).unwrap(), "x");
        assert_eq!(
            fs::read(svc.volume_path("a").join(VOLUME_META)).unwrap(),
            before
        );
        assert_eq!(entries(&svc), ["a"]);

        // the row of a directory that is gone does not block
        fs::remove_dir_all(svc.volume_path("a")).unwrap();
        svc.store_volume(&v).await.unwrap();
        svc.create("a", VolumeDriver::Local, HashMap::new(), HashMap::new())
            .await
            .unwrap();
        assert!(svc.volume_path("a").join(VOLUME_DATA).is_dir());
    }

    /// A create that cannot move its directory into place (a file has the
    /// name) leaves nothing of its own.
    #[tokio::test]
    async fn a_create_that_cannot_place_its_directory_leaves_no_temporary() {
        let (svc, _dir) = service().await;
        // (the name of a build is no volume name)
        assert!(!valid_volume_name(".new-x"));
        fs::write(svc.volume_path("a"), "x").unwrap();
        assert!(matches!(
            svc.create("a", VolumeDriver::Local, HashMap::new(), HashMap::new())
                .await,
            Err(VolumeError::AlreadyExists(_))
        ));
        assert_eq!(entries(&svc), ["a"]);
    }

    /// A removal that dies after the directory is gone and before the row
    /// leaves the row alone.
    #[tokio::test]
    async fn a_removal_killed_before_its_row_leaves_a_row() {
        let (svc, _dir) = service().await;
        svc.create("a", VolumeDriver::Local, HashMap::new(), HashMap::new())
            .await
            .unwrap();
        ignore(&svc, "DELETE").await;
        svc.remove("a", false).await.unwrap();
        assert!(entries(&svc).is_empty());
        assert!(svc.get("a").await.is_ok());
    }

    /// What a create or a removal that died leaves does not stand in the
    /// way: a `.new-*` of a build, a volume whose `_data` is gone.
    #[tokio::test]
    async fn leftovers_of_a_killed_change_do_not_block() {
        let (svc, _dir) = service().await;
        fs::create_dir_all(svc.volume_path(".new-x").join(VOLUME_DATA)).unwrap();
        svc.create("a", VolumeDriver::Local, HashMap::new(), HashMap::new())
            .await
            .unwrap();
        fs::remove_dir(svc.volume_path("a").join(VOLUME_DATA)).unwrap();
        svc.remove("a", false).await.unwrap();
        assert!(matches!(svc.get("a").await, Err(VolumeError::NotFound(_))));
        assert_eq!(entries(&svc), [".new-x"]);
    }

    /// A state is written to the file, then to the row.
    #[tokio::test]
    async fn set_state_writes_the_file_and_the_row() {
        let (svc, _dir) = service().await;
        let v = svc
            .create("a", VolumeDriver::Local, HashMap::new(), HashMap::new())
            .await
            .unwrap();
        let mut state = v.state.clone();
        state.needs_copy_up = false;
        state.copied_up = true;
        svc.set_state("a", &state).await.unwrap();
        let meta = VolumeMeta::read(&svc.volume_path("a")).unwrap();
        assert_eq!(meta.state, state);
        assert_eq!(meta.created_at, v.created_at);
        assert_eq!(svc.get("a").await.unwrap().state, state);
        assert_eq!(entries(&svc), ["a"]);
    }

    #[tokio::test]
    async fn test_resolve_mounts() {
        let (svc, dir) = service().await;
        // A named volume that does not exist is created, once.
        let (cfg, created) = svc.resolve_mount_new(volume("vol:/d"), None).await.unwrap();
        assert!(created);
        assert_eq!(cfg.volume.as_deref(), Some("vol"));
        assert_eq!(
            cfg.source,
            svc.volume_path("vol").join(VOLUME_DATA).to_string_lossy()
        );
        let (_, created) = svc.resolve_mount_new(volume("vol:/d"), None).await.unwrap();
        assert!(!created);
        // `-v /path`: an anonymous volume.
        let (cfg, created) = svc
            .resolve_mount_new(volume("/anon"), Some("c"))
            .await
            .unwrap();
        assert!(created);
        let v = svc.get(cfg.volume.as_deref().unwrap()).await.unwrap();
        assert!(v.state.anonymous);
        assert_eq!(v.state.container.as_deref(), Some("c"));
        // A bind mount of something that is not there.
        let missing = dir.path().join("missing");
        let spec = volume(&format!("{}:/d", missing.display()));
        let e = svc.resolve_mount(spec).await.unwrap_err().to_string();
        assert!(e.contains("missing"), "{e}");
        let spec = volume(&format!("{}:/d", dir.path().display()));
        assert_eq!(
            svc.resolve_mount(spec).await.unwrap().source,
            dir.path().to_string_lossy()
        );
        // Removing a volume that is in use is refused without force.
        assert!(svc.users("vol").await.unwrap().is_empty());
    }

    #[test]
    fn overlay_volumes() {
        let m = MountSpec::parse_volume_arg("/src:/dst:O").unwrap();
        assert!(m.options.overlay && m.options.upperdir.is_none());
        let c = m.to_mount_config(Path::new("/v")).unwrap();
        assert_eq!(c.source, "/src");
        assert_eq!(
            c.overlay,
            Some(crate::container::OverlayMountConfig::default())
        );
        let m = MountSpec::parse_volume_arg("/src:/dst:O,upperdir=/u,workdir=/w").unwrap();
        let ov = m.to_mount_config(Path::new("/v")).unwrap().overlay.unwrap();
        assert_eq!(
            (ov.upperdir.as_deref(), ov.workdir.as_deref()),
            (Some("/u"), Some("/w"))
        );
        let named = MountSpec::parse_volume_arg("data:/dst:O").unwrap();
        assert_eq!(
            named.to_mount_config(Path::new("/v")).unwrap().source,
            "/v/data"
        );
        for bad in [
            "/src:/dst:O,upperdir=/u",
            "/src:/dst:O,workdir=/w",
            "/src:/dst:upperdir=/u,workdir=/w",
            "/src:/dst:O,upperdir=u,workdir=/w",
            "/src:/dst:O,z",
            "/src:/dst:O,U",
            "/src:/dst:O,idmap",
            "/dst:O",
        ] {
            assert!(MountSpec::parse_volume_arg(bad).is_err(), "{bad}");
        }
        // U goes to the directory of the sub path
        assert!(MountSpec::parse_mount_arg("type=volume,src=v,dst=/d,subpath=a,U").is_ok());
        let c = MountSpec::parse_mount_arg("type=volume,src=v,dst=/d,subpath=a/b")
            .unwrap()
            .to_mount_config(Path::new("/v"))
            .unwrap();
        assert_eq!(
            (c.subpath.as_deref(), c.subpath_root.as_deref()),
            (Some("a/b"), None)
        );
    }
}
