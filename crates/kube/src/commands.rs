// SPDX-License-Identifier: Apache-2.0
//! `play` and `down`: what the YAML makes of the engine's pods, volumes and
//! secrets, and how it is taken down, through the typed interface of the
//! engine ([`Engine`]).
//!
//! The work is in two parts around the confinement of the process.  What
//! reads files and decides what the play does ([`prepare`]: the YAML, the
//! secrets of the engine the documents refer to, the images that are built)
//! comes first; [`Prepared::writable`] says where the process needs to
//! make files (the host paths Kubernetes creates), and then [`play`] makes
//! the pods, which needs the engine's socket and those directories only.

use crate::engine::{Engine, Error, Result};
use crate::play::{self, ContainerPlan, HostPath, Plan, PodPlan};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsStr;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use velarx_proto::workload::VolumeSpec;
use velarx_registry::auth::RegistryAccess;

/// How long the containers of a pod that a play replaces or a down removes
/// have to obey their stop signal, as podman's default.
pub const STOP_TIMEOUT: u64 = 10;

/// What a play is asked.
#[derive(Debug, Default, Clone)]
pub struct PlayArgs {
    /// Pods of the same names are removed first
    pub replace: bool,
    pub start: bool,
    /// Build the images that have a directory in `context_dir` (none: those
    /// missing)
    pub build: Option<bool>,
    pub context_dir: PathBuf,
    pub tls_verify: bool,
    /// The n-th address to the n-th pod
    pub static_ips: Vec<String>,
    pub static_macs: Vec<String>,
    pub options: play::Options,
}

/// The credentials of the registries the pulls and the builds go to.
#[derive(Default)]
pub struct Access {
    /// `--creds` and `--cert-dir`
    pub fixed: RegistryAccess,
    /// `--authfile`: the entries of the endpoints of an image only go with
    /// its pull
    pub authfile: Option<velarx_registry::AuthConfig>,
}

/// What every pull and build of a play sends, resolved before the process
/// confines itself (reading the credentials may run a credential helper).
pub struct Resolved {
    /// What the pull of an image sends, or why that cannot be known
    pulls: BTreeMap<String, std::result::Result<RegistryAccess, String>>,
    /// What a build sends: the references of its Containerfile are not
    /// known here, so all of the entries
    build: std::result::Result<RegistryAccess, String>,
}

impl Access {
    /// What the pulls of the images of `prepared` and its builds send.
    pub async fn resolve(&self, engine: &Engine, prepared: &Prepared) -> Result<Resolved> {
        let mut pulls = BTreeMap::new();
        for image in prepared.images() {
            let mut access = self.fixed.clone();
            let resolved = match &self.authfile {
                Some(file) => {
                    let scopes = engine.credential_scopes(&image).await?;
                    file.export_for(&scopes).map(|auths| {
                        access.auths = auths;
                        access
                    })
                }
                None => Ok(access),
            };
            pulls.insert(image, resolved);
        }
        let mut access = self.fixed.clone();
        let build = match &self.authfile {
            Some(file) => file.export().map(|auths| {
                access.auths = auths;
                access
            }),
            None => Ok(access),
        };
        Ok(Resolved { pulls, build })
    }
}

impl Resolved {
    fn for_pull(&self, image: &str) -> Result<RegistryAccess> {
        match self.pulls.get(image) {
            Some(r) => r.clone().map_err(Error::new),
            None => Err(Error::new(format!("{image}: no credentials were resolved"))),
        }
    }

    fn for_build(&self) -> Result<RegistryAccess> {
        self.build.clone().map_err(Error::new)
    }
}

/// A play, decided: nothing is made yet.
pub struct Prepared {
    plan: Plan,
    args: PlayArgs,
    /// The images to build, by the directory of their context: opened now,
    /// what the engine builds from is this descriptor, never a path
    builds: BTreeMap<String, OwnedFd>,
}

/// The stored secrets the documents refer to.
struct Stored(HashMap<String, Vec<u8>>);

impl play::Sources for Stored {
    fn secret(&self, name: &str) -> Option<Vec<u8>> {
        self.0.get(name).cloned()
    }
}

/// The names of the secrets a YAML refers to.
fn secret_refs(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                match (k.as_str(), x) {
                    ("secretName", Value::String(n)) => out.push(n.clone()),
                    ("secretKeyRef" | "secretRef", r) => {
                        if let Some(n) = r.get("name").and_then(Value::as_str) {
                            out.push(n.to_string());
                        }
                    }
                    _ => secret_refs(x, out),
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|x| secret_refs(x, out)),
        _ => {}
    }
}

/// The directory of the build of `image` in `context`, as podman looks it
/// up: a directory named as the last part of the image's name, with a
/// Containerfile or a Dockerfile.  The directory is opened here, by the
/// process that was asked for it and with its rights: the engine is given
/// the descriptor (`context` is the directory the user named, links in it
/// followed as the user meant; the directory of the image is a directory,
/// not a link out of it).
pub fn build_dir(context: &Path, image: &str) -> Option<OwnedFd> {
    use rustix::fs::{statat, AtFlags};
    let last = image.rsplit('/').next().unwrap_or(image);
    let last = last.split('@').next().unwrap_or(last);
    let name = last.split(':').next().unwrap_or(last);
    if name.is_empty() || name == "." || name == ".." || name.contains('\0') {
        return None;
    }
    let root = std::fs::File::open(context).ok()?;
    let dir = velarx_base::walk::open_dir_at(root.as_fd(), OsStr::new(name)).ok()?;
    ["Containerfile", "Dockerfile"]
        .iter()
        .any(|f| statat(&dir, *f, AtFlags::SYMLINK_NOFOLLOW).is_ok())
        .then_some(dir)
}

/// podman's `staticIPs` and `staticMACs`: the address at index n goes to
/// the n-th pod, which must be on one bridge network; the pods after the
/// last get one picked (as podman, with a warning), and the addresses
/// beyond the pods are not used.
fn static_addresses(pods: &mut [PodPlan], ips: &[String], macs: &[String]) -> Result<()> {
    for (n, p) in pods.iter_mut().enumerate() {
        let (ip, mac) = (ips.get(n), macs.get(n));
        if ip.is_none() && !ips.is_empty() {
            eprintln!(
                "Warning: kube play: no more static ips left, the pod {} gets one picked",
                p.name
            );
        }
        if ip.is_none() && mac.is_none() {
            continue;
        }
        let what = if ip.is_some() {
            "static ip addresses"
        } else {
            "a static mac address"
        };
        let bridge = matches!(
            p.spec["netns"]["nsmode"].as_str(),
            None | Some("" | "bridge")
        );
        if !bridge {
            return Err(Error::new(format!(
                "{what} can only be set when the network mode is bridge"
            )));
        }
        if p.spec["Networks"].as_object().is_some_and(|n| n.len() > 1) {
            return Err(Error::new(format!(
                "cannot set {what} for more than one network"
            )));
        }
        if let Some(ip) = ip {
            p.spec["static_ip"] = json!(ip);
        }
        if let Some(mac) = mac {
            p.spec["static_mac"] = json!(mac);
        }
    }
    Ok(())
}

/// Whether `mac` is six pairs of hexadecimal digits with colons.
fn is_mac(mac: &str) -> bool {
    let parts: Vec<&str> = mac.split(':').collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Decide the play of `docs`: what the YAML names is checked, the secrets of
/// the engine it refers to are read, the images with a build directory are
/// picked.
pub async fn prepare(engine: &Engine, docs: &[Value], args: PlayArgs) -> Result<Prepared> {
    for ip in &args.static_ips {
        if ip.parse::<std::net::IpAddr>().is_err() {
            return Err(Error::new(format!("invalid IP address `{ip}`")));
        }
    }
    for mac in &args.static_macs {
        if !is_mac(mac) {
            return Err(Error::new(format!("invalid MAC address `{mac}`")));
        }
    }
    let warnings: Vec<String> = docs
        .iter()
        .flat_map(crate::validate::unknown_fields)
        .collect();
    if !warnings.is_empty() {
        return Err(Error::new(format!("validating {}", warnings.join("; "))));
    }
    // the stored secrets the YAML refers to
    let mut refs = Vec::new();
    docs.iter().for_each(|d| secret_refs(d, &mut refs));
    let mut stored = HashMap::new();
    for r in refs {
        if let Some(data) = engine.secret_data(&r).await? {
            stored.insert(r, data);
        }
    }
    let mut plan = play::plan(docs, &args.options, &Stored(stored)).map_err(Error::new)?;
    for w in &plan.warnings {
        eprintln!("Warning: kube play: {w}");
    }
    static_addresses(&mut plan.pods, &args.static_ips, &args.static_macs)?;
    let mut builds = BTreeMap::new();
    if args.build != Some(false) {
        for c in plan
            .pods
            .iter()
            .flat_map(|p| p.init_containers.iter().chain(&p.containers))
        {
            if builds.contains_key(&c.image) {
                continue;
            }
            let Some(dir) = build_dir(&args.context_dir, &c.image) else {
                continue;
            };
            if args.build == Some(true) || engine.image(&c.image).await?.is_none() {
                builds.insert(c.image.clone(), dir);
            }
        }
    }
    Ok(Prepared { plan, args, builds })
}

impl Prepared {
    /// The pods of the play, by name.
    pub fn pod_names(&self) -> Vec<String> {
        self.plan.pods.iter().map(|p| p.name.clone()).collect()
    }

    /// The images of the containers of the play.
    pub fn images(&self) -> BTreeSet<String> {
        self.plan
            .pods
            .iter()
            .flat_map(|p| p.init_containers.iter().chain(&p.containers))
            .map(|c| c.image.clone())
            .collect()
    }

    /// Check or make the host paths of the pods as their types say (as
    /// Kubernetes does).  Before the process confines itself: it may then
    /// make no file.
    pub fn make_host_paths(&self) -> Result<()> {
        self.plan
            .pods
            .iter()
            .flat_map(|p| &p.host_paths)
            .try_for_each(prepare_host_path)
    }
}

/// What a play made.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PlayReport {
    pub pods: Vec<PlayedPod>,
    /// The names of the volumes it made
    pub volumes: Vec<String>,
    /// The ids of the secrets it made
    pub secret_ids: Vec<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PlayedPod {
    pub id: String,
    pub containers: Vec<String>,
    pub init_containers: Vec<String>,
}

/// What a down removed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DownReport {
    /// The ids of the pods
    pub pods: Vec<String>,
    pub volumes: Vec<String>,
    /// The ids of the secrets
    pub secret_ids: Vec<String>,
}

/// Check or make a host path as its type says, as Kubernetes does.
fn prepare_host_path(h: &HostPath) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt};
    let p = Path::new(&h.path);
    let st = std::fs::metadata(p);
    let fail = |what: &str| Err(Error::new(format!("the hostPath {} {what}", h.path)));
    match (h.kind.as_str(), &st) {
        ("", _) => Ok(()),
        ("DirectoryOrCreate", Err(_)) => std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(p)
            .map_err(|e| Error::new(format!("cannot make the hostPath {}: {e}", h.path))),
        ("FileOrCreate", Err(_)) => make_host_file(p)
            .map_err(|e| Error::new(format!("cannot make the hostPath {}: {e}", h.path))),
        (_, Err(_)) => fail("does not exist"),
        ("Directory" | "DirectoryOrCreate", Ok(m)) if !m.is_dir() => fail("is not a directory"),
        ("File" | "FileOrCreate", Ok(m)) if !m.is_file() => fail("is not a file"),
        ("Socket", Ok(m)) if !m.file_type().is_socket() => fail("is not a socket"),
        ("CharDevice", Ok(m)) if !m.file_type().is_char_device() => {
            fail("is not a character device")
        }
        ("BlockDevice", Ok(m)) if !m.file_type().is_block_device() => fail("is not a block device"),
        _ => Ok(()),
    }
}

/// The file a `FileOrCreate` hostPath names, made when it is not there.  A play
/// that made it between the look at the path and here (two plays of one
/// YAML) leaves a file that is as good: only what is not a regular file is
/// an error.
fn make_host_file(p: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)
    {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if std::fs::metadata(p)?.is_file() {
                Ok(())
            } else {
                Err(e)
            }
        }
        Err(e) => Err(e),
    }
}

/// The files of a ConfigMap or Secret volume as a tar archive (the paths
/// were checked: relative, no `..`).
fn volume_archive(files: &[(String, Vec<u8>, u32)]) -> std::io::Result<Vec<u8>> {
    let mut tar = tar::Builder::new(Vec::new());
    let mut made: Vec<String> = Vec::new();
    for (rel, data, mode) in files {
        let mut dir = String::new();
        let parts: Vec<&str> = rel.split('/').collect();
        for part in &parts[..parts.len() - 1] {
            dir.push_str(part);
            dir.push('/');
            if !made.contains(&dir) {
                let mut h = tar::Header::new_gnu();
                h.set_entry_type(tar::EntryType::Directory);
                h.set_mode(0o755);
                h.set_size(0);
                tar.append_data(&mut h, &dir, std::io::empty())?;
                made.push(dir.clone());
            }
        }
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_mode(*mode);
        h.set_size(data.len() as u64);
        tar.append_data(&mut h, rel, &data[..])?;
    }
    tar.into_inner()
}

/// Pull the image of a container as its policy says.
async fn ensure_image(
    engine: &Engine,
    image: &str,
    policy: &str,
    tls_verify: bool,
    access: &Resolved,
) -> Result<()> {
    let local = engine.image(image).await?.is_some();
    match (policy, local) {
        ("Never", false) => Err(Error::new(format!(
            "{image}: image not known (imagePullPolicy Never)"
        ))),
        ("IfNotPresent" | "Never", true) => Ok(()),
        _ => {
            let pulled = async {
                let access = access.for_pull(image)?;
                engine.image_pull(image, tls_verify, &access).await
            }
            .await;
            match pulled {
                Ok(()) => Ok(()),
                // as podman: Always with a local image and no registry runs it
                Err(_) if local => Ok(()),
                Err(e) => Err(Error::new(format!("pull {image}: {e}"))),
            }
        }
    }
}

/// `runAsNonRoot`, as the kubelet checks it: the user of the container
/// (its spec's, else its image's) is a number other than 0.
async fn check_non_root(engine: &Engine, c: &ContainerPlan) -> Result<()> {
    let user = match c.spec["user"].as_str().filter(|u| !u.is_empty()) {
        Some(u) => u.to_string(),
        None => match engine.image(&c.image).await? {
            Some(rec) => rec.config.user,
            None => return Err(Error::new(format!("{}: image not known", c.image))),
        },
    };
    let uid = user.split(':').next().unwrap_or_default();
    match uid.parse::<u32>() {
        Ok(n) if n != 0 => Ok(()),
        Err(_) if !uid.is_empty() => Err(Error::new(format!(
            "the container {} has runAsNonRoot and its image has the non-numeric user {uid}: \
             it cannot be verified to be no root",
            c.name
        ))),
        _ => Err(Error::new(format!(
            "the container {} has runAsNonRoot and will run as root",
            c.name
        ))),
    }
}

/// Make what the YAML describes.
pub async fn play(engine: &Engine, prepared: &Prepared, access: &Resolved) -> Result<PlayReport> {
    let Prepared { plan, args, builds } = prepared;
    let replace = args.replace;
    for p in &plan.pods {
        if engine.pod(&p.name).await?.is_some() {
            if !replace {
                return Err(Error::new(format!("{}: pod already exists", p.name)));
            }
            engine.pod_remove(&p.name, STOP_TIMEOUT).await?;
        }
    }
    let mut report = PlayReport::default();
    for (name, data) in &plan.secrets {
        report
            .secret_ids
            .push(engine.secret_create(name, data.clone(), replace).await?);
    }
    for v in &plan.volumes {
        if engine.volume(&v.name).await?.is_none() {
            let spec = VolumeSpec {
                name: v.name.clone(),
                labels: v.labels.clone(),
                ..Default::default()
            };
            engine.volume_create(&spec).await?;
            report.volumes.push(v.name.clone());
        }
        if let Some(files) = &v.files {
            let archive = volume_archive(files)
                .map_err(|e| Error::new(format!("the files of the volume {}: {e}", v.name)))?;
            engine
                .volume_import(&v.name, archive)
                .await
                .map_err(|e| Error::new(format!("the files of the volume {}: {e}", v.name)))?;
        }
    }
    for p in &plan.pods {
        // (the digests of the images in the YAML are typed at the play, as
        // those of a `run`)
        let digests = velarx_proto::request::typed_digests(
            p.init_containers
                .iter()
                .chain(&p.containers)
                .map(|c| c.image.as_str()),
        );
        for c in p.init_containers.iter().chain(&p.containers) {
            match builds.get(&c.image) {
                Some(dir) => {
                    engine
                        .image_build(dir.as_fd(), &c.image, args.tls_verify, &access.for_build()?)
                        .await
                        .map_err(|e| Error::new(format!("build {}: {e}", c.image)))?;
                }
                None => {
                    ensure_image(engine, &c.image, &c.pull_policy, args.tls_verify, access).await?
                }
            }
            if c.run_as_non_root {
                check_non_root(engine, c).await?;
            }
        }
        if !p.init_containers.is_empty() && !args.start {
            return Err(Error::new(
                "init containers run when the play starts the pod: --start=false is not supported with them",
            ));
        }
        let generator = serde_json::from_value(p.spec.clone())
            .map_err(|e| Error::new(format!("the pod {}: {e}", p.name)))?;
        let pod_spec = velarx_proto::podgen::spec_of(generator).map_err(|e| {
            Error::new(match e {
                velarx_proto::podgen::SpecError::Invalid(m)
                | velarx_proto::podgen::SpecError::NotImplemented(m) => m,
            })
        })?;
        let pod_id = engine
            .pod_create(serde_json::to_vec(&pod_spec).map_err(|e| Error::new(e.to_string()))?)
            .await?;
        match populate(engine, p, &pod_id, args.start, &digests).await {
            Ok((init_containers, containers)) => report.pods.push(PlayedPod {
                id: pod_id,
                containers,
                init_containers,
            }),
            Err(e) => {
                // what this play made of the pod goes
                let _ = engine.pod_remove(&pod_id, STOP_TIMEOUT).await;
                return Err(e);
            }
        }
    }
    Ok(report)
}

/// The containers of a pod, made and (with `start`) started: the ids of its
/// init containers, which ran first, and of the others.
async fn populate(
    engine: &Engine,
    p: &PodPlan,
    pod_id: &str,
    start: bool,
    digests: &[String],
) -> Result<(Vec<String>, Vec<String>)> {
    // the init containers first, one after the other to their end
    // (podman's `once`: removed once they succeeded)
    let mut init_ids = Vec::new();
    for c in &p.init_containers {
        let mut spec = c.spec.clone();
        spec["pod"] = json!(pod_id);
        let id = engine.container_create(&spec).await?;
        engine.pod_start(pod_id, digests).await?;
        let code = engine.container_wait(&id).await?;
        if code != 0 {
            return Err(Error::new(format!(
                "the init container {} exited with {code}",
                c.name
            )));
        }
        engine.container_remove(&id).await?;
        init_ids.push(id);
    }
    let mut ids = Vec::new();
    for c in &p.containers {
        let mut spec = c.spec.clone();
        spec["pod"] = json!(pod_id);
        ids.push(engine.container_create(&spec).await?);
    }
    if start {
        engine.pod_start(pod_id, digests).await?;
    }
    Ok((init_ids, ids))
}

/// Remove the pods and the secrets of the documents (and with `force` their
/// volumes).
pub async fn down(engine: &Engine, docs: &[Value], force: bool) -> Result<DownReport> {
    let mut report = DownReport::default();
    for name in play::pod_names(docs) {
        let Some(pod) = engine.pod(&name).await? else {
            continue;
        };
        engine.pod_remove(&name, STOP_TIMEOUT).await?;
        report.pods.push(pod.id);
    }
    // the secrets the documents made go too, as podman's (one that is gone
    // already is not told)
    for name in play::secret_names(docs) {
        if let Some(secret) = engine.secret(&name).await? {
            if engine.secret_remove(&name).await.is_ok() {
                report.secret_ids.push(secret.id);
            }
        }
    }
    if force {
        let mut names = play::volume_names(docs);
        names.extend(play::file_volume_names(docs));
        for v in names {
            if engine.volume_remove(&v).await.is_ok() {
                report.volumes.push(v);
            }
        }
    }
    Ok(report)
}

/// The images the containers of `docs` name.
pub fn images(docs: &[Value]) -> Vec<String> {
    play::container_images(docs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pods(n: usize, networks: &[&str]) -> Vec<PodPlan> {
        let yaml: String = (0..n)
            .map(|i| {
                format!(
                    "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p{i}\nspec:\n  containers:\n  - name: c\n    image: img\n---\n"
                )
            })
            .collect();
        let docs = crate::yaml::parse_documents(&yaml).unwrap();
        let opts = play::Options {
            networks: networks.iter().map(|n| n.to_string()).collect(),
            ..Default::default()
        };
        play::plan(&docs, &opts, &Stored(Default::default()))
            .unwrap()
            .pods
    }

    /// Plays that make one FileOrCreate path at the same time all find
    /// the file; a path that is not a file stays an error.
    #[test]
    fn plays_that_make_one_host_file_together_all_succeed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let (path, barrier) = (path.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    make_host_file(&path)
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap().unwrap();
        }
        assert!(path.is_file());
        make_host_file(&path).unwrap();
        let sub = dir.path().join("d");
        std::fs::create_dir(&sub).unwrap();
        assert!(make_host_file(&sub).is_err());
    }

    #[test]
    fn static_addresses_go_to_the_pods_in_order() {
        let mut p = pods(3, &["n1"]);
        static_addresses(
            &mut p,
            &["10.0.0.1".into(), "10.0.0.2".into()],
            &["02:00:00:00:00:01".into()],
        )
        .unwrap();
        assert_eq!(p[0].spec["static_ip"], "10.0.0.1");
        assert_eq!(p[0].spec["static_mac"], "02:00:00:00:00:01");
        assert_eq!(p[1].spec["static_ip"], "10.0.0.2");
        assert!(p[1].spec.get("static_mac").is_none());
        // the third gets one picked
        assert!(p[2].spec.get("static_ip").is_none());
        // more addresses than pods: the others are not used
        let mut p = pods(1, &["n1"]);
        static_addresses(&mut p, &["10.0.0.1".into(), "10.0.0.2".into()], &[]).unwrap();
        assert_eq!(p[0].spec["static_ip"], "10.0.0.1");
        // a bridge network, one
        let mut p = pods(1, &["host"]);
        assert!(static_addresses(&mut p, &["10.0.0.1".into()], &[]).is_err());
        let mut p = pods(1, &["n1", "n2"]);
        assert!(static_addresses(&mut p, &[], &["02:00:00:00:00:01".into()]).is_err());
    }

    /// The identity of the directory a descriptor is.
    fn same(fd: &OwnedFd, path: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        let a = rustix::fs::fstat(fd).unwrap();
        let b = std::fs::metadata(path).unwrap();
        (a.st_dev as u64, a.st_ino as u64) == (b.dev(), b.ino())
    }

    #[test]
    fn the_build_directories_of_the_images_of_a_yaml() {
        let dir = tempfile::tempdir().unwrap();
        for d in ["web", "db", "other"] {
            std::fs::create_dir(dir.path().join(d)).unwrap();
        }
        std::fs::write(dir.path().join("web/Containerfile"), "FROM x\n").unwrap();
        std::fs::write(dir.path().join("db/Dockerfile"), "FROM x\n").unwrap();
        let web = build_dir(dir.path(), "localhost/web:1").unwrap();
        assert!(same(&web, &dir.path().join("web")));
        let db = build_dir(dir.path(), "quay.io/x/db@sha256:00").unwrap();
        assert!(same(&db, &dir.path().join("db")));
        // a directory with no Containerfile, one that is not there, a name
        // that leaves the directory
        assert!(build_dir(dir.path(), "other").is_none());
        assert!(build_dir(dir.path(), "missing").is_none());
        assert!(build_dir(dir.path(), "../x").is_none());
    }

    /// The directory the user names may be a link (it is followed: the user
    /// meant what it points to); the directory of an image is not (it would
    /// be a way out of the context), and the descriptor stays the directory
    /// it was opened as when the names change.
    #[test]
    fn the_context_may_be_a_link_the_image_directory_may_not() {
        let base = tempfile::tempdir().unwrap();
        let real = base.path().join("real");
        std::fs::create_dir_all(real.join("web")).unwrap();
        std::fs::write(real.join("web/Containerfile"), "FROM x\n").unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let web = build_dir(&link, "web").unwrap();
        assert!(same(&web, &real.join("web")));
        // the image's directory is a link: refused, as a link to a
        // Containerfile of a place outside is
        let out = base.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("Containerfile"), "FROM x\n").unwrap();
        std::os::unix::fs::symlink(&out, real.join("evil")).unwrap();
        assert!(build_dir(&real, "evil").is_none());
        // the names change after the open: the descriptor is the same
        // directory
        let moved = base.path().join("moved");
        std::fs::rename(real.join("web"), &moved).unwrap();
        std::fs::create_dir(real.join("web")).unwrap();
        assert!(same(&web, &moved));
        assert!(!same(&web, &real.join("web")));
    }

    /// Names that a shell or a path would trip on are names.
    #[test]
    fn odd_names_are_directories_like_the_others() {
        use std::os::unix::ffi::OsStrExt;
        let base = tempfile::tempdir().unwrap();
        for name in ["with space", "-dash", "dot.dot", "caf\u{e9}", "a\nb", "x*y"] {
            let d = base.path().join(name);
            std::fs::create_dir(&d).unwrap();
            std::fs::write(d.join("Dockerfile"), "FROM x\n").unwrap();
            let image = format!("localhost/{name}:1");
            let fd = build_dir(base.path(), &image).unwrap_or_else(|| panic!("{name:?}"));
            assert!(same(&fd, &d), "{name:?}");
        }
        // (a name that is not UTF-8 is not an image name)
        let raw = base.path().join(std::ffi::OsStr::from_bytes(b"\xff\xfe"));
        std::fs::create_dir(&raw).unwrap();
        assert!(build_dir(base.path(), "\u{fffd}\u{fffd}").is_none());
        // a directory too: the context itself that is no directory
        let file = base.path().join("file");
        std::fs::write(&file, "x").unwrap();
        assert!(build_dir(&file, "web").is_none());
    }

    #[test]
    fn the_files_of_a_volume_are_a_tar_with_their_directories() {
        let tar = volume_archive(&[
            ("a.conf".into(), b"x".to_vec(), 0o644),
            ("d/e/b.conf".into(), b"yy".to_vec(), 0o600),
        ])
        .unwrap();
        let mut names: Vec<(String, u32, u64)> = tar::Archive::new(&tar[..])
            .entries()
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (
                    e.path().unwrap().display().to_string(),
                    e.header().mode().unwrap(),
                    e.header().size().unwrap(),
                )
            })
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                ("a.conf".to_string(), 0o644, 1),
                ("d/".to_string(), 0o755, 0),
                ("d/e/".to_string(), 0o755, 0),
                ("d/e/b.conf".to_string(), 0o600, 2),
            ]
        );
    }

    #[test]
    fn the_secrets_a_yaml_refers_to() {
        let docs = crate::yaml::parse_documents(
            "kind: Pod\nspec:\n  volumes:\n  - secret:\n      secretName: s1\n  containers:\n  - envFrom:\n    - secretRef:\n        name: s2\n    env:\n    - valueFrom:\n        secretKeyRef:\n          name: s3\n          key: k\n",
        )
        .unwrap();
        let mut refs = Vec::new();
        docs.iter().for_each(|d| secret_refs(d, &mut refs));
        refs.sort();
        assert_eq!(refs, ["s1", "s2", "s3"]);
        assert!(is_mac("02:00:00:00:00:01"));
        assert!(!is_mac("02:00:00:00:01"));
        assert!(!is_mac("zz:00:00:00:00:01"));
    }

    #[test]
    fn host_paths_are_made_or_checked_as_their_type_says() {
        let dir = tempfile::tempdir().unwrap();
        let host = |p: &Path, kind: &str| HostPath {
            path: p.to_string_lossy().into_owned(),
            kind: kind.into(),
        };
        let d = dir.path().join("a/b");
        assert!(prepare_host_path(&host(&d, "Directory")).is_err());
        prepare_host_path(&host(&d, "DirectoryOrCreate")).unwrap();
        assert!(d.is_dir());
        let f = dir.path().join("f");
        prepare_host_path(&host(&f, "FileOrCreate")).unwrap();
        assert!(f.is_file());
        assert!(prepare_host_path(&host(&f, "Directory")).is_err());
        assert!(prepare_host_path(&host(&d, "File")).is_err());
        prepare_host_path(&host(&d, "")).unwrap();
    }
}
