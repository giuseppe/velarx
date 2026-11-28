// SPDX-License-Identifier: Apache-2.0
//! The chain of trust of a container whose image was named by a digest
//! (`NAME@sha256:D`): the digest the user typed is the root, and nothing the
//! container is made of is taken on trust from a row of the store.
//!
//! ```text
//! D (typed) -> [index] -> platform manifest -> configuration blob
//!                                           -> layers' EROFS digests -> kernel
//! ```
//!
//! Every link is a hash of bytes the store keeps, compared with the digest
//! the link before it names: the manifest (or the index it was chosen from)
//! with `D`, the configuration with the digest of the manifest, the layers
//! with the manifest's.  The digests the monitor holds the layer images
//! against come out of the manifest so verified (`seal::start_lists`), and the
//! settings of the container that the image decided are held against the
//! configuration so verified ([`check_taken`]).

use super::*;
use crate::container::{ContainerConfig, TakenSettings};
use velarx_db::LayerRecord;
use velarx_types::digest::Digest;
use velarx_wire::chain::Chain;

/// How many indexes are followed from the digest to the manifest: as many as
/// the resolution of a pull follows.
const MAX_INDEXES: usize = 2;

/// How many entries of an index are looked at for a nested index.
const MAX_ENTRIES: usize = 1024;

/// A stored image, hashed back to the digest of its reference.
pub struct Verified {
    pub manifest: OciManifest,
    pub config: OciConfig,
}

/// The digests an index names, to look for the indexes among them.
pub fn index_entries(index: &str) -> Vec<Digest> {
    serde_json::from_str::<serde_json::Value>(index)
        .ok()
        .and_then(|v| {
            v.get("manifests").and_then(|m| m.as_array()).map(|a| {
                a.iter()
                    .filter_map(|m| m.get("digest").and_then(|d| d.as_str()?.parse().ok()))
                    .collect()
            })
        })
        .unwrap_or_default()
}

/// The os, architecture and variant an index states for a manifest it lists.
type Platform = (Option<String>, Option<String>, Option<String>);

/// The indexes from the one named by the reference to the one that lists the
/// manifest: each one's digest and size, for the debug log of the chain.
type IndexPath = Vec<(Digest, usize)>;

/// Whether the index `digest` (or one it names, `depth` levels deep) lists
/// `target`, and for which platform.  The bytes of each index are hashed
/// against the digest that named it.  The entry must be the first of the
/// index for its platform: the one a pull for that platform takes.
fn lists(
    digest: &Digest,
    target: &Digest,
    indexes: &HashMap<Digest, String>,
    depth: usize,
    refuse: &dyn Fn(String) -> ImageError,
    chain: &Chain,
) -> ImageResult<Option<(Platform, IndexPath)>> {
    let Some(bytes) = indexes.get(digest) else {
        return Ok(None);
    };
    let have = Digest::of(digest.alg(), bytes.as_bytes());
    if have != *digest {
        chain.broken(|| ("index".into(), digest.to_string(), have.to_string()));
        return Err(refuse(format!(
            "the stored index {digest} hashes to {have}: the store was modified; pull the image again"
        )));
    }
    let value: serde_json::Value = serde_json::from_str(bytes).map_err(|e| {
        chain.broken(|| (format!("{digest} index"), "json".into(), "invalid".into()));
        refuse(format!("the stored index {digest} is not valid: {e}"))
    })?;
    let entries = value
        .get("manifests")
        .and_then(|m| m.as_array())
        .cloned()
        .unwrap_or_default();
    let platform = |m: &serde_json::Value| -> Platform {
        let field = |k: &str| {
            m.get("platform")
                .and_then(|p| p.get(k))
                .and_then(|v| v.as_str())
                .map(str::to_string)
        };
        (field("os"), field("architecture"), field("variant"))
    };
    let wanted = target.to_string();
    if let Some(at) = entries
        .iter()
        .position(|m| m.get("digest").and_then(|d| d.as_str()) == Some(wanted.as_str()))
    {
        let found = platform(&entries[at]);
        if let Some(first) = entries[..at]
            .iter()
            .find(|m| found.0.is_some() && platform(m) == found)
        {
            let first = first.get("digest").and_then(|d| d.as_str()).unwrap_or("?");
            chain.broken(|| {
                (
                    format!("{digest} index"),
                    target.to_string(),
                    first.to_string(),
                )
            });
            return Err(refuse(format!(
                "the index {digest} lists {first} first for the platform of the stored manifest {target}: the store was modified; pull the image again"
            )));
        }
        return Ok(Some((found, vec![(*digest, bytes.len())])));
    }
    if depth + 1 < MAX_INDEXES {
        for m in entries.iter().take(MAX_ENTRIES) {
            if let Some(d) = m
                .get("digest")
                .and_then(|d| d.as_str()?.parse::<Digest>().ok())
            {
                if let Some((found, mut path)) =
                    lists(&d, target, indexes, depth + 1, refuse, chain)?
                {
                    path.insert(0, (*digest, bytes.len()));
                    return Ok(Some((found, path)));
                }
            }
        }
    }
    Ok(None)
}

/// The platform an index states, as `os/arch[/variant]`.
fn show_platform((os, arch, variant): &Platform) -> String {
    let mut text = format!(
        "{}/{}",
        os.as_deref().unwrap_or("?"),
        arch.as_deref().unwrap_or("?")
    );
    if let Some(v) = variant {
        text.push('/');
        text.push_str(v);
    }
    text
}

/// How many indexes the chain from `root` to the stored manifest `have`
/// goes through, for the number of its links (the bytes are not hashed:
/// [`verify`] does that).  One if the store does not say.
pub fn index_links(root: &Digest, have: &Digest, indexes: &HashMap<Digest, String>) -> usize {
    fn depth(
        digest: &Digest,
        target: &Digest,
        indexes: &HashMap<Digest, String>,
        level: usize,
    ) -> Option<usize> {
        let entries = index_entries(indexes.get(digest)?);
        if entries.iter().any(|d| d == target) {
            return Some(1);
        }
        if level + 1 >= MAX_INDEXES {
            return None;
        }
        entries
            .iter()
            .find_map(|d| depth(d, target, indexes, level + 1).map(|n| n + 1))
    }
    if root == have {
        0
    } else {
        depth(root, have, indexes, 0).unwrap_or(1)
    }
}

/// The links of the chain of a container's root file system or of an image
/// mounted in it: the root of trust, the indexes, the configuration,
/// `settings` (what the container took from the configuration, and the
/// process of its spec), the annotation of each layer, the measure of each
/// layer by the monitor, the overlay.
pub fn links(indexes: usize, settings: usize, layers: usize) -> usize {
    1 + indexes + 1 + settings + layers + layers + 1
}

/// The links of the chain of an image that is not named by a digest, the
/// container made from a tag: the root of trust (the digest the database
/// records for the image), the annotations, the measures, the overlay.
pub fn links_of_tag(layers: usize) -> usize {
    1 + layers + layers + 1
}

impl ImageService {
    /// [`verify`] the stored `image` without a word in the log (the check
    /// of a create; the start's has a chain).
    pub async fn verify_pinned(
        &self,
        reference: &str,
        root: &Digest,
        why: &str,
        image: &ImageRecord,
        layers: &[LayerRecord],
    ) -> ImageResult<Verified> {
        let indexes = self.pinned_indexes(root, image).await?;
        verify(reference, root, why, image, layers, &indexes, &Chain::off())
    }

    /// The indexes [`verify`] may need to go from `root` to the stored
    /// `image`, from the store (their bytes are hashed by `verify`).  The
    /// common case, a manifest that is the digest itself, reads nothing.
    pub async fn pinned_indexes(
        &self,
        root: &Digest,
        image: &ImageRecord,
    ) -> ImageResult<HashMap<Digest, String>> {
        let mut indexes = HashMap::new();
        if Digest::of(root.alg(), image.manifest.as_bytes()) != *root {
            // (level by level, as deep as a pull follows indexes)
            let mut level = vec![*root];
            for _ in 0..MAX_INDEXES {
                let mut next = Vec::new();
                for d in level {
                    if indexes.contains_key(&d) {
                        continue;
                    }
                    if let Some(bytes) = self.db.index(&d).await? {
                        next.extend(index_entries(&bytes).into_iter().take(MAX_ENTRIES));
                        indexes.insert(d, bytes);
                    }
                }
                level = next;
            }
        }
        Ok(indexes)
    }
}

/// The architecture as the platform of an index spells it.
fn arch(a: &str) -> &str {
    match a {
        "x86_64" | "x86-64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

/// Hash the stored image back to `root`, the digest of the reference
/// `reference` (`ALGORITHM:<hex>`): the manifest is `root`, or `root` is an
/// index (of `indexes`, by digest) that lists it for the platform of the
/// image; the configuration is the one the manifest names; the layers are
/// the manifest's.  `why` is the option that asks for it, for the errors.
/// Nothing is read from the rows but the bytes and the algorithm of the
/// manifest digest: it says which hash of the manifest an index is to list
/// (and which digest to ask for in an error), so a row that lies about it
/// fails the check; the id and the digests themselves are not looked at.
/// The debug log has a link of `chain` for each
/// comparison that held, and says the one that did not.
pub fn verify(
    reference: &str,
    root: &Digest,
    why: &str,
    image: &ImageRecord,
    layers: &[LayerRecord],
    indexes: &HashMap<Digest, String>,
    chain: &Chain,
) -> ImageResult<Verified> {
    verify_links(reference, root, why, image, layers, indexes, chain)
        .inspect_err(|_| chain.broken(|| ("manifest".into(), root.to_string(), "error".into())))
}

fn verify_links(
    reference: &str,
    root: &Digest,
    why: &str,
    image: &ImageRecord,
    layers: &[LayerRecord],
    indexes: &HashMap<Digest, String>,
    chain: &Chain,
) -> ImageResult<Verified> {
    let short = &image.id[..image.id.len().min(12)];
    let refuse = |detail: String| {
        ImageError::Invalid(format!("{reference}: image {short}: {detail} ({why})"))
    };
    if !indexes.contains_key(root) && root.alg() != image.manifest_digest.alg() {
        chain.broken(|| {
            (
                "root".into(),
                image.manifest_digest.to_string(),
                root.to_string(),
            )
        });
        return Err(refuse(format!(
            "the image is named by {}, not by a {} digest: pass that digest",
            image.manifest_digest,
            root.alg()
        )));
    }
    // (the manifest an index lists is hashed as the index lists it)
    let have_alg = match indexes.contains_key(root) {
        true => image.manifest_digest.alg(),
        false => root.alg(),
    };
    let have = Digest::of(have_alg, image.manifest.as_bytes());
    let platform: Option<Platform> = if have == *root {
        None
    } else {
        match lists(root, &have, indexes, 0, &refuse, chain)? {
            Some((p, path)) => {
                for (n, (index, _)) in path.iter().enumerate() {
                    chain.link(|| match path.get(n + 1) {
                        Some((next, _)) => format!("{index} index -> {next} index"),
                        None => format!("{index} index -> {have} manifest"),
                    });
                    chain.add(|| path.get(n + 1).map_or(have, |(d, _)| *d).to_string());
                }
                Some(p)
            }
            None if indexes.contains_key(root) => {
                chain.broken(|| (format!("{root} index"), have.to_string(), "none".into()));
                return Err(refuse(format!(
                    "the stored manifest hashes to {have}, which the index {root} of the reference does not list: the store was modified; pull the image again"
                )));
            }
            None => {
                chain.broken(|| ("manifest".into(), root.to_string(), have.to_string()));
                return Err(refuse(format!(
                    "the stored manifest hashes to {have}, not {root}, the digest of the reference (and the store has no index {root}): the store was modified; pull the image again"
                )));
            }
        }
    };
    let manifest: OciManifest = serde_json::from_str(&image.manifest).map_err(|e| {
        chain.broken(|| (format!("{have} manifest"), "json".into(), "invalid".into()));
        refuse(format!("the stored manifest is not valid: {e}"))
    })?;
    let config_have = Digest::of(manifest.config.digest.alg(), image.config.as_bytes());
    if config_have != manifest.config.digest || image.config.len() as i64 != manifest.config.size {
        chain.broken(|| match config_have == manifest.config.digest {
            true => (
                "config size".into(),
                manifest.config.size.to_string(),
                image.config.len().to_string(),
            ),
            false => (
                "config".into(),
                manifest.config.digest.to_string(),
                config_have.to_string(),
            ),
        });
        return Err(refuse(format!(
            "the stored configuration hashes to {config_have} ({} bytes), the manifest says {} ({} bytes): the store was modified; pull the image again",
            image.config.len(),
            manifest.config.digest,
            manifest.config.size
        )));
    }
    let config: OciConfig = serde_json::from_str(&image.config).map_err(|e| {
        chain.broken(|| {
            (
                format!("{config_have} config"),
                "json".into(),
                "invalid".into(),
            )
        });
        refuse(format!("the stored configuration is not valid: {e}"))
    })?;
    if let Some((os, architecture, variant)) = platform.clone() {
        // (the variant is not a field of the configuration this engine reads)
        #[derive(serde::Deserialize)]
        struct Variant {
            #[serde(default)]
            variant: Option<String>,
        }
        let own_variant = serde_json::from_str::<Variant>(&image.config)
            .ok()
            .and_then(|v| v.variant);
        let differs = |stated: &Option<String>, own: &str, f: fn(&str) -> &str| {
            stated.as_deref().is_some_and(|s| f(s) != f(own))
        };
        if differs(&os, &config.os, |s| s)
            || differs(&architecture, &config.architecture, arch)
            || own_variant
                .as_deref()
                .is_some_and(|own| differs(&variant, own, |s| s))
        {
            let show = |os: &str, arch: &str, variant: Option<&str>| match variant {
                Some(v) => format!("{os}/{arch}/{v}"),
                None => format!("{os}/{arch}"),
            };
            let stated = show_platform(&(os, architecture, variant));
            let own = show(&config.os, &config.architecture, own_variant.as_deref());
            chain.broken(|| {
                (
                    format!("{config_have} config platform"),
                    stated.clone(),
                    own.clone(),
                )
            });
            return Err(refuse(format!(
                "the index {root} lists the manifest for {stated}, the configuration is of {own}"
            )));
        }
    }
    chain.link(|| format!("{have} manifest -> {config_have} config"));
    chain.add(|| config_have.to_string());
    if let Some(e) = layers_differ(&manifest, layers, chain) {
        return Err(refuse(e));
    }
    if config.rootfs.diff_ids.len() != manifest.layers.len() {
        chain.broken(|| {
            (
                "diff ids".into(),
                manifest.layers.len().to_string(),
                config.rootfs.diff_ids.len().to_string(),
            )
        });
        return Err(refuse(format!(
            "the configuration has {} diff ids for the {} layers of the manifest",
            config.rootfs.diff_ids.len(),
            manifest.layers.len()
        )));
    }
    for (i, (diff_id, layer)) in config.rootfs.diff_ids.iter().zip(layers).enumerate() {
        // (the recorded diff id of the algorithm of the configuration's: a
        // layer shared by images of both has one of each, a layer recorded
        // with one only was never checked against the other)
        let recorded = layer
            .diff_id_in(diff_id.alg())
            .or(layer.diff_id.as_ref().or(layer.other_diff_id.as_ref()));
        match recorded {
            Some(recorded) if recorded != diff_id => {
                chain.broken(|| {
                    (
                        format!("layer {} diff", i + 1),
                        diff_id.to_string(),
                        recorded.to_string(),
                    )
                });
                return Err(refuse(format!(
                    "layer {} of {} ({}): its diff id is recorded as {recorded}, the configuration says {diff_id}: the store was modified",
                    i + 1,
                    layers.len(),
                    layer.key
                )));
            }
            _ => {}
        }
    }
    Ok(Verified { manifest, config })
}

/// Whether the layers of the image, `layers`, are not those of `manifest`,
/// in its order: the error, with the link that broke said by `chain`.
pub fn layers_differ(
    manifest: &OciManifest,
    layers: &[LayerRecord],
    chain: &Chain,
) -> Option<String> {
    let error = || {
        "the layers of the image are not those of its manifest: the store was modified; pull the image again".to_string()
    };
    if manifest.layers.len() != layers.len() {
        chain.broken(|| {
            (
                "layers".into(),
                manifest.layers.len().to_string(),
                layers.len().to_string(),
            )
        });
        return Some(error());
    }
    let (i, (m, l)) = manifest
        .layers
        .iter()
        .zip(layers)
        .enumerate()
        .find(|(_, (m, l))| !l.key.stands_for(m))?;
    chain.broken(|| {
        (
            format!("layer {} blob", i + 1),
            m.digest.to_string(),
            l.key.to_string(),
        )
    });
    Some(error())
}

/// The working directory the image gives.
fn image_workdir(image: &OciConfig) -> String {
    match image.config.working_dir.as_str() {
        "" => "/".to_string(),
        dir => dir.to_string(),
    }
}

fn volume_target(path: &str) -> &str {
    match path.trim_end_matches('/') {
        "" => "/",
        p => p,
    }
}

/// What `config`, the settings of a container just made, has from the
/// configuration of its image `image` as the image gave it.
pub fn taken_of(image: &OciConfig, config: &ContainerConfig) -> TakenSettings {
    let img = &image.config;
    let same = |own: &[String], theirs: &Option<Vec<String>>| {
        theirs.clone().filter(|t| t.as_slice() == own)
    };
    TakenSettings {
        entrypoint: same(
            &config.entrypoint,
            &Some(img.entrypoint.clone().unwrap_or_default()),
        ),
        cmd: same(&config.command, &Some(img.cmd.clone().unwrap_or_default())),
        env: img
            .env
            .iter()
            .filter(|e| config.env.contains(e))
            .cloned()
            .collect(),
        user: Some(img.user.clone()).filter(|u| *u == config.user),
        working_dir: Some(image_workdir(image)).filter(|d| *d == config.working_dir),
        stop_signal: Some(img.stop_signal.clone())
            .filter(|s| !s.is_empty() && *s == config.stop_signal),
        healthcheck: img
            .healthcheck
            .as_ref()
            .map(|h| h.test.clone())
            .filter(|t| config.healthcheck.as_ref().is_some_and(|h| h.test == *t)),
        volumes: img
            .volumes
            .keys()
            .filter(|v| {
                config
                    .mounts
                    .iter()
                    .any(|m| volume_target(&m.target) == volume_target(v))
            })
            .cloned()
            .collect(),
    }
}

/// Whether the settings `config` of a container have what `taken` says the
/// image gave, and whether that is what the configuration of the image,
/// `image` (hashed), says: the record of what was taken and the settings
/// both held against the bytes.
pub fn check_taken(
    reference: &str,
    why: &str,
    taken: &TakenSettings,
    image: &OciConfig,
    config: &ContainerConfig,
    chain: &Chain,
) -> ImageResult<()> {
    let img = &image.config;
    let refuse = |setting: &str, theirs: String, own: String| {
        chain.broken(|| (format!("settings {setting}"), theirs.clone(), own.clone()));
        ImageError::Invalid(format!(
            "{reference}: {setting}: the configuration of the image (hashed from the digest of the reference) gives {theirs}, the container has {own}: the store was modified ({why})"
        ))
    };
    let list = |l: &[String]| format!("{l:?}");
    let want = |setting: &str,
                taken: &Option<Vec<String>>,
                theirs: Vec<String>,
                own: &[String]|
     -> ImageResult<()> {
        match taken {
            Some(t) if *t != theirs => Err(refuse(setting, list(&theirs), list(t))),
            Some(_) if theirs != own => Err(refuse(setting, list(&theirs), list(own))),
            _ => Ok(()),
        }
    };
    want(
        "entrypoint",
        &taken.entrypoint,
        img.entrypoint.clone().unwrap_or_default(),
        &config.entrypoint,
    )?;
    want(
        "command",
        &taken.cmd,
        img.cmd.clone().unwrap_or_default(),
        &config.command,
    )?;
    for e in &taken.env {
        if !img.env.contains(e) {
            return Err(refuse(
                "env",
                list(&img.env),
                format!("{e:?} as the image's"),
            ));
        }
        if !config.env.contains(e) {
            return Err(refuse("env", format!("{e:?}"), "no such entry".to_string()));
        }
    }
    let one = |setting: &str, taken: &Option<String>, theirs: String, own: &str| match taken {
        Some(t) if *t != theirs => Err(refuse(setting, format!("{theirs:?}"), format!("{t:?}"))),
        Some(_) if theirs != own => Err(refuse(setting, format!("{theirs:?}"), format!("{own:?}"))),
        _ => Ok(()),
    };
    one("user", &taken.user, img.user.clone(), &config.user)?;
    one(
        "working directory",
        &taken.working_dir,
        image_workdir(image),
        &config.working_dir,
    )?;
    one(
        "stop signal",
        &taken.stop_signal,
        img.stop_signal.clone(),
        &config.stop_signal,
    )?;
    if let Some(t) = &taken.healthcheck {
        let theirs = img.healthcheck.as_ref().map(|h| h.test.clone());
        let own = config.healthcheck.as_ref().map(|h| h.test.clone());
        if theirs.as_ref() != Some(t) || own.as_ref() != Some(t) {
            return Err(refuse(
                "health check",
                format!("{theirs:?}"),
                format!("{own:?}"),
            ));
        }
    }
    for v in &taken.volumes {
        if !img.volumes.contains_key(v) {
            return Err(refuse(
                "volume",
                format!("no volume {v}"),
                "a volume of the image".to_string(),
            ));
        }
        if !config
            .mounts
            .iter()
            .any(|m| volume_target(&m.target) == volume_target(v))
        {
            return Err(refuse(
                "volume",
                format!("a volume {v}"),
                "no mount there".to_string(),
            ));
        }
    }
    Ok(())
}

/// Whether the process the runtime reads from the spec of the bundle (`spec`,
/// its `config.json`) is the one `config` says: the arguments, the
/// environment, the working directory and the user.  The settings the image
/// decided are held against its configuration by [`check_taken`]; this is
/// the file the runtime reads, held against the settings.
pub fn check_spec(
    reference: &str,
    why: &str,
    spec: &serde_json::Value,
    config: &ContainerConfig,
    chain: &Chain,
) -> ImageResult<()> {
    let refuse = |what: &str, theirs: String, own: String| {
        chain.broken(|| (format!("spec process {what}"), own.clone(), theirs.clone()));
        ImageError::Invalid(format!(
            "{reference}: the {what} of the bundle's spec is {theirs}, the container has {own}: the store was modified ({why})"
        ))
    };
    let process = spec.get("process");
    let strings = |key: &str| -> Option<Vec<String>> {
        process?
            .get(key)?
            .as_array()?
            .iter()
            .map(|v| v.as_str().map(str::to_string))
            .collect()
    };
    let mut args = config.command.clone();
    if !config.entrypoint.is_empty() {
        let mut full = config.entrypoint.clone();
        full.extend(args);
        args = full;
    }
    if args.is_empty() {
        args = vec!["/bin/sh".to_string()];
    }
    let theirs = strings("args").unwrap_or_default();
    if theirs != args {
        return Err(refuse(
            "arguments",
            format!("{theirs:?}"),
            format!("{args:?}"),
        ));
    }
    let env = strings("env").unwrap_or_default();
    if let Some(missing) = config.env.iter().find(|e| !env.contains(e)) {
        return Err(refuse(
            "environment",
            format!("without {missing:?}"),
            "it".to_string(),
        ));
    }
    let cwd = process
        .and_then(|p| p.get("cwd"))
        .and_then(|c| c.as_str())
        .unwrap_or("/");
    let wanted = if config.working_dir.is_empty() {
        "/"
    } else {
        config.working_dir.as_str()
    };
    if cwd != wanted {
        return Err(refuse(
            "working directory",
            format!("{cwd:?}"),
            format!("{wanted:?}"),
        ));
    }
    if let Some(u) = &config.process_user {
        let id = |k: &str| {
            process
                .and_then(|p| p.get("user"))
                .and_then(|u| u.get(k))
                .and_then(|v| v.as_u64())
        };
        if id("uid") != Some(u64::from(u.uid)) || id("gid") != Some(u64::from(u.gid)) {
            return Err(refuse(
                "user",
                format!("{:?}:{:?}", id("uid"), id("gid")),
                format!("{}:{}", u.uid, u.gid),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::PinnedImage;
    use velarx_proto::health::Healthcheck;

    fn hash(s: &str) -> String {
        Digest::of(velarx_types::digest::Algorithm::Sha256, s.as_bytes()).to_string()
    }

    struct Fixture {
        image: ImageRecord,
        layers: Vec<LayerRecord>,
    }

    fn fixture(env: &str) -> Fixture {
        fixture_for(env, r#""architecture":"amd64","os":"linux""#)
    }

    fn fixture_for(env: &str, platform: &str) -> Fixture {
        let config = format!(
            r#"{{{platform},"config":{{"Env":["{env}"],"Cmd":["sh"],"WorkingDir":"/w","User":"1:1","StopSignal":"SIGUSR1","Volumes":{{"/data":{{}}}},"Healthcheck":{{"Test":["CMD","true"]}}}},"rootfs":{{"type":"layers","diff_ids":["sha256:d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1"]}}}}"#
        );
        let manifest = format!(
            r#"{{"schemaVersion":2,"config":{{"mediaType":"x","digest":"{}","size":{}}},"layers":[{{"mediaType":"x","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1}}]}}"#,
            hash(&config),
            config.len()
        );
        let digest = hash(&manifest);
        Fixture {
            image: ImageRecord {
                id: digest[7..].to_string(),
                manifest_digest: digest.parse().unwrap(),
                config_digest: hash(&config).parse().unwrap(),
                manifest,
                config,
                created_at: String::new(),
                is_lazy: false,
            },
            layers: vec![LayerRecord {
                stream_size: Some(0),
                inline: 0,
                key: velarx_db::LayerKey::Whole(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .parse()
                        .unwrap(),
                ),
                blob: Some(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .parse()
                        .unwrap(),
                ),
                diff_id: Some(
                    "sha256:d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1"
                        .parse()
                        .unwrap(),
                ),
                other_diff_id: None,
                size: 1,
                status: "ready".into(),
                created_at: String::new(),
                registry_ref: None,
                erofs: None,
                owners: None,
            }],
        }
    }

    fn typed(indexes: &HashMap<String, String>) -> HashMap<Digest, String> {
        indexes
            .iter()
            .map(|(k, v)| (k.parse().unwrap(), v.clone()))
            .collect()
    }

    fn run(
        f: &Fixture,
        root: impl std::fmt::Display,
        indexes: &HashMap<String, String>,
    ) -> ImageResult<Verified> {
        verify(
            "img@x",
            &root.to_string().parse().unwrap(),
            "option",
            &f.image,
            &f.layers,
            &typed(indexes),
            &Chain::off(),
        )
    }

    #[test]
    fn the_manifest_must_hash_to_the_digest_of_the_reference() {
        let f = fixture("A=1");
        let none = HashMap::new();
        run(&f, f.image.manifest_digest, &none).unwrap();
        let other = fixture("A=2");
        // the rows of another image put in place of this one: they agree
        // with each other, not with the digest typed
        let e = run(&other, f.image.manifest_digest, &none)
            .err()
            .unwrap()
            .to_string();
        assert!(
            e.contains(&other.image.manifest_digest.to_string())
                && e.contains(&f.image.manifest_digest.to_string())
                && e.contains("(option)")
                && e.contains("img@x"),
            "{e}"
        );
        // (a digest of another algorithm than the image's is not that of
        // its manifest: the image says the one it is named by)
        let sha512 = format!("sha512:{}", "0".repeat(128));
        let e = run(&f, &sha512, &none).err().unwrap().to_string();
        assert!(e.contains("pass that digest"), "{e}");
    }

    #[test]
    fn the_configuration_must_hash_to_the_digest_in_the_manifest() {
        let mut f = fixture("A=1");
        f.image.config = f.image.config.replace("A=1", "A=2");
        let e = run(&f, f.image.manifest_digest, &HashMap::new())
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("stored configuration hashes to"), "{e}");
    }

    #[test]
    fn the_layers_and_diff_ids_are_the_manifests_and_the_configurations() {
        let mut f = fixture("A=1");
        let root = f.image.manifest_digest;
        f.layers[0].diff_id = Some(
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                .parse()
                .unwrap(),
        );
        let e = run(&f, root, &HashMap::new()).err().unwrap().to_string();
        assert!(
            e.contains("layer 1 of 1")
                && e.contains(
                    "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                ),
            "{e}"
        );
        // a layer of images of both algorithms: the configuration's diff id
        // is held against the recorded one of its algorithm
        let d1: Digest = "sha256:d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1"
            .parse()
            .unwrap();
        f.layers[0].diff_id = Some(Digest::of(Algorithm::Sha512, b"tar"));
        f.layers[0].other_diff_id = Some(d1);
        run(&f, root, &HashMap::new()).unwrap();
        // (recorded in the other algorithm only: never checked against it)
        f.layers[0].other_diff_id = None;
        let e = run(&f, root, &HashMap::new()).err().unwrap().to_string();
        assert!(e.contains("its diff id is recorded as sha512:"), "{e}");
        f.layers[0].diff_id = None;
        run(&f, root, &HashMap::new()).unwrap();
        // the layer of the TOC of the blob is not the layer of a descriptor
        // without zstd:chunked labels
        f.layers[0].key = velarx_db::LayerKey::Toc(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .parse()
                .unwrap(),
        );
        let e = run(&f, root, &HashMap::new()).err().unwrap().to_string();
        assert!(e.contains("not those of its manifest"), "{e}");
        f.layers[0].key = velarx_db::LayerKey::Whole(
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .parse()
                .unwrap(),
        );
        f.layers[0].blob = Some(
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .parse()
                .unwrap(),
        );
        let e = run(&f, root, &HashMap::new()).err().unwrap().to_string();
        assert!(e.contains("not those of its manifest"), "{e}");
    }

    fn index(f: &Fixture, platform: &str) -> (String, String) {
        let text = format!(
            r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"x","digest":"sha256:{}","size":1,"platform":{{"os":"linux","architecture":"arm64"}}}},{{"mediaType":"x","digest":"{}","size":1,"platform":{platform}}}]}}"#,
            "0".repeat(64),
            f.image.manifest_digest
        );
        (hash(&text), text)
    }

    #[test]
    fn an_index_digest_is_a_root_when_it_lists_the_manifest() {
        let f = fixture("A=1");
        let (d, text) = index(&f, r#"{"os":"linux","architecture":"amd64"}"#);
        let indexes = HashMap::from([(d.clone(), text.clone())]);
        run(&f, &d, &indexes).unwrap();
        // the architecture the index states is the configuration's
        let (d2, text2) = index(&f, r#"{"os":"linux","architecture":"s390x"}"#);
        let e = run(&f, &d2, &HashMap::from([(d2.clone(), text2)]))
            .err()
            .unwrap()
            .to_string();
        assert!(
            e.contains("linux/s390x") && e.contains("linux/amd64"),
            "{e}"
        );
        // an index that does not list it
        let other = fixture("A=2");
        let e = run(&other, &d, &indexes).err().unwrap().to_string();
        assert!(e.contains("does not list"), "{e}");
        // bytes that are not the index the digest names
        let bad = HashMap::from([(d.clone(), text.replace("arm64", "arm"))]);
        let e = run(&f, &d, &bad).err().unwrap().to_string();
        assert!(e.contains("stored index") && e.contains("hashes to"), "{e}");
        // no index at all
        let e = run(&f, &d, &HashMap::new()).err().unwrap().to_string();
        assert!(e.contains("no index"), "{e}");
        // an index that lists an index that lists it
        let outer = format!(
            r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"x","digest":"{d}","size":1}}]}}"#
        );
        let od = hash(&outer);
        let nested = HashMap::from([(od.clone(), outer), (d, text)]);
        run(&f, &od, &nested).unwrap();
    }

    #[test]
    fn an_index_is_followed_as_deep_as_a_pull_and_for_the_platform_a_pull_takes() {
        let f = fixture("A=1");
        let (d, text) = index(&f, r#"{"os":"linux","architecture":"amd64"}"#);
        let around = |inner: &str| {
            let text = format!(
                r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"x","digest":"{inner}","size":1}}]}}"#
            );
            (hash(&text), text)
        };
        // an index in an index in an index: deeper than a pull follows
        let (md, mid) = around(&d);
        let (td, top) = around(&md);
        let deep = HashMap::from([(td.clone(), top), (md, mid), (d, text)]);
        let e = run(&f, &td, &deep).err().unwrap().to_string();
        assert!(e.contains("does not list"), "{e}");
        // another manifest first for the same platform: the pull took that one
        let entry = |digest: &str| {
            format!(
                r#"{{"mediaType":"x","digest":"{digest}","size":1,"platform":{{"os":"linux","architecture":"amd64"}}}}"#
            )
        };
        let other = format!("sha256:{}", "1".repeat(64));
        let dup = format!(
            r#"{{"schemaVersion":2,"manifests":[{},{}]}}"#,
            entry(&other),
            entry(&f.image.manifest_digest.to_string())
        );
        let dd = hash(&dup);
        let e = run(&f, &dd, &HashMap::from([(dd.clone(), dup)]))
            .err()
            .unwrap()
            .to_string();
        assert!(
            e.contains(&format!("lists {other} first for the platform")),
            "{e}"
        );
        // the variant the index states is the configuration's
        let v8 = fixture_for(
            "A=1",
            r#""architecture":"arm64","os":"linux","variant":"v8""#,
        );
        let (d, text) = index(
            &v8,
            r#"{"os":"linux","architecture":"arm64","variant":"v8"}"#,
        );
        run(&v8, &d, &HashMap::from([(d.clone(), text)])).unwrap();
        let (d, text) = index(
            &v8,
            r#"{"os":"linux","architecture":"arm64","variant":"v7"}"#,
        );
        let e = run(&v8, &d, &HashMap::from([(d.clone(), text)]))
            .err()
            .unwrap()
            .to_string();
        assert!(
            e.contains("linux/arm64/v7") && e.contains("linux/arm64/v8"),
            "{e}"
        );
    }

    fn container(f: &Fixture) -> (ContainerConfig, OciConfig) {
        let image: OciConfig = serde_json::from_str(&f.image.config).unwrap();
        let config = ContainerConfig {
            command: vec!["sh".into()],
            working_dir: "/w".into(),
            env: vec!["A=1".into(), "B=2".into()],
            user: "1:1".into(),
            stop_signal: "SIGUSR1".into(),
            healthcheck: Some(Healthcheck {
                test: vec!["CMD".into(), "true".into()],
                ..Default::default()
            }),
            mounts: vec![crate::container::MountConfig {
                source: "v".into(),
                target: "/data".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        (config, image)
    }

    #[test]
    fn what_the_container_took_from_the_image_is_held_against_its_configuration() {
        let f = fixture("A=1");
        let (config, image) = container(&f);
        let taken = taken_of(&image, &config);
        assert_eq!(taken.cmd, Some(vec!["sh".to_string()]));
        assert_eq!(taken.entrypoint, Some(Vec::new()));
        assert_eq!(taken.env, ["A=1"]);
        assert_eq!(taken.user.as_deref(), Some("1:1"));
        assert_eq!(taken.working_dir.as_deref(), Some("/w"));
        assert_eq!(taken.stop_signal.as_deref(), Some("SIGUSR1"));
        assert_eq!(taken.volumes, ["/data"]);
        check_taken("img@x", "option", &taken, &image, &config, &Chain::off()).unwrap();
        let pinned = PinnedImage {
            digest: format!("sha256:{}", "0".repeat(64)).parse().unwrap(),
            taken: taken.clone(),
        };
        let back: PinnedImage =
            serde_json::from_str(&serde_json::to_string(&pinned).unwrap()).unwrap();
        assert_eq!(back, pinned);

        // each setting edited in the container is refused, by name
        type Edit = fn(&mut ContainerConfig);
        let edits: [(&str, Edit); 7] = [
            ("command", |c| c.command = vec!["evil".into()]),
            ("entrypoint", |c| c.entrypoint = vec!["evil".into()]),
            ("env", |c| c.env = vec!["B=2".into()]),
            ("user", |c| c.user = "0".into()),
            ("working directory", |c| c.working_dir = "/".into()),
            ("stop signal", |c| c.stop_signal = "SIGKILL".into()),
            ("volume", |c| c.mounts.clear()),
        ];
        for (name, edit) in edits {
            let mut c = config.clone();
            edit(&mut c);
            let e = check_taken("img@x", "option", &taken, &image, &c, &Chain::off())
                .err()
                .unwrap_or_else(|| panic!("{name} edited"))
                .to_string();
            assert!(e.contains(name) && e.contains("(option)"), "{name}: {e}");
        }
        let mut c = config.clone();
        c.healthcheck = None;
        assert!(check_taken("img@x", "option", &taken, &image, &c, &Chain::off()).is_err());

        // a setting the request changed is not held against the image
        let mut c = config.clone();
        c.command = vec!["mine".into()];
        c.env.push("C=3".into());
        let taken = taken_of(&image, &c);
        assert_eq!(taken.cmd, None);
        check_taken("img@x", "option", &taken, &image, &c, &Chain::off()).unwrap();

        // the record edited to say something the image does not: the
        // configuration of the image is the judge
        let mut lying = taken_of(&image, &config);
        lying.cmd = Some(vec!["evil".into()]);
        let mut c = config.clone();
        c.command = vec!["evil".into()];
        let e = check_taken("img@x", "option", &lying, &image, &c, &Chain::off())
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("command") && e.contains("\"sh\""), "{e}");
        let mut lying = taken_of(&image, &config);
        lying.env.push("EVIL=1".into());
        assert!(check_taken("img@x", "option", &lying, &image, &config, &Chain::off()).is_err());
    }

    #[test]
    fn the_process_of_the_spec_is_the_containers() {
        let f = fixture("A=1");
        let (config, _) = container(&f);
        let spec = serde_json::json!({"process": {
            "args": ["sh"], "env": ["A=1", "B=2", "HOME=/"], "cwd": "/w",
            "user": {"uid": 1, "gid": 1}}});
        check_spec("img@x", "option", &spec, &config, &Chain::off()).unwrap();
        let mut c = config.clone();
        c.process_user = Some(crate::container::userspec::ResolvedUser {
            uid: 1,
            gid: 1,
            ..Default::default()
        });
        check_spec("img@x", "option", &spec, &c, &Chain::off()).unwrap();
        type Edit = fn(&mut serde_json::Value);
        let edits: [(&str, Edit); 4] = [
            ("arguments", |s| {
                s["process"]["args"] = serde_json::json!(["evil"])
            }),
            ("environment", |s| {
                s["process"]["env"] = serde_json::json!(["A=1"])
            }),
            ("working directory", |s| {
                s["process"]["cwd"] = serde_json::json!("/x")
            }),
            ("user", |s| {
                s["process"]["user"]["uid"] = serde_json::json!(0)
            }),
        ];
        for (what, edit) in edits {
            let mut s = spec.clone();
            edit(&mut s);
            let e = check_spec("img@x", "option", &s, &c, &Chain::off())
                .err()
                .unwrap_or_else(|| panic!("{what}"))
                .to_string();
            assert!(e.contains(what), "{what}: {e}");
        }
        // no command at all: the runtime's /bin/sh
        let mut c = config.clone();
        c.command.clear();
        let mut s = spec.clone();
        s["process"]["args"] = serde_json::json!(["/bin/sh"]);
        check_spec("img@x", "option", &s, &c, &Chain::off()).unwrap();
    }

    /// The lines of the chain that `f` logs at debug level.
    fn logged(f: impl FnOnce()) -> Vec<String> {
        velarx_wire::logcapture::logged_by(tracing::Level::DEBUG, f)
            .lines()
            .filter_map(|l| l.split_once("verity chain: ").map(|(_, r)| r.to_string()))
            .collect()
    }

    /// `verify` on a chain at debug level with `links` links in all.
    fn chain_of_run(
        f: &Fixture,
        root: impl std::fmt::Display,
        indexes: &HashMap<String, String>,
        total: usize,
    ) -> (ImageResult<Verified>, Vec<String>) {
        let mut result = None;
        let root: Digest = root.to_string().parse().unwrap();
        let lines = logged(|| {
            let chain = Chain::new("", total);
            result = Some(verify(
                "img@x",
                &root,
                "option",
                &f.image,
                &f.layers,
                &typed(indexes),
                &chain,
            ));
        });
        (result.unwrap(), lines)
    }

    /// An image whose manifest, configuration and layer are all sha512 (the
    /// config states a sha512 diff id).
    fn sha512_fixture() -> Fixture {
        let sha = |data: &[u8]| Digest::of(velarx_types::digest::Algorithm::Sha512, data);
        let layer = sha(b"layer");
        let config = format!(
            r#"{{"architecture":"amd64","os":"linux","config":{{}},"rootfs":{{"type":"layers","diff_ids":["{}"]}}}}"#,
            sha(b"tar")
        );
        let manifest = format!(
            r#"{{"schemaVersion":2,"config":{{"mediaType":"x","digest":"{}","size":{}}},"layers":[{{"mediaType":"x","digest":"{layer}","size":1}}]}}"#,
            sha(config.as_bytes()),
            config.len()
        );
        let digest = sha(manifest.as_bytes());
        Fixture {
            image: ImageRecord {
                id: digest.hex(),
                manifest_digest: digest,
                config_digest: sha(config.as_bytes()),
                manifest,
                config,
                created_at: String::new(),
                is_lazy: false,
            },
            layers: vec![LayerRecord {
                stream_size: Some(0),
                inline: 0,
                key: velarx_db::LayerKey::Whole(layer),
                blob: Some(layer),
                diff_id: Some(sha(b"tar")),
                other_diff_id: None,
                size: 1,
                status: "ready".into(),
                created_at: String::new(),
                registry_ref: None,
                erofs: None,
                owners: None,
            }],
        }
    }

    #[test]
    fn a_sha512_image_is_verified_with_sha512_links_and_the_log_says_so() {
        let f = sha512_fixture();
        let root = f.image.manifest_digest;
        assert_eq!(root.hex().len(), 128);
        let (v, lines) = chain_of_run(&f, root, &HashMap::new(), links(0, 0, 1));
        v.unwrap();
        assert!(!lines.is_empty());
        assert!(
            lines.iter().any(|l| l.starts_with(&format!(
                "{root} manifest -> {} config",
                f.image.config_digest
            ))),
            "{lines:?}"
        );
        assert!(lines.iter().all(|l| !l.contains("sha256:")), "{lines:?}");
        // a sha512 that is not the manifest's
        let other = Digest::of(velarx_types::digest::Algorithm::Sha512, b"x");
        let e = run(&f, other, &HashMap::new()).err().unwrap().to_string();
        assert!(
            e.contains(&other.to_string()) && e.contains("hashes to"),
            "{e}"
        );
        // the sha256 of the very bytes is another name of the image: the
        // image is named by its sha512
        let sha256 = Digest::of(
            velarx_types::digest::Algorithm::Sha256,
            f.image.manifest.as_bytes(),
        );
        let e = run(&f, sha256, &HashMap::new()).err().unwrap().to_string();
        assert!(
            e.contains("pass that digest") && e.contains(&root.to_string()),
            "{e}"
        );
        // a configuration that is not the sha512 the manifest names
        let mut f = f;
        f.image.config = f.image.config.replace("amd64", "arm64");
        let e = run(&f, root, &HashMap::new()).err().unwrap().to_string();
        assert!(e.contains("stored configuration hashes to sha512:"), "{e}");
    }

    #[test]
    fn a_sha256_index_over_a_sha512_manifest_is_followed_link_by_link() {
        let f = sha512_fixture();
        let m = f.image.manifest_digest;
        let index = format!(
            r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"x","digest":"{m}","size":1,"platform":{{"os":"linux","architecture":"amd64"}}}}]}}"#
        );
        let x = hash(&index);
        let indexes = HashMap::from([(x.clone(), index)]);
        run(&f, &x, &indexes).unwrap();
    }

    #[test]
    fn a_good_image_says_each_link_from_the_digest_that_vouches() {
        let f = fixture("A=1");
        let root = f.image.manifest_digest;
        let (v, lines) = chain_of_run(&f, root, &HashMap::new(), links(0, 0, 1));
        v.unwrap();
        assert_eq!(
            lines,
            [format!(
                "{root} manifest -> {} config",
                f.image.config_digest
            )]
        );
    }

    #[test]
    fn a_manifest_that_is_not_the_digest_breaks_the_chain_at_the_manifest() {
        let f = fixture("A=1");
        let other = fixture("A=2");
        // (the rows of another image, in place of the ones of the digest)
        let (v, lines) = chain_of_run(
            &other,
            f.image.manifest_digest,
            &HashMap::new(),
            links(0, 0, 1),
        );
        assert!(v.is_err());
        assert_eq!(
            lines,
            [format!(
                "BROKEN manifest expected {} found {}",
                f.image.manifest_digest, other.image.manifest_digest
            )]
        );
    }

    #[test]
    fn a_configuration_changed_in_the_store_breaks_the_chain_at_the_config() {
        let mut f = fixture("A=1");
        let want = f.image.config_digest;
        f.image.config = f.image.config.replace("A=1", "A=2");
        let root = f.image.manifest_digest;
        let (v, lines) = chain_of_run(&f, root, &HashMap::new(), links(0, 0, 1));
        assert!(v.is_err());
        assert_eq!(
            lines,
            [format!(
                "BROKEN config expected {want} found {}",
                hash(&f.image.config)
            )]
        );
    }

    #[test]
    fn layers_that_are_not_the_manifests_break_the_chain_at_the_layer() {
        let mut f = fixture("A=1");
        f.layers[0].key = velarx_db::LayerKey::Whole(
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .parse()
                .unwrap(),
        );
        f.layers[0].blob = Some(
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .parse()
                .unwrap(),
        );
        let root = f.image.manifest_digest;
        let (v, lines) = chain_of_run(&f, root, &HashMap::new(), links(0, 0, 1));
        assert!(v.is_err());
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert_eq!(
            lines[1],
            "BROKEN layer 1 blob expected sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa found sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        // and a diff id that is not the configuration's
        let mut f = fixture("A=1");
        f.layers[0].diff_id = Some(
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                .parse()
                .unwrap(),
        );
        let (_, lines) = chain_of_run(&f, root, &HashMap::new(), links(0, 0, 1));
        assert_eq!(
            lines[1],
            "BROKEN layer 1 diff expected sha256:d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1 found sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        );
    }

    #[test]
    fn an_index_is_a_link_of_its_own_and_a_changed_one_breaks_there() {
        let f = fixture("A=1");
        let m = f.image.manifest_digest;
        let (x, text) = index(&f, r#"{"os":"linux","architecture":"amd64"}"#);
        let mut indexes = HashMap::new();
        indexes.insert(x.clone(), text.clone());
        let total = links(index_links(&x.parse().unwrap(), &m, &typed(&indexes)), 0, 1);
        assert_eq!(total, links(1, 0, 1));
        let (v, lines) = chain_of_run(&f, &x, &indexes, total);
        v.unwrap();
        assert_eq!(
            lines,
            [
                format!("{x} index -> {m} manifest"),
                format!("{m} manifest -> {} config", f.image.config_digest),
            ]
        );
        // an index in an index
        let outer = format!(
            r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"x","digest":"{x}","size":1}}]}}"#
        );
        let od = hash(&outer);
        let nested = HashMap::from([(od.clone(), outer), (x.clone(), text.clone())]);
        let (v, lines) = chain_of_run(&f, &od, &nested, links(2, 0, 1));
        v.unwrap();
        assert_eq!(lines[0], format!("{od} index -> {x} index"));
        assert_eq!(lines[1], format!("{x} index -> {m} manifest"));
        // (the bytes of the index changed in the store)
        indexes.insert(x.clone(), format!("{text} "));
        let (v, lines) = chain_of_run(&f, &x, &indexes, total);
        assert!(v.is_err());
        assert_eq!(
            lines,
            [format!(
                "BROKEN index expected {x} found {}",
                hash(&format!("{text} "))
            )]
        );
        // an index that does not list it
        let other = fixture("A=2");
        let (_, lines) = chain_of_run(&other, &x, &HashMap::from([(x.clone(), text)]), total);
        assert_eq!(
            lines,
            [format!(
                "BROKEN {x} index expected {} found none",
                other.image.manifest_digest
            )]
        );
    }

    #[test]
    fn each_layer_is_a_link_from_the_manifest_to_its_annotation() {
        use super::super::seal::{start_lists, Enforcing};
        let (e1, e2) = (
            format!("sha256:{}", "e".repeat(64)),
            format!("sha256:{}", "f".repeat(64)),
        );
        let manifest = format!(
            r#"{{"schemaVersion":2,"config":{{"mediaType":"x","digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","size":1}},"layers":[{{"mediaType":"x","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1,"annotations":{{"io.containers.composefs.digest":"{e1},{e2}"}}}}]}}"#
        );
        let m = hash(&manifest);
        let mut f = fixture("A=1");
        f.layers[0].erofs = Some(e2.clone());
        let lines = logged(|| {
            let chain = Chain::new("", 1);
            start_lists(
                &m[7..],
                &m.parse().unwrap(),
                &manifest,
                &f.layers,
                false,
                Enforcing::Container,
                &chain,
            )
            .unwrap();
        });
        assert_eq!(
            lines,
            [format!(
                "{m} manifest -> sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa layer 1 blob -> {e1},{e2} annotation"
            )]
        );
        // a record the annotation does not have
        f.layers[0].erofs = Some(format!("sha256:{}", "0".repeat(64)));
        let lines = logged(|| {
            let chain = Chain::new("", 1);
            let _ = start_lists(
                &m[7..],
                &m.parse().unwrap(),
                &manifest,
                &f.layers,
                false,
                Enforcing::Container,
                &chain,
            );
        });
        assert_eq!(
            lines,
            [format!(
                "BROKEN layer 1 annotation expected {e1},{e2} found sha256:{}",
                "0".repeat(64)
            )]
        );
    }

    #[test]
    fn the_settings_and_the_spec_say_the_setting_that_broke() {
        let f = fixture("A=1");
        let (config, image) = container(&f);
        let taken = taken_of(&image, &config);
        let mut c = config.clone();
        c.command = vec!["evil".into()];
        let lines = logged(|| {
            let chain = Chain::new("", 1);
            let _ = check_taken("img@x", "option", &taken, &image, &c, &chain);
        });
        assert_eq!(
            lines,
            [r#"BROKEN settings command expected ["sh"] found ["evil"]"#]
        );
        let spec = serde_json::json!({"process": {"args": ["evil"], "cwd": "/w"}});
        let lines = logged(|| {
            let chain = Chain::new("", 1);
            let _ = check_spec("img@x", "option", &spec, &config, &chain);
        });
        assert_eq!(
            lines,
            [r#"BROKEN spec process arguments expected ["sh"] found ["evil"]"#]
        );
    }
}
