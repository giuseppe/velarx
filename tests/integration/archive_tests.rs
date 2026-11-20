// SPDX-License-Identifier: Apache-2.0
//! Saving, loading and importing images: the archives go through the pull
//! engine, so every digest is checked.

use crate::common::*;
use std::io::{Read, Write};
use velarx_content::layer::reproduce::StoredLayer;
use velarx_core::services::ImageService;
use velarx_proto::transfer::FailureClass;
use velarx_types::{ImageError, OciManifest};

const GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";

fn items() -> Vec<Item> {
    vec![
        Item::Dir("etc/"),
        Item::File {
            name: "etc/hello",
            data: b"hello\n".to_vec(),
            chunk: 4096,
        },
        Item::File {
            name: "usr/big",
            data: (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect(),
            chunk: 65536,
        },
        Item::Symlink("etc/link", "hello"),
    ]
}

/// A service whose store has an image of two layers (gzip and
/// zstd:chunked) named `<host>/test:latest`.
async fn source() -> Env {
    let e = env().await;
    let first = build_gzip(&items());
    let second = build_chunked(&items()[..2]);
    e.publish(&[&first, &second], &[GZIP, ZSTD]);
    e.pull().await.unwrap();
    e
}

/// What `save` writes of `images`: the bytes of the archive.
async fn try_save(service: &ImageService, images: &[&str]) -> velarx_types::ImageResult<Vec<u8>> {
    use std::io::{Read, Seek};
    let named = service
        .save_names(&images.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        .await?;
    let mut file = tempfile::tempfile().unwrap();
    let path = velarx_core::services::PathPush {
        mode: velarx_content::dir_push::Mode::Archive,
        dest: std::sync::Arc::new(file.try_clone().unwrap().into()),
        names: Vec::new(),
        label: "test".into(),
    };
    service.save_images(&named, &path).await?;
    file.rewind().unwrap();
    let mut out = Vec::new();
    file.read_to_end(&mut out).unwrap();
    Ok(out)
}

async fn save(service: &ImageService, images: &[&str]) -> Vec<u8> {
    try_save(service, images).await.unwrap()
}

fn spooled(data: &[u8]) -> std::fs::File {
    let mut f = tempfile::tempfile().unwrap();
    f.write_all(data).unwrap();
    f
}

/// What a load of `data` is: a pull from the origin `archive:` that
/// `velarx-dir` serves, as the engine pulls it (`velarx load`, the podman
/// API).
async fn load(
    service: &ImageService,
    data: &[u8],
) -> velarx_types::ImageResult<Vec<velarx_core::services::LoadedImage>> {
    pull_from(service, "archive:", spooled(data)).await
}

/// A pull of `source` from the file or the directory `target`.
async fn pull_from(
    service: &ImageService,
    source: &str,
    target: impl Into<std::os::fd::OwnedFd>,
) -> velarx_types::ImageResult<Vec<velarx_core::services::LoadedImage>> {
    let origin = velarx_content::origin::Origin::parse(source).unwrap();
    // (the progress is told to nobody: a channel nobody reads is read
    // here)
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let drain = tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let loaded = service
        .pull_origin(
            &origin,
            Some(target.into()),
            &velarx_core::services::PullOptions::default(),
            tx,
        )
        .await;
    drain.abort();
    loaded
}

fn members(archive: &[u8]) -> Vec<String> {
    tar::Archive::new(archive)
        .entries()
        .unwrap()
        .map(|e| e.unwrap().path().unwrap().to_string_lossy().to_string())
        .collect()
}

fn member(archive: &[u8], name: &str) -> Vec<u8> {
    let mut a = tar::Archive::new(archive);
    for e in a.entries().unwrap() {
        let mut e = e.unwrap();
        if e.path().unwrap().to_string_lossy() == name {
            let mut out = Vec::new();
            e.read_to_end(&mut out).unwrap();
            return out;
        }
    }
    panic!("no {name}");
}

async fn same_layers(a: &Env, b: &Side, image: &str, other: &str) {
    let left = a.service.get(image).await.unwrap();
    let right = b.service.get(other).await.unwrap();
    assert_eq!(left.config_digest, right.config_digest);
    let lm: OciManifest = serde_json::from_str(&left.manifest).unwrap();
    let rm: OciManifest = serde_json::from_str(&right.manifest).unwrap();
    assert_eq!(lm.layers.len(), rm.layers.len());
    // (a layer of a table of contents has no diff id of its own: the
    // configuration's is the one its stream is checked against)
    let diffs = serde_json::from_str::<velarx_types::OciConfig>(&left.config)
        .unwrap()
        .rootfs
        .diff_ids;
    for ((l, r), diff) in lm.layers.iter().zip(&rm.layers).zip(&diffs) {
        let (from, to) = (
            StoredLayer::load_expecting(
                &a.db,
                &stored_key(&a.db, &l.digest).await,
                None,
                Some(diff),
            )
            .await
            .unwrap(),
            StoredLayer::load_expecting(
                &b.db,
                &stored_key(&a.db, &r.digest).await,
                None,
                Some(diff),
            )
            .await
            .unwrap(),
        );
        assert_eq!(from.diff_id, to.diff_id);
        let mut x = Vec::new();
        from.verified_stream(a.store.clone())
            .unwrap()
            .read_to_end(&mut x)
            .unwrap();
        let mut y = Vec::new();
        to.verified_stream(b.store.clone())
            .unwrap()
            .read_to_end(&mut y)
            .unwrap();
        assert_eq!(x, y);
    }
}

/// A `docker save` tarball: `manifest.json`, the configuration and the
/// layers (the files of a saved OCI archive, in Docker's names).
fn docker_archive(oci: &[u8]) -> Vec<u8> {
    let index: serde_json::Value = serde_json::from_slice(&member(oci, "index.json")).unwrap();
    let manifest_digest = index["manifests"][0]["digest"].as_str().unwrap();
    let blob = |digest: &str| member(oci, &format!("blobs/sha256/{}", &digest[7..]));
    let manifest: serde_json::Value = serde_json::from_slice(&blob(manifest_digest)).unwrap();
    let mut t = tar::Builder::new(Vec::new());
    let mut add = |name: &str, data: &[u8]| {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        t.append_data(&mut h, name, data).unwrap();
    };
    let config = manifest["config"]["digest"].as_str().unwrap();
    add("config.json", &blob(config));
    let mut layers = Vec::new();
    for (i, l) in manifest["layers"].as_array().unwrap().iter().enumerate() {
        let name = format!("l{i}/layer.tar");
        add(&name, &blob(l["digest"].as_str().unwrap()));
        layers.push(name);
    }
    add(
        "manifest.json",
        &serde_json::to_vec(&serde_json::json!([
            {"Config": "config.json", "RepoTags": ["localhost/docker:v1"], "Layers": layers}
        ]))
        .unwrap(),
    );
    t.into_inner().unwrap()
}

#[tokio::test]
async fn test_a_docker_archive_is_loaded_as_an_oci_image() {
    let a = source().await;
    let name = format!("{}/test:latest", a.host);
    let oci = save(&a.service, &[&name]).await;
    let archive = docker_archive(&oci);

    let b = side().await;
    let loaded = load(&b.service, &archive).await.unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].names, ["localhost/docker:v1"]);
    // the image id is the digest of the configuration, as in the source
    // (`same_layers`), the manifest digest is the synthesised one
    same_layers(&a, &b, &name, "localhost/docker:v1").await;
    let original = a.service.get(&name).await.unwrap();
    let stored = b.service.get("localhost/docker:v1").await.unwrap();
    assert_ne!(stored.manifest_digest, original.manifest_digest);
    // what is stored is OCI, with the manifest made of the archive
    let manifest: serde_json::Value = serde_json::from_str(&stored.manifest).unwrap();
    assert_eq!(
        manifest["mediaType"],
        "application/vnd.oci.image.manifest.v1+json"
    );
    assert_eq!(manifest["layers"].as_array().unwrap().len(), 2);
    let again = load(&b.service, &archive).await.unwrap();
    assert_eq!(again[0].id, loaded[0].id);
    assert_eq!(b.db.list_images().await.unwrap().len(), 1);
}

#[tokio::test]
async fn test_a_docker_archive_with_a_modified_layer_is_refused() {
    let a = source().await;
    let name = format!("{}/test:latest", a.host);
    let oci = save(&a.service, &[&name]).await;
    let archive = docker_archive(&oci);
    let mut out = tar::Builder::new(Vec::new());
    let mut input = tar::Archive::new(&archive[..]);
    for entry in input.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().to_string();
        let mut data = Vec::new();
        entry.read_to_end(&mut data).unwrap();
        if path == "l0/layer.tar" {
            // (the member is the gzip stream of the layer)
            let at = data.len() / 2;
            data[at] ^= 0xff;
        }
        let mut h = entry.header().clone();
        out.append_data(&mut h, &path, &data[..]).unwrap();
    }
    let b = side().await;
    let err = load(&b.service, &out.into_inner().unwrap())
        .await
        .unwrap_err();
    assert!(!matches!(err, ImageError::DockerFormat(_)), "{err}");
    assert!(b.db.list_images().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_a_docker_archive_naming_a_member_that_is_not_there_is_refused() {
    let a = source().await;
    let oci = save(&a.service, &[&format!("{}/test:latest", a.host)]).await;
    let archive = docker_archive(&oci);
    let mut out = tar::Builder::new(Vec::new());
    let mut input = tar::Archive::new(&archive[..]);
    for entry in input.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().to_string();
        if path == "l1/layer.tar" {
            continue;
        }
        let mut data = Vec::new();
        entry.read_to_end(&mut data).unwrap();
        let mut h = entry.header().clone();
        out.append_data(&mut h, &path, &data[..]).unwrap();
    }
    let b = side().await;
    let err = load(&b.service, &out.into_inner().unwrap())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("l1/layer.tar"), "{err}");
    assert!(b.db.list_images().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_docker_schema_2_in_an_oci_layout_is_loaded() {
    let a = source().await;
    let name = format!("{}/test:latest", a.host);
    let oci = save(&a.service, &[&name]).await;
    // the manifest of the layout is Docker's schema 2
    let index: serde_json::Value = serde_json::from_slice(&member(&oci, "index.json")).unwrap();
    let old: Digest = index["manifests"][0]["digest"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let docker = String::from_utf8(member(&oci, &format!("blobs/sha256/{}", old.hex())))
        .unwrap()
        .replace(
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        );
    let new = sha(docker.as_bytes());
    let mut out = tar::Builder::new(Vec::new());
    let mut input = tar::Archive::new(&oci[..]);
    for entry in input.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().to_string();
        let mut data = Vec::new();
        entry.read_to_end(&mut data).unwrap();
        let mut h = entry.header().clone();
        if path == "index.json" {
            data = String::from_utf8(data)
                .unwrap()
                .replace(&old.to_string(), &new.to_string())
                .into_bytes();
        } else if path == format!("blobs/sha256/{}", old.hex()) {
            continue;
        }
        h.set_size(data.len() as u64);
        out.append_data(&mut h, &path, &data[..]).unwrap();
    }
    let mut h = tar::Header::new_gnu();
    h.set_size(docker.len() as u64);
    h.set_mode(0o644);
    out.append_data(
        &mut h,
        format!("blobs/sha256/{}", new.hex()),
        docker.as_bytes(),
    )
    .unwrap();
    let archive = out.into_inner().unwrap();

    let b = side().await;
    load(&b.service, &archive).await.unwrap();
    // the manifest is kept as it was in the archive
    let images = b.db.list_images().await.unwrap();
    assert_eq!(images.len(), 1);
    assert_eq!(images[0].manifest_digest, new);
}

#[tokio::test]
async fn test_oci_archive_round_trip_with_two_images() {
    let a = source().await;
    let first = format!("{}/test:latest", a.host);
    a.service.tag(&first, "localhost/second:v2").await.unwrap();
    let archive = save(&a.service, &[&first, "localhost/second:v2"]).await;

    let listing = members(&archive);
    for expected in ["oci-layout", "index.json", "blobs/sha256"] {
        assert!(
            listing.iter().any(|n| n.trim_end_matches('/') == expected),
            "{listing:?}"
        );
    }
    let index: serde_json::Value = serde_json::from_slice(&member(&archive, "index.json")).unwrap();
    assert_eq!(index["manifests"].as_array().unwrap().len(), 2);
    assert_eq!(
        index["manifests"][1]["annotations"]["org.opencontainers.image.ref.name"],
        "v2"
    );

    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&archive).unwrap();
    let b = side().await;
    let loaded = load(&b.service, &gz.finish().unwrap()).await.unwrap();
    // (two names of one image: one image, loaded by both)
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].names.len(), 2, "{:?}", loaded[0].names);
    assert!(loaded[0].names.contains(&"localhost/second:v2".to_string()));
    same_layers(&a, &b, &first, "localhost/second:v2").await;
}

#[tokio::test]
async fn test_archive_with_a_modified_layer_is_refused() {
    let a = source().await;
    let archive = save(&a.service, &[&format!("{}/test:latest", a.host)]).await;
    let index: serde_json::Value = serde_json::from_slice(&member(&archive, "index.json")).unwrap();
    let manifest_digest = index["manifests"][0]["digest"].as_str().unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&member(
        &archive,
        &format!("blobs/sha256/{}", &manifest_digest[7..]),
    ))
    .unwrap();
    let layer = format!(
        "blobs/sha256/{}",
        &manifest["layers"][0]["digest"].as_str().unwrap()[7..]
    );

    let mut out = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut out);
        let mut input = tar::Archive::new(&archive[..]);
        for entry in input.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().to_string();
            let mut data = Vec::new();
            entry.read_to_end(&mut data).unwrap();
            if path == layer {
                let at = data.len() / 2;
                data[at] ^= 0xff;
            }
            let mut h = entry.header().clone();
            builder.append_data(&mut h, &path, &data[..]).unwrap();
        }
        builder.finish().unwrap();
    }
    let b = side().await;
    let err = load(&b.service, &out).await.unwrap_err();
    // an OCI archive finds a blob by the digest of its content: the changed
    // layer is not there any more
    let message = err.to_string();
    assert!(
        message.contains("digest") || message.contains("is not in the archive"),
        "{err}"
    );
    assert!(b.db.list_images().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_invalid_archives_are_refused() {
    let b = side().await;
    for data in [b"not an archive".to_vec(), Vec::new(), {
        let mut t = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(1);
        t.append_data(&mut h, "random", &b"x"[..]).unwrap();
        t.into_inner().unwrap()
    }] {
        assert!(load(&b.service, &data).await.is_err());
    }
    assert!(b.db.list_images().await.unwrap().is_empty());
}

/// The party of a failure of the origin of a path, which names it.
fn party_of(e: &ImageError) -> Option<&str> {
    match e {
        ImageError::Transfer { party, .. } => Some(party),
        _ => None,
    }
}

/// An archive of `entries` (name, bytes).
fn tar_entries(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut t = tar::Builder::new(Vec::new());
    for (name, data) in entries {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        t.append_data(&mut h, name, &data[..]).unwrap();
    }
    t.into_inner().unwrap()
}

/// The archive `oci` with the member `name` replaced by `data` (or the
/// archive cut where `name` is, with `None`).
fn with_member(oci: &[u8], name: &str, data: Option<Vec<u8>>) -> Vec<u8> {
    let mut out = tar::Builder::new(Vec::new());
    let mut input = tar::Archive::new(oci);
    for entry in input.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().to_string();
        let mut body = Vec::new();
        entry.read_to_end(&mut body).unwrap();
        if path == name {
            match &data {
                Some(d) => body = d.clone(),
                None => continue,
            }
        }
        let mut h = entry.header().clone();
        h.set_size(body.len() as u64);
        out.append_data(&mut h, &path, &body[..]).unwrap();
    }
    out.into_inner().unwrap()
}

/// What the helper that parses an archive does with one that is not: it
/// says so as a typed error of its party, writes nothing outside its
/// staging, and the engine goes on (the next load of a good archive works).
#[tokio::test]
async fn test_malformed_archives_are_typed_errors_of_the_helper_and_the_engine_goes_on() {
    let a = source().await;
    let name = format!("{}/test:latest", a.host);
    let oci = save(&a.service, &[&name]).await;
    let docker = docker_archive(&oci);
    let b = side().await;

    let mut bad: Vec<(&str, Vec<u8>)> = Vec::new();
    // cut in the middle of the layers
    bad.push(("truncated", oci[..oci.len() / 2].to_vec()));
    // a name that goes up, and one that is absolute, in `manifest.json`
    for member in ["../../../../etc/passwd", "/etc/passwd"] {
        let manifest = serde_json::to_vec(&serde_json::json!([
            {"Config": member, "RepoTags": ["x:1"], "Layers": ["l0/layer.tar"]}
        ]))
        .unwrap();
        bad.push((
            "a member that leaves the archive",
            with_member(&docker, "manifest.json", Some(manifest)),
        ));
    }
    // a `manifest.json` that names a layer the archive has not
    bad.push((
        "a missing layer",
        with_member(&docker, "l1/layer.tar", None),
    ));
    // an index larger than any index may be
    bad.push((
        "an oversized index",
        with_member(&oci, "index.json", Some(vec![b' '; 5 << 20])),
    ));
    // a member with a very long name
    bad.push((
        "a long name",
        tar_entries(&[(&"d/".repeat(3000), b"x".to_vec())]),
    ));
    // a tar of zeros that inflates past what an archive may
    let zeros = tar_entries(&[("bomb", vec![0u8; 200 << 20])]);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    gz.write_all(&zeros).unwrap();
    bad.push(("a bomb", gz.finish().unwrap()));
    for (what, data) in bad {
        let e = load(&b.service, &data).await.unwrap_err();
        // (invalid content of the party `dir`: the engine asks nobody else)
        assert_eq!(party_of(&e), Some("dir"), "{what}: {e}");
        assert_eq!(e.class(), Some(FailureClass::Invalid), "{what}: {e}");
        assert!(!e.to_string().is_empty(), "{what}");
        assert!(b.db.list_images().await.unwrap().is_empty(), "{what}");
    }
    // the engine is as it was
    let loaded = load(&b.service, &oci).await.unwrap();
    assert_eq!(loaded.len(), 1);
}

/// A transport of `[[transports]]` that serves the one image of an archive
/// as what its location names: the fetcher side of a `s3://bucket/name`.
struct ArchiveTransport {
    inner: std::sync::Arc<velarx_content::dir_origin::DirOrigin>,
    archive: std::sync::Arc<std::fs::File>,
}

impl ArchiveTransport {
    /// The scope of the origin of the archive, as the helper of a path gets it.
    fn scope(&self, of: &velarx_content::serve_fetch::Scope) -> velarx_content::serve_fetch::Scope {
        velarx_content::serve_fetch::Scope {
            verity: of.verity,
            source: Some("oci-archive:".into()),
            tls_verify: None,
            target: Some(self.archive.clone()),
            access: None,
            idle: of.idle,
            kept: Default::default(),
        }
    }
}

#[async_trait::async_trait]
impl velarx_content::serve_fetch::StagingFetcher for ArchiveTransport {
    fn described(&self) -> velarx_content::serve_fetch::Described {
        velarx_content::serve_fetch::Described {
            name: "s3".into(),
            capabilities: vec!["metadata".into(), "unpack".into(), "origin".into()],
            max_objects: 1,
        }
    }

    async fn get_manifest(
        &self,
        scope: &velarx_content::serve_fetch::Scope,
        reference: &str,
        max: u64,
    ) -> Result<(std::fs::File, Option<String>), velarx_content::fetcher::fetch::FetcherError> {
        let scope = self.scope(scope);
        if !reference.is_empty() {
            return self.inner.get_manifest(&scope, reference, max).await;
        }
        // (the image the location names: the first of the archive)
        let (index, _) = self.inner.get_manifest(&scope, "", max).await.unwrap();
        let bytes =
            velarx_base::sealed::read_sealed(&index, index.metadata().unwrap().len(), max).unwrap();
        let index: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let digest = index["manifests"][0]["digest"].as_str().unwrap();
        self.inner.get_manifest(&scope, digest, max).await
    }

    async fn get_blob(
        &self,
        scope: &velarx_content::serve_fetch::Scope,
        blob: &velarx_content::fetcher::fetch::Blob,
    ) -> Result<std::fs::File, velarx_content::fetcher::fetch::FetcherError> {
        self.inner.get_blob(&self.scope(scope), blob).await
    }

    async fn unpack(
        &self,
        scope: &velarx_content::serve_fetch::Scope,
        layer: &velarx_content::serve_fetch::LayerScope,
        call: velarx_content::serve_fetch::UnpackCall,
        out: &velarx_content::serve_fetch::Out<velarx_content::fetcher::fetch::FetchEvent>,
    ) -> Result<(), velarx_content::fetcher::fetch::FetcherError> {
        self.inner
            .unpack(&self.scope(scope), layer, call, out)
            .await
    }
}

/// `SCHEME://...` of a `[[transports]]` is an origin of pulls: the engine
/// asks its process for the manifest and the blobs, which it checks, and its
/// layers are unpacked there and replayed against the diff ids.  A scheme that
/// is none of the configuration's is refused by name.
#[tokio::test]
async fn test_a_transport_is_an_origin_of_pulls() {
    let a = source().await;
    let oci = save(&a.service, &[&format!("{}/test:latest", a.host)]).await;
    let dir = tempfile::tempdir().unwrap();
    let staging = std::fs::File::open(dir.path()).unwrap();
    let archive = std::sync::Arc::new(spooled(&oci));
    let settings = velarx_content::list::HelperSettings::of(&velarx_config::Config::default());
    let transport = ArchiveTransport {
        inner: velarx_content::dir_origin::DirOrigin::new(
            Box::new(|_, _| Ok(())),
            settings,
            std::sync::Arc::new(staging),
        ),
        archive,
    };
    let socket = dir.path().join("s3.sock");
    let _served = velarx_content::serve_fetch::serve_in_thread(
        std::os::unix::net::UnixListener::bind(&socket).unwrap(),
        std::sync::Arc::new(transport),
        velarx_content::activation::Limits::default(),
    )
    .unwrap();
    let b = env_transports(vec![velarx_config::TransportConfig {
        scheme: "s3".into(),
        socket,
        idle_timeout_secs: 15,
        credentials: false,
    }])
    .await;
    let origin = |text: &str| velarx_content::origin::Origin::parse(text).unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let drain = tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let loaded = b
        .service
        .pull_origin(
            &origin("s3://bucket/name:1"),
            None,
            &velarx_core::services::PullOptions::default(),
            tx.clone(),
        )
        .await
        .unwrap();
    assert_eq!(loaded.len(), 1);
    // (the same configuration: the image id is its digest)
    let original = a
        .service
        .get(&format!("{}/test:latest", a.host))
        .await
        .unwrap();
    let pulled = b.service.get(&loaded[0].id).await.unwrap();
    assert_eq!(original.config_digest, pulled.config_digest);
    assert_eq!(b.db.list_images().await.unwrap().len(), 1);
    let e = b
        .service
        .pull_origin(
            &origin("gs://bucket/name:1"),
            None,
            &velarx_core::services::PullOptions::default(),
            tx,
        )
        .await
        .unwrap_err();
    assert!(
        e.to_string()
            .contains("no transport is configured for gs://"),
        "{e}"
    );
    drain.abort();
}

/// A layout directory, and a `dir:`, are read where they are.
#[tokio::test]
async fn test_a_layout_directory_and_a_dir_are_pulled_by_their_scheme() {
    let a = source().await;
    let name = format!("{}/test:latest", a.host);
    let oci = save(&a.service, &[&name]).await;
    let layout = tempfile::tempdir().unwrap();
    tar::Archive::new(&oci[..]).unpack(layout.path()).unwrap();
    let open = |p: &std::path::Path| std::fs::File::open(p).unwrap();
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(layout.path().join("index.json")).unwrap()).unwrap();
    let tag = index["manifests"][0]["annotations"]["org.opencontainers.image.ref.name"]
        .as_str()
        .unwrap()
        .to_string();

    // `oci:DIR:NAME` takes the image of that name and names it so
    let b = side().await;
    let e = pull_from(&b.service, "oci:/x:nope", open(layout.path()))
        .await
        .unwrap_err();
    assert!(e.to_string().contains("no image named `nope`"), "{e}");
    let loaded = pull_from(&b.service, &format!("oci:/x:{tag}"), open(layout.path()))
        .await
        .unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].names, [format!("docker.io/library/{tag}:latest")]);
    // a directory is no archive, and a file no directory
    let e = pull_from(&b.service, "oci-archive:/x", open(layout.path()))
        .await
        .unwrap_err();
    assert!(party_of(&e).is_some(), "{e}");
    let e = pull_from(&b.service, "oci:/x", spooled(&oci))
        .await
        .unwrap_err();
    assert!(party_of(&e).is_some(), "{e}");

    // `archive:` is either kind: a layout directory loads every image
    let c = side().await;
    let loaded = pull_from(&c.service, "archive:/x", open(layout.path()))
        .await
        .unwrap();
    assert_eq!(loaded.len(), 1);
    // `dir:` has one manifest and its blobs, named by their hex
    let digest = index["manifests"][0]["digest"].as_str().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let manifest =
        std::fs::read(layout.path().join(format!("blobs/sha256/{}", &digest[7..]))).unwrap();
    std::fs::write(dir.path().join("manifest.json"), &manifest).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
    let mut blobs = vec![parsed["config"]["digest"].as_str().unwrap().to_string()];
    blobs.extend(
        parsed["layers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l["digest"].as_str().unwrap().to_string()),
    );
    for blob in blobs {
        std::fs::copy(
            layout.path().join(format!("blobs/sha256/{}", &blob[7..])),
            dir.path().join(&blob[7..]),
        )
        .unwrap();
    }
    let d = side().await;
    let loaded = pull_from(&d.service, "dir:/x", open(dir.path()))
        .await
        .unwrap();
    assert_eq!(loaded.len(), 1);
    assert!(loaded[0].names.is_empty());
}

#[tokio::test]
async fn test_saving_an_unknown_image_or_an_incomplete_store_fails() {
    let a = source().await;
    assert!(try_save(&a.service, &["localhost/nope:1"]).await.is_err());
    assert!(try_save(&a.service, &[]).await.is_err());
    // A lost file is found while writing, not silently skipped.
    a.store.remove(&vid(b"hello\n")).unwrap();
    let image = format!("{}/test:latest", a.host);
    assert!(try_save(&a.service, &[&image]).await.is_err());
}

fn rootfs_tar() -> Vec<u8> {
    tar_of(&items())
}

#[tokio::test]
async fn test_import_a_root_file_system() {
    let b = side().await;
    let tar = rootfs_tar();
    let id = b
        .service
        .import_tar(
            spooled(&tar),
            Some("myimg"),
            &[
                "ENV IMPORTED=yes".into(),
                "CMD [\"sh\",\"-c\",\"echo $IMPORTED\"]".into(),
            ],
            Some("a comment"),
        )
        .await
        .unwrap();
    let image = b.service.get("localhost/myimg:latest").await.unwrap();
    assert_eq!(image.id, id);
    // the manifest states the digest of the EROFS image of the layer
    let manifest: velarx_types::OciManifest = serde_json::from_str(&image.manifest).unwrap();
    let layers = b.db.get_image_layers(&id).await.unwrap();
    assert_eq!(
        manifest.layers[0].annotations["io.containers.composefs.digest"],
        layers[0].erofs.clone().unwrap()
    );
    let config: serde_json::Value = serde_json::from_str(&image.config).unwrap();
    assert_eq!(config["config"]["Env"], serde_json::json!(["IMPORTED=yes"]));
    assert_eq!(
        config["config"]["Cmd"],
        serde_json::json!(["sh", "-c", "echo $IMPORTED"])
    );
    assert_eq!(config["rootfs"]["diff_ids"], serde_json::json!([sha(&tar)]));
    assert_eq!(config["history"][0]["comment"], "a comment");
    assert!(b.store.contains(&vid(b"hello\n")));
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&tar).unwrap();
    let id2 = b
        .service
        .import_tar(spooled(&gz.finish().unwrap()), None, &[], None)
        .await
        .unwrap();
    assert_ne!(id, id2);
    let layers = b.db.get_image_layers(&id2).await.unwrap();
    assert_eq!(layers[0].diff_id.as_ref(), Some(&sha(&tar)));
}

/// A tar of 4 KiB with a sparse entry of 64 MiB is imported without the
/// zeros ever being written: the file of the layer in the store has the
/// blocks of its data, and reads back as the file that was archived.
#[tokio::test]
async fn test_import_of_a_sparse_entry_leaves_the_holes() {
    use std::os::unix::fs::MetadataExt;
    let real: u64 = 64 << 20;
    let octal = |v: u64| {
        let mut b = [0u8; 12];
        b[..11].copy_from_slice(format!("{v:011o}").as_bytes());
        b
    };
    let mut h = tar::Header::new_gnu();
    h.set_path("hole").unwrap();
    h.set_entry_type(tar::EntryType::GNUSparse);
    h.set_size(1024);
    h.set_mode(0o644);
    {
        let g = h.as_gnu_mut().unwrap();
        g.realsize = octal(real);
        for (i, (off, len)) in [(0, 512), (real - 512, 512), (real, 0)].iter().enumerate() {
            g.sparse[i].offset = octal(*off);
            g.sparse[i].numbytes = octal(*len);
        }
    }
    h.set_cksum();
    let mut tar = h.as_bytes().to_vec();
    tar.extend([b'h'; 512]);
    tar.extend([b't'; 512]);
    tar.extend([0u8; 1024]);
    assert!(tar.len() < 4096 + 1024);
    let mut want = vec![0u8; real as usize];
    want[..512].fill(b'h');
    want[real as usize - 512..].fill(b't');

    let b = side().await;
    b.service
        .import_tar(spooled(&tar), Some("holes"), &[], None)
        .await
        .unwrap();
    let path = b.store.get_path(&vid(&want)).expect("the file is stored");
    assert_eq!(std::fs::read(&path).unwrap(), want);
    let probe = tempfile::tempfile_in(path.parent().unwrap()).unwrap();
    probe.set_len(1 << 20).unwrap();
    if probe.metadata().unwrap().blocks() > 0 {
        eprintln!("no holes in the file system of the store: skipped");
        return;
    }
    let blocks = std::fs::metadata(&path).unwrap().blocks();
    assert!(blocks * 512 < 1 << 20, "{blocks} blocks of 512 bytes");
}

#[tokio::test]
async fn test_import_of_nothing_is_an_empty_image() {
    let b = side().await;
    let id = b
        .service
        .import_tar(spooled(b""), Some("empty:1"), &[], None)
        .await
        .unwrap();
    let image = b.service.get(&id).await.unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&image.manifest).unwrap();
    assert_eq!(manifest["layers"].as_array().map(Vec::len), Some(1));
    assert!(b.service.get("localhost/empty:1").await.is_ok());
}

#[tokio::test]
async fn test_import_refuses_what_is_not_a_tar_or_a_bad_change() {
    let b = side().await;
    assert!(b
        .service
        .import_tar(spooled(b"junk junk junk"), None, &[], None)
        .await
        .is_err());
    assert!(b
        .service
        .import_tar(spooled(&rootfs_tar()), None, &["FROM scratch".into()], None)
        .await
        .is_err());
    assert!(b
        .service
        .import_tar(spooled(&rootfs_tar()), Some("img@sha256:00"), &[], None)
        .await
        .is_err());
    assert!(b.db.list_images().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_matching_tag_follows_short_names() {
    let b = side().await;
    let id = b
        .service
        .import_tar(spooled(&rootfs_tar()), Some("foo"), &[], None)
        .await
        .unwrap();
    b.db.insert_image_tag(&velarx_db::ImageTag {
        repository: "quay.io/libpod/alpine".into(),
        tag: "latest".into(),
        image_id: id.clone(),
    })
    .await
    .unwrap();
    let repo = |r: &str| {
        let s = b.service.clone();
        let id = id.clone();
        let r = r.to_string();
        async move {
            let tags = s.get_tags(&id).await.unwrap();
            s.matching_tag(&r, &tags).map(|t| t.repository)
        }
    };
    assert_eq!(repo("foo").await.as_deref(), Some("localhost/foo"));
    assert_eq!(
        repo("localhost/foo:latest").await.as_deref(),
        Some("localhost/foo")
    );
    assert_eq!(
        repo("alpine").await.as_deref(),
        Some("quay.io/libpod/alpine")
    );
    assert_eq!(repo("docker.io/library/foo").await, None);
    assert_eq!(repo("foo:other").await, None);
}

#[tokio::test]
async fn test_import_for_a_platform() {
    let b = side().await;
    let platform = velarx_registry::target::Platform {
        os: "linux".into(),
        arch: "arm64".into(),
        variant: Some("v8".into()),
    };
    let id = b
        .service
        .import_tar_for(
            spooled(&rootfs_tar()),
            Some("arm:1"),
            &[],
            None,
            Some(&platform),
            None,
        )
        .await
        .unwrap();
    let image = b.service.get(&id).await.unwrap();
    let config: serde_json::Value = serde_json::from_str(&image.config).unwrap();
    assert_eq!(config["architecture"], "arm64");
    assert_eq!(config["os"], "linux");
    assert_eq!(config["variant"], "v8");
}

/// `import --digest sha512`: the layer, its diff id, the configuration and
/// the manifest are SHA-512, and the id has 128 digits.
#[tokio::test]
async fn test_import_with_sha512_digests() {
    use velarx_types::digest::{Algorithm, Digest};
    let b = side().await;
    let tar = rootfs_tar();
    for (digest, alg, len) in [
        (Some("sha512"), Algorithm::Sha512, 128),
        (Some("sha256"), Algorithm::Sha256, 64),
        (None, Algorithm::Sha256, 64),
    ] {
        let id = b
            .service
            .import_tar_for(spooled(&tar), None, &[], None, None, digest)
            .await
            .unwrap();
        assert_eq!(id.len(), len);
        let image = b.service.get(&id).await.unwrap();
        assert_eq!(image.manifest_digest.alg(), alg);
        assert_eq!(image.manifest_digest.hex(), id);
        let m: velarx_types::OciManifest = serde_json::from_str(&image.manifest).unwrap();
        assert_eq!(m.config.digest, Digest::of(alg, image.config.as_bytes()));
        assert_eq!(m.layers[0].digest, Digest::of(alg, &tar));
        let config: serde_json::Value = serde_json::from_str(&image.config).unwrap();
        assert_eq!(
            config["rootfs"]["diff_ids"][0],
            Digest::of(alg, &tar).to_string()
        );
    }
    let e = b
        .service
        .import_tar_for(spooled(&tar), None, &[], None, None, Some("md5"))
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("unknown digest algorithm `md5`"), "{e}");
}

/// A tarball received is written to a file with no name in the staging
/// area: the file is not on the disk once it is closed.
#[tokio::test]
async fn test_a_received_tarball_has_no_name() {
    let e = env().await;
    let mut f = e.service.spool().unwrap();
    f.write_all(&[1u8; 1 << 20]).unwrap();
    assert_eq!(e.staged_leftovers(), 0);
    drop(f);
    assert_eq!(e.staged_leftovers(), 0);
}
