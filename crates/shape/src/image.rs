// SPDX-License-Identifier: Apache-2.0
//! The images: podman's ImageSummary and ImageData (libpod's list and
//! inspect), Docker's ImageSummary and InspectResponse, the entries of
//! their histories, and Docker's DistributionInspect.

use crate::string_map;
use crate::time::rfc3339;
use serde_json::{json, Map, Value};
use velarx_proto::workload::{
    ImageConfigRecord, ImageHistoryEntry, ImagePlatform, ImageRecord, ImageTreeRecord, RemoteImage,
};

/// The version of Docker's API is at least `major.minor` (none: the
/// newest).
fn at_least(version: Option<(u32, u32)>, major: u32, minor: u32) -> bool {
    match version {
        None => true,
        Some((a, b)) => a > major || (a == major && b >= minor),
    }
}

/// When the image was made, else stored (podman's `Created`).
fn made_ns(r: &ImageRecord) -> i64 {
    match r.created_ns {
        0 => r.stored_ns,
        n => n,
    }
}

/// The keys of an object whose values are empty objects (Go's
/// `map[string]struct{}`).
fn set(keys: &[String]) -> Value {
    Value::Object(keys.iter().map(|k| (k.clone(), json!({}))).collect())
}

/// The configuration as Go's OCI ImageConfig writes it (what is empty is
/// left out).
pub fn config(c: &ImageConfigRecord) -> Value {
    let mut m = Map::new();
    let mut text = |k: &str, v: &str| {
        if !v.is_empty() {
            m.insert(k.into(), json!(v));
        }
    };
    text("User", &c.user);
    text("WorkingDir", &c.working_dir);
    text("StopSignal", &c.stop_signal);
    if !c.exposed_ports.is_empty() {
        m.insert("ExposedPorts".into(), set(&c.exposed_ports));
    }
    if !c.volumes.is_empty() {
        m.insert("Volumes".into(), set(&c.volumes));
    }
    for (k, v) in [
        ("Env", &c.env),
        ("Entrypoint", &c.entrypoint),
        ("Cmd", &c.cmd),
    ] {
        if !v.is_empty() {
            m.insert(k.into(), json!(v));
        }
    }
    if !c.labels.is_empty() {
        m.insert("Labels".into(), string_map(&c.labels));
    }
    if c.args_escaped {
        m.insert("ArgsEscaped".into(), json!(true));
    }
    for (k, v) in [("OnBuild", &c.on_build), ("Shell", &c.shell)] {
        if !v.is_empty() {
            m.insert(k.into(), json!(v));
        }
    }
    if let Some(h) = &c.healthcheck {
        let mut hc = Map::new();
        hc.insert("Test".into(), json!(h.test));
        for (k, v) in [
            ("Interval", h.interval_ns),
            ("Timeout", h.timeout_ns),
            ("StartPeriod", h.start_period_ns),
            ("StartInterval", h.start_interval_ns),
            ("Retries", h.retries),
        ] {
            if v != 0 {
                hc.insert(k.into(), json!(v));
            }
        }
        m.insert("Healthcheck".into(), Value::Object(hc));
    }
    Value::Object(m)
}

/// A step of the history as Go's OCI History writes it.
fn history_step(h: &ImageHistoryEntry) -> Value {
    let mut m = Map::new();
    if h.created_ns > 0 {
        m.insert("created".into(), json!(rfc3339(h.created_ns)));
    }
    for (k, v) in [
        ("created_by", &h.created_by),
        ("author", &h.author),
        ("comment", &h.comment),
    ] {
        if !v.is_empty() {
            m.insert(k.into(), json!(v));
        }
    }
    if h.empty_layer {
        m.insert("empty_layer".into(), json!(true));
    }
    Value::Object(m)
}

/// podman's ImageSummary, an entry of libpod's list of images (a manifest
/// list has no platform of its own).
pub fn libpod_summary(r: &ImageRecord) -> Value {
    // podman's Names: every name, also those with a digest (RepoTags: the
    // tags only)
    let names: Vec<&String> = r.names.iter().chain(&r.digest_names).collect();
    if r.manifest_list {
        return json!({
            "Id": r.id,
            "ParentId": "",
            "RepoTags": r.names,
            "RepoDigests": r.digests,
            "Created": made_ns(r) / 1_000_000_000,
            "Size": 0,
            "SharedSize": 0,
            "VirtualSize": 0,
            "Labels": {},
            "Containers": 0,
            "Dangling": names.is_empty(),
            "Digest": r.digest,
            "Names": names,
            "History": [],
            "IsManifestList": true,
        });
    }
    let mut s = json!({
        "Id": r.id,
        "ParentId": r.parent_id,
        "RepoTags": r.names,
        "RepoDigests": r.digests,
        "Created": made_ns(r) / 1_000_000_000,
        "Size": r.size,
        "SharedSize": 0,
        "VirtualSize": r.size,
        "Labels": string_map(&r.labels),
        "Containers": r.containers,
        "Dangling": names.is_empty() && !r.has_children,
        "Arch": r.architecture,
        "Digest": r.digest,
        "Names": names,
        "Os": r.os,
        "History": r.names_history,
        "IsManifestList": false,
    });
    // podman's: only when it is
    if r.read_only {
        s["ReadOnly"] = json!(true);
    }
    s
}

/// Docker's ImageSummary of its API `version` (none: the newest); with
/// `shared_size` the size the image shares (podman's 0), else -1.
pub fn docker_summary(r: &ImageRecord, version: Option<(u32, u32)>, shared_size: bool) -> Value {
    let mut s = libpod_summary(r);
    if let Some(m) = s.as_object_mut() {
        m.insert("Id".into(), json!(crate::id_with_algorithm(&r.id)));
        if !r.parent_id.is_empty() {
            m.insert(
                "ParentId".into(),
                json!(crate::id_with_algorithm(&r.parent_id)),
            );
        }
        // podman's extensions stay, but those of libpod only
        for k in ["Arch", "Os", "IsManifestList"] {
            m.remove(k);
        }
        // Go leaves these out when they are empty
        for k in ["Names", "History", "Digest"] {
            let empty = match m.get(k) {
                Some(Value::Array(a)) => a.is_empty(),
                Some(Value::String(s)) => s.is_empty(),
                Some(Value::Null) => true,
                _ => false,
            };
            if empty {
                m.remove(k);
            }
        }
        // 1.42: -1 unless asked; VirtualSize is gone in 1.44
        if !shared_size {
            m.insert("SharedSize".into(), json!(-1));
        }
        if at_least(version, 1, 44) {
            m.remove("VirtualSize");
        }
    }
    s
}

/// podman's ImageData, libpod's inspect of an image.
pub fn libpod_inspect(r: &ImageRecord) -> Value {
    let mut o = json!({
        "Id": r.id,
        "Digest": r.digest,
        "RepoTags": r.names,
        "RepoDigests": r.digests,
        "Parent": "",
        "Comment": r.comment,
        "Created": rfc3339(made_ns(r)),
        "Config": config(&r.config),
        "Version": "",
        "Author": r.author,
        "Architecture": r.architecture,
        "Os": r.os,
        "Size": r.size,
        "VirtualSize": r.size,
        "GraphDriver": {"Name": r.graph_driver, "Data": {}},
        "RootFS": {"Type": "layers", "Layers": r.layers},
        "Labels": string_map(&r.labels),
        "Annotations": string_map(&r.annotations),
        "ManifestType": r.manifest_type,
        "User": r.config.user,
        "History": r.history.iter().map(history_step).collect::<Vec<_>>(),
        "NamesHistory": r.names_history,
        "IsManifestList": false,
    });
    // (podman's: the check of a Docker configuration, left out when none)
    if let Some(h) = o.pointer("/Config/Healthcheck").cloned() {
        o["Healthcheck"] = h;
    }
    if r.read_only {
        o["ReadOnly"] = json!(true);
    }
    // (velarx's: the digests the manifest states, as written; none: left out)
    if !r.composefs.is_empty() {
        o["Composefs"] = json!({
            "Layers": r.composefs.iter().map(|l| json!({"Digest": l.layer, "Fsverity": l.digests})).collect::<Vec<_>>(),
        });
    }
    o
}

/// Docker's inspect of an image, of its API `version` (none: the newest).
pub fn docker_inspect(r: &ImageRecord, version: Option<(u32, u32)>) -> Value {
    let mut data = libpod_inspect(r);
    if let Some(m) = data.as_object_mut() {
        m.insert("Id".into(), json!(crate::id_with_algorithm(&r.id)));
        // Created is left out from 1.44 when the configuration has none,
        // and is Go's zero time before
        if r.created_ns == 0 {
            if at_least(version, 1, 44) {
                m.remove("Created");
            } else {
                m.insert("Created".into(), json!(rfc3339(0)));
            }
        }
        if at_least(version, 1, 44) {
            m.remove("VirtualSize");
        }
        if !at_least(version, 1, 45) {
            let hostname: String = r.id.chars().take(11).collect();
            let volumes = if r.config.volumes.is_empty() {
                Value::Null
            } else {
                set(&r.config.volumes)
            };
            m.insert(
                "ContainerConfig".into(),
                json!({"Hostname": hostname, "Volumes": volumes}),
            );
        }
    }
    data
}

/// podman's HistoryResponse, an entry of the history of an image (the
/// newest first): libpod's ids, or with `docker` Docker's (`sha256:` before
/// every one, `<missing>` too).
pub fn history(h: &ImageHistoryEntry, docker: bool) -> Value {
    let id = if h.id.is_empty() {
        "<missing>"
    } else {
        h.id.as_str()
    };
    json!({
        "Id": if docker { crate::id_with_algorithm(id) } else { id.to_string() },
        "Created": h.created_ns / 1_000_000_000,
        "CreatedBy": h.created_by,
        "Tags": if h.id.is_empty() { Value::Null } else { json!(h.tags) },
        "Size": h.size,
        "Comment": h.comment,
    })
}

/// The first 12 characters of an id.
fn short(id: &str) -> &str {
    &id[..id.len().min(12)]
}

/// podman's text of `image tree`: the layers of the image and the images
/// they are the top layer of, or with `what_requires` the images built on
/// it.
pub fn tree(t: &ImageTreeRecord, what_requires: bool) -> String {
    let mut out = format!(
        "Image ID: {}\nTags:     [{}]\nSize:     {}\n",
        short(&t.id),
        t.names.join(" "),
        crate::container::human_size(t.size)
    );
    let branch = |i: usize, n: usize| if i + 1 == n { "└──" } else { "├──" };
    if what_requires {
        out.push_str("Images built on it\n");
        for (i, c) in t.children.iter().enumerate() {
            out.push_str(&format!(
                "{} ID: {} Tags: [{}]\n",
                branch(i, t.children.len()),
                short(&c.id),
                c.names.join(" ")
            ));
        }
    } else {
        out.push_str("Image Layers\n");
        for (i, l) in t.layers.iter().enumerate() {
            out.push_str(&format!(
                "{} ID: {} Size: {}",
                branch(i, t.layers.len()),
                short(&l.id),
                crate::container::human_size(l.size)
            ));
            if !l.top_of.is_empty() {
                out.push_str(&format!(" Top Layer of: [{}]", l.top_of.join(" ")));
            }
            out.push('\n');
        }
    }
    out
}

/// Docker's `DistributionInspect` of what a registry has for a name: the
/// descriptor of the manifest or index and the platforms of its instances.
pub fn distribution(d: &RemoteImage) -> Value {
    json!({
        "Descriptor": {"mediaType": d.media_type, "digest": d.digest, "size": d.size},
        "Platforms": d.platforms.iter().map(platform).collect::<Vec<_>>(),
    })
}

/// An OCI platform: the members that are empty are left out, but the
/// architecture and the OS.
fn platform(p: &ImagePlatform) -> Value {
    let mut o = Map::new();
    o.insert("architecture".into(), json!(p.architecture));
    o.insert("os".into(), json!(p.os));
    for (key, v) in [("os.version", &p.os_version), ("variant", &p.variant)] {
        if !v.is_empty() {
            o.insert(key.into(), json!(v));
        }
    }
    for (key, v) in [("os.features", &p.os_features), ("features", &p.features)] {
        if !v.is_empty() {
            o.insert(key.into(), json!(v));
        }
    }
    Value::Object(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> ImageRecord {
        ImageRecord {
            id: "9617696764".repeat(6) + "abcd",
            names: vec!["localhost/a:1".into()],
            digests: vec!["localhost/a@sha256:1".into()],
            digest: "sha256:1".into(),
            size: 1000,
            created_ns: 1_767_323_045_000_000_000,
            stored_ns: 1_767_323_046_000_000_000,
            os: "linux".into(),
            architecture: "amd64".into(),
            labels: [("l".to_string(), "v".to_string())].into(),
            config: ImageConfigRecord {
                user: "1000".into(),
                env: vec!["A=1".into()],
                cmd: vec!["sh".into()],
                volumes: vec!["/data".into()],
                labels: [("l".to_string(), "v".to_string())].into(),
                ..Default::default()
            },
            history: vec![ImageHistoryEntry {
                created_ns: 1_767_323_045_000_000_000,
                created_by: "ADD x".into(),
                ..Default::default()
            }],
            layers: vec!["sha256:d".into()],
            ..Default::default()
        }
    }

    #[test]
    fn the_graph_driver_of_an_image_is_the_drivers() {
        let r = ImageRecord {
            graph_driver: "overlay".into(),
            ..image()
        };
        assert_eq!(libpod_inspect(&r)["GraphDriver"]["Name"], "overlay");
        assert_eq!(docker_inspect(&r, None)["GraphDriver"]["Name"], "overlay");
    }

    #[test]
    fn libpod_s_summary_and_docker_s() {
        let mut r = image();
        let s = libpod_summary(&r);
        assert_eq!(s["Created"], 1_767_323_045);
        assert_eq!(s["Dangling"], false);
        assert_eq!(s["Labels"]["l"], "v");
        assert!(s.get("ReadOnly").is_none());
        r.names.clear();
        // (named by a pull by digest: in Names, not in RepoTags)
        r.digest_names = vec!["quay.io/a/b@sha256:d".into()];
        let s = libpod_summary(&r);
        assert_eq!(s["Dangling"], false);
        assert_eq!(s["Names"], json!(["quay.io/a/b@sha256:d"]));
        assert_eq!(s["RepoTags"], json!([]));
        r.digest_names.clear();
        assert_eq!(libpod_summary(&r)["Dangling"], true);
        r.has_children = true;
        assert_eq!(libpod_summary(&r)["Dangling"], false);
        r.created_ns = 0;
        assert_eq!(libpod_summary(&r)["Created"], 1_767_323_046);
        r.parent_id = "p".into();
        let d = docker_summary(&r, None, false);
        assert_eq!(d["Id"], format!("sha256:{}", r.id));
        assert_eq!(d["ParentId"], "sha256:p");
        assert_eq!(d["SharedSize"], -1);
        for gone in [
            "Arch",
            "Os",
            "IsManifestList",
            "Names",
            "History",
            "VirtualSize",
        ] {
            assert!(d.get(gone).is_none(), "{gone}");
        }
        assert_eq!(docker_summary(&r, Some((1, 43)), true)["VirtualSize"], 1000);
        assert_eq!(docker_summary(&r, Some((1, 43)), true)["SharedSize"], 0);
    }

    #[test]
    fn a_manifest_list_in_the_list() {
        let r = ImageRecord {
            id: "list".into(),
            names: vec!["localhost/l:1".into()],
            manifest_list: true,
            stored_ns: 2_000_000_000,
            created_ns: 2_000_000_000,
            ..Default::default()
        };
        let s = libpod_summary(&r);
        assert_eq!(s["IsManifestList"], true);
        assert_eq!(s["Created"], 2);
        assert!(s.get("Arch").is_none());
    }

    #[test]
    fn docker_s_settings_of_a_build_are_in_the_configuration() {
        use velarx_proto::workload::ImageHealthcheck;
        let c = ImageConfigRecord {
            on_build: vec!["RUN x".into()],
            shell: vec!["/bin/sh".into(), "-c".into()],
            healthcheck: Some(ImageHealthcheck {
                test: vec!["CMD".into(), "true".into()],
                interval_ns: 7,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            config(&c),
            json!({"OnBuild": ["RUN x"], "Shell": ["/bin/sh", "-c"],
                   "Healthcheck": {"Test": ["CMD", "true"], "Interval": 7}})
        );
    }

    #[test]
    fn libpod_s_inspect_and_docker_s() {
        let r = image();
        let i = libpod_inspect(&r);
        assert_eq!(i["Created"], "2026-01-02T03:04:05Z");
        assert_eq!(i["User"], "1000");
        assert_eq!(
            i["Config"],
            json!({"User": "1000", "Env": ["A=1"], "Cmd": ["sh"], "Volumes": {"/data": {}},
                   "Labels": {"l": "v"}})
        );
        assert_eq!(
            i["History"],
            json!([{"created": "2026-01-02T03:04:05Z", "created_by": "ADD x"}])
        );
        assert_eq!(i["RootFS"]["Layers"], json!(["sha256:d"]));
        assert_eq!(i["Annotations"], json!({}));
        let d = docker_inspect(&r, Some((1, 41)));
        assert_eq!(d["Id"], format!("sha256:{}", r.id));
        assert_eq!(d["ContainerConfig"]["Hostname"], "96176967649");
        assert_eq!(d["ContainerConfig"]["Volumes"], json!({"/data": {}}));
        assert_eq!(d["VirtualSize"], 1000);
        let d = docker_inspect(&r, None);
        assert!(d.get("ContainerConfig").is_none());
        assert!(d.get("VirtualSize").is_none());
        let made_at_no_time = ImageRecord { created_ns: 0, ..r };
        assert!(docker_inspect(&made_at_no_time, None)
            .get("Created")
            .is_none());
        assert_eq!(
            docker_inspect(&made_at_no_time, Some((1, 43)))["Created"],
            "0001-01-01T00:00:00Z"
        );
        assert_eq!(
            libpod_inspect(&made_at_no_time)["Created"],
            "2026-01-02T03:04:06Z"
        );
    }

    #[test]
    fn the_history_names_the_image_on_its_last_step() {
        let top = ImageHistoryEntry {
            id: "abc".into(),
            created_ns: 3_000_000_000,
            tags: vec!["localhost/a:1".into()],
            size: 5,
            ..Default::default()
        };
        let h = history(&top, false);
        assert_eq!(
            (&h["Id"], &h["Created"], &h["Tags"], &h["Size"]),
            (
                &json!("abc"),
                &json!(3),
                &json!(["localhost/a:1"]),
                &json!(5)
            )
        );
        assert_eq!(history(&top, true)["Id"], "sha256:abc");
        let below = ImageHistoryEntry::default();
        assert_eq!(history(&below, false)["Id"], "<missing>");
        assert_eq!(history(&below, true)["Id"], "sha256:<missing>");
        assert_eq!(history(&below, false)["Tags"], Value::Null);
    }

    #[test]
    fn the_platforms_of_a_distribution_are_oci_s() {
        let d = RemoteImage {
            media_type: "m".into(),
            digest: "sha256:d".into(),
            size: 7,
            platforms: vec![
                ImagePlatform {
                    architecture: "amd64".into(),
                    os: "windows".into(),
                    os_version: "10.0".into(),
                    os_features: vec!["win32k".into()],
                    ..Default::default()
                },
                ImagePlatform::default(),
            ],
        };
        assert_eq!(
            distribution(&d),
            json!({
                "Descriptor": {"mediaType": "m", "digest": "sha256:d", "size": 7},
                "Platforms": [
                    {"architecture": "amd64", "os": "windows", "os.version": "10.0",
                     "os.features": ["win32k"]},
                    {"architecture": "", "os": ""}
                ]
            })
        );
    }

    #[test]
    fn podman_s_tree() {
        use velarx_proto::workload::{ImageTreeChild, ImageTreeLayer};
        let t = ImageTreeRecord {
            id: "0123456789abcdef".into(),
            names: vec!["localhost/a:1".into()],
            size: 2000,
            layers: vec![
                ImageTreeLayer {
                    id: "aaaaaaaaaaaaaaaa".into(),
                    size: 1000,
                    top_of: vec![],
                },
                ImageTreeLayer {
                    id: "bbbbbbbbbbbbbbbb".into(),
                    size: 0,
                    top_of: vec!["localhost/a:1".into()],
                },
            ],
            children: vec![ImageTreeChild {
                id: "cccccccccccccccc".into(),
                names: vec![],
            }],
        };
        assert_eq!(
            tree(&t, false),
            "Image ID: 0123456789ab\nTags:     [localhost/a:1]\nSize:     2kB\nImage Layers\n\
             ├── ID: aaaaaaaaaaaa Size: 1kB\n\
             └── ID: bbbbbbbbbbbb Size: 0B Top Layer of: [localhost/a:1]\n"
        );
        assert_eq!(
            tree(&t, true),
            "Image ID: 0123456789ab\nTags:     [localhost/a:1]\nSize:     2kB\nImages built on it\n\
             └── ID: cccccccccccc Tags: []\n"
        );
    }
}
