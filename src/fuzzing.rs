// SPDX-License-Identifier: Apache-2.0
//! The parsers that take untrusted bytes, each behind a function of a byte
//! slice, for the fuzz targets of `fuzz/` (cargo-fuzz) and for the replay of
//! their corpora and the randomized tests of `tests/integration/fuzz_corpus.rs`.
//!
//! A function must never panic, whatever its input: the targets turn a
//! panic into a crash.  What a parser accepts is used a little (iterated,
//! emitted again) so that the code after the parse runs too.

use std::io::{BufReader, Cursor, Read};

/// The names of the targets, as `fuzz/fuzz_targets/NAME.rs` and the
/// directories of `fuzz/corpus/` name them.
pub const TARGETS: [&str; 23] = [
    "tar",
    "sparse",
    "tarsplit",
    "multipart",
    "toc",
    "table",
    "manifest",
    "challenge",
    "registries_conf",
    "policy",
    "containerfile",
    "request_line",
    "dns",
    "archive",
    "openpgp",
    "sigstore",
    "fetcher",
    "fetcher_reply",
    "cdi",
    "hooks",
    "api_body",
    "monitor_call",
    "digest",
];

/// Run the target `name` on `data`; false for a name that is no target.
pub fn run(name: &str, data: &[u8]) -> bool {
    match name {
        "tar" => tar(data),
        "sparse" => sparse(data),
        "tarsplit" => tarsplit(data),
        "multipart" => multipart(data),
        "toc" => toc(data),
        "table" => table(data),
        "manifest" => manifest(data),
        "challenge" => challenge(data),
        "registries_conf" => registries_conf(data),
        "policy" => policy(data),
        "containerfile" => containerfile(data),
        "request_line" => request_line(data),
        "dns" => dns(data),
        "archive" => archive(data),
        "openpgp" => openpgp(data),
        "sigstore" => sigstore(data),
        "fetcher" => fetcher(data),
        "fetcher_reply" => fetcher_reply(data),
        "cdi" => cdi(data),
        "hooks" => hooks(data),
        "api_body" => api_body(data),
        "monitor_call" => monitor_call(data),
        "digest" => digest(data),
        _ => return false,
    }
    true
}

/// The text of a digest, as a registry, a manifest, a user or a peer gives it:
/// what parses is the digest it prints back, and the forms the annotations and
/// the TOCs write are read from the same text.
pub fn digest(data: &[u8]) {
    use velarx_types::digest::{parse_composefs_annotation, parse_toc_fsverity, Digest};
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(d) = text.parse::<Digest>() {
        assert_eq!(d.to_string().parse::<Digest>(), Ok(d));
        assert_eq!(text, d.to_string());
        let _ = (d.hex(), d.short(), d.file_name(), d.plain());
    }
    if let Ok(d) = Digest::parse_fsverity(text) {
        assert_eq!(text, d.to_string());
        assert!(d.to_string().parse::<Digest>().is_err());
    }
    let _ = parse_toc_fsverity(text);
    let _ = parse_composefs_annotation(text);
    let _ = velarx_types::ImageReference::parse(text);
}

/// A layer: its entries and their contents, as a pull reads them.
pub fn tar(data: &[u8]) {
    let mut r = velarx_content::pull::tar::TarReader::new(Cursor::new(data));
    let mut buf = [0u8; 4096];
    for _ in 0..10_000 {
        match r.next_entry() {
            Ok(Some(_)) => {
                // the contents of the entry
                while let Ok(n) = r.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                }
            }
            _ => break,
        }
    }
    let _ = r.finish();
}

/// A tar a user hands over (a build context, `cp`, a volume), its sparse
/// entries made into files: the name, the size, the map and the data.
pub fn sparse(data: &[u8]) {
    use std::io::Seek;
    let Ok(mut out) = tempfile::tempfile() else {
        return;
    };
    let mut ar = velarx_wire::sparse::archive(Cursor::new(data));
    let Ok(entries) = ar.entries() else {
        return;
    };
    for e in entries.take(1000) {
        let Ok(mut e) = e else {
            return;
        };
        let _ = velarx_wire::sparse::path(&mut e);
        let _ = velarx_wire::sparse::real_size(&mut e);
        if out.set_len(0).and_then(|()| out.rewind()).is_err() {
            return;
        }
        // (a few MiB: what it writes goes to a temporary file)
        let _ = velarx_wire::sparse::copy(&mut e, &mut out, 16 << 20);
    }
}

/// The tar-split of a zstd:chunked layer (JSON lines), read and replayed
/// with zeros for the files.
pub fn tarsplit(data: &[u8]) {
    use velarx_content::pull::tarsplit::{Contents, Entries, Replay};

    struct Zeros;
    impl Contents for Zeros {
        fn open(&mut self, _: &str, size: u64) -> std::io::Result<Box<dyn Read + Send>> {
            Ok(Box::new(std::io::repeat(0).take(size.min(1 << 20))))
        }
    }

    let entries = Entries::new(BufReader::new(Cursor::new(data)));
    for e in entries.take(100_000) {
        if e.is_err() {
            break;
        }
    }
    let mut replay = Replay::new(Entries::new(BufReader::new(Cursor::new(data))), Zeros);
    let _ = std::io::copy(&mut replay.by_ref().take(16 << 20), &mut std::io::sink());
}

/// A multipart/byteranges answer: the first byte is the number of ranges
/// asked, the rest the body, fed in pieces.
pub fn multipart(data: &[u8]) {
    let Some((&n, body)) = data.split_first() else {
        return;
    };
    let ranges: Vec<std::ops::Range<u64>> = (0..u64::from(n % 8) + 1)
        .map(|i| i * 100..i * 100 + 50)
        .collect();
    let mut m = velarx_content::pull::ranges::Multipart::new("BOUNDARY", &ranges);
    let mut out = Vec::new();
    for piece in body.chunks(37) {
        if m.push(bytes::Bytes::copy_from_slice(piece), &mut out)
            .is_err()
        {
            return;
        }
        out.clear();
    }
    let _ = m.is_done();
}

/// The table of contents of a zstd:chunked layer, as its checks see it:
/// the input is the compressed TOC (its digest is the one announced).
pub fn toc(data: &[u8]) {
    let info = velarx_content::pull::chunked::Info {
        toc: (0, data.len() as u64, 0),
        checksum: velarx_types::digest::Digest::of(velarx_types::digest::Algorithm::Sha256, data),
        tarsplit: None,
        table: false,
    };
    let _ = velarx_content::pull::chunked::verify_metadata(
        &info,
        data,
        Vec::new(),
        &velarx_types::digest::Digest::of(velarx_types::digest::Algorithm::Sha256, b""),
        u64::MAX,
    );
    // and as JSON, as the store reads it
    let _ = serde_json::from_slice::<velarx_storage::Toc>(data);
}

/// The binary table of a zstd:chunked layer.  A table that is accepted is
/// the one encoding of the table of contents it decodes to: written again,
/// it is the same bytes (its optional features aside).
pub fn table(data: &[u8]) {
    use velarx_storage::table;
    let Ok(toc) = table::decode(data, u64::MAX) else {
        return;
    };
    let alg = table::head(data).expect("the header of a table").alg;
    let mut again = table::encode(&toc, alg).expect("a decoded table is a table");
    again[16..20].copy_from_slice(&data[16..20]);
    assert!(
        again == data,
        "a table that is not its one encoding is accepted"
    );
    // (its entries are in the form a layer keeps)
    if !toc.is_canonical() {
        let layer = velarx_types::digest::Digest::of(alg, data);
        let kept = velarx_content::pull::lazy::toc_view(toc.clone(), alg, &layer)
            .expect("the entries of a table are those of a layer");
        assert!(
            serde_json::to_value(&kept).ok() == serde_json::to_value(&toc).ok(),
            "a table gives entries that a layer keeps otherwise"
        );
    }
}

/// A manifest or an index, and the choice of a platform.
pub fn manifest(data: &[u8]) {
    let _ = serde_json::from_slice::<velarx_types::OciManifest>(data);
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
        if let Some(m) = v["manifests"].as_array() {
            let host = velarx_registry::target::Platform::host();
            let _ = velarx_registry::target::select_platform(m, &host);
        }
    }
    for layer in serde_json::from_slice::<velarx_types::OciManifest>(data)
        .map(|m| m.layers)
        .unwrap_or_default()
    {
        let _ = velarx_content::pull::chunked::parse_info(&layer);
    }
}

/// The WWW-Authenticate header of a registry.
pub fn challenge(data: &[u8]) {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = velarx_registry::target::Challenge::parse(s);
    }
}

/// registries.conf, and the lookups made with it.
pub fn registries_conf(data: &[u8]) {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(c) = velarx_registry::config::RegistriesConfig::parse(s) {
        let _ = c.check();
        let _ = c.find_registry("docker.io/library/alpine:latest");
        let _ = c.is_blocked("example.com");
    }
}

/// policy.json, and the requirements of a few images.
pub fn policy(data: &[u8]) {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(p) = velarx_signature::SignaturePolicy::parse(s) {
        for name in [
            "docker.io/library/alpine:latest",
            "localhost:5000/a/b@sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            if let Ok(reference) = velarx_signature::reference::DockerRef::parse_normalized(name) {
                let _ = p.requirements_for("docker", &reference);
            }
        }
    }
}

/// A Containerfile.
pub fn containerfile(data: &[u8]) {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = velarx_wire::parse::Containerfile::parse(s);
    }
}

/// The first line of an HTTP request, as the API fixes it for hyper.
pub fn request_line(data: &[u8]) {
    let _ = velarx_proto::request_line::fix_request_line(data);
}

/// A DNS query to the server of the bridge networks.
pub fn dns(data: &[u8]) {
    let zone = [velarx_netkernel::dns::Record {
        names: vec!["web".into()],
        ips: vec![std::net::Ipv4Addr::new(10, 88, 0, 2)],
        ips6: Vec::new(),
    }];
    let size = data.first().map_or(512, |b| usize::from(*b) * 8);
    let _ = velarx_netkernel::dns::answer(&zone, data, size);
    let _ = velarx_netkernel::dns::servfail(data);
    if let Some(q) = velarx_netkernel::dns::question(data) {
        let _ = velarx_netkernel::dns::head(data, &q, 2);
    }
}

/// An image archive (docker save, oci-archive), opened as `load` opens it.
pub fn archive(data: &[u8]) {
    use std::io::{Seek, Write};
    let Ok(mut f) = tempfile::tempfile() else {
        return;
    };
    if f.write_all(data).and_then(|()| f.rewind()).is_err() {
        return;
    }
    let Ok(dir) = tempfile::tempdir() else {
        return;
    };
    if let Ok(a) =
        velarx_content::archive::Archive::open(f, &std::fs::File::open(dir.path()).unwrap(), |_| {
            1 << 30
        })
    {
        let _ = a.find("manifest.json");
        let _ = a.blob(
            &velarx_types::digest::Digest::of(
                velarx_types::digest::Algorithm::Sha256,
                b"index.json",
            ),
            1 << 20,
        );
    }
}

/// An OpenPGP signature (simple signing) and keyring: the first byte
/// splits the input between them.
pub fn openpgp(data: &[u8]) {
    use velarx_signature::openpgp;
    let Some((&n, rest)) = data.split_first() else {
        return;
    };
    let at = (usize::from(n) * rest.len()) / 256;
    let (keyring, message) = rest.split_at(at);
    let keys = openpgp::parse_keyring(keyring).unwrap_or_default();
    let _ = openpgp::verify_message(&keys, message, 1_800_000_000);
    let _ = openpgp::verify_message(&[], data, 1_800_000_000);
}

/// A signature of lookaside storage, its payload, and a Rekor SET.
pub fn sigstore(data: &[u8]) {
    use velarx_signature::sigstore;
    if let Ok(sig) = sigstore::Signature::from_blob(data) {
        let _ = sig.to_blob();
        if let sigstore::Signature::Sigstore(s) = &sig {
            let _ = sigstore::parse_payload(&s.payload, sigstore::SIGSTORE_TYPE);
            if let Some(set) = s.annotations.get(sigstore::SET_ANNOTATION) {
                let _ = sigstore::verify_rekor_set(&[], set.as_bytes(), b"", b"", &s.payload);
            }
        }
    }
    let _ = sigstore::parse_payload(data, sigstore::SIMPLE_SIGNING_TYPE);
    let _ = sigstore::verify_rekor_set(&[], data, b"", b"", b"");
}

/// What a content source says over `org.velarx.Fetcher`: the first byte
/// picks the type of the JSON that follows; a text is checked as the
/// digest or the manifest reference of a request.
pub fn fetcher(data: &[u8]) {
    use velarx_content::fetcher::proto as p;
    let Some((&n, rest)) = data.split_first() else {
        return;
    };
    fn again<T: serde::Serialize + serde::de::DeserializeOwned>(rest: &[u8]) {
        if let Ok(v) = serde_json::from_slice::<T>(rest) {
            let _ = serde_json::to_vec(&v);
        }
    }
    match n % 13 {
        0..=8 => {
            again::<p::Tagged>(rest);
            again::<p::Found>(rest);
            again::<p::Downloaded>(rest);
        }
        9 => {
            // the repository of a call about a registry, as the server
            // checks it
            if let Ok(remote) = serde_json::from_slice::<p::Remote>(rest) {
                let _ = velarx_content::serve_registry::checked_remote(&remote);
                let _ = serde_json::to_vec(&remote);
            }
        }
        10 => again::<velarx_content::pusher::push::ProbeReply>(rest),
        11 => again::<velarx_content::pusher::push::PutReply>(rest),
        12 => {
            again::<velarx_content::pusher::push::CommitReply>(rest);
            again::<velarx_proto::info::Info>(rest);
            again::<p::Ack>(rest);
        }
        _ => {
            if let Ok(s) = std::str::from_utf8(rest) {
                let _ = velarx_content::serve_registry::checked_digest(s);
                let _ = velarx_content::serve_registry::checked_reference(s);
                let _ = velarx_content::serve_push::checked_name(s);
                let _ = velarx_content::serve_push::checked_object(
                    &velarx_content::pusher::push::Object {
                        digest: s.to_string(),
                        size: 0,
                        media_type: s.to_string(),
                        role: velarx_content::pusher::push::Role::Unknown,
                        known_at: Some(vec![s.to_string()]),
                    },
                );
                let _ = velarx_content::serve_registry::checked_remote(&p::Remote {
                    repository: s.to_string(),
                    tls_verify: None,
                    access: None,
                });
            }
        }
    }
}

/// A message of a fetcher as the engine's client reads it: split at its
/// NULs, each parsed as a reply of `Fetch`, `Get`, `Probe` or `GetInfo`.
pub fn fetcher_reply(data: &[u8]) {
    use velarx_content::fetcher::fetch;
    for message in data.split(|&b| b == 0).take(64) {
        let _ = velarx_wire::varlink::parse_reply::<fetch::FetchReply>(message);
        let _ = velarx_wire::varlink::parse_reply::<fetch::Manifest>(message);
        let _ = velarx_wire::varlink::parse_reply::<fetch::Item>(message);
        let _ = velarx_wire::varlink::parse_reply::<fetch::ProbeReply>(message);
        let _ = velarx_wire::varlink::parse_reply::<velarx_proto::info::Info>(message);
    }
}

/// What a client sends to a monitor, as the monitor reads it: messages
/// split at their NULs, each parsed as a call of org.velarx.Monitor; and
/// each message as a reply of a monitor, as its clients read them.
pub fn monitor_call(data: &[u8]) {
    use velarx_wire::monitor::iface;
    use velarx_wire::varlink::parse_reply;
    for message in data.split(|&b| b == 0).take(64) {
        if message.len() > iface::MAX_CALL {
            continue;
        }
        if let Ok(call) = iface::parse_request(message) {
            let _ = format!("{:?} {} {}", call.request, call.more, call.oneway);
        }
        let _ = parse_reply::<iface::AttachReply>(message);
        let _ = parse_reply::<iface::ExecReply>(message);
        let _ = parse_reply::<iface::Info>(message);
        if let Ok(r) = parse_reply::<iface::Subscribed>(message) {
            let _ = r.parameters.event.and_then(|e| e.into_event());
        }
    }
}

/// A CDI spec (JSON or YAML: the first byte picks), validated, found in a
/// spec directory and written into a runtime spec.
pub fn cdi(data: &[u8]) {
    use velarx_runtime::cdi;
    let Some((&n, rest)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    let yaml = n & 1 == 1;
    let Ok(spec) = cdi::parse_spec(text, yaml) else {
        return;
    };
    if spec.validate().is_err() {
        return;
    }
    let Ok(dir) = tempfile::tempdir() else {
        return;
    };
    let name = if yaml { "spec.yaml" } else { "spec.json" };
    if std::fs::write(dir.path().join(name), text).is_err() {
        return;
    }
    let dirs = [dir.path().to_path_buf()];
    let catalog = cdi::scan(&dirs);
    let _ = catalog.error_lines();
    let devices = catalog.device_names();
    if let Ok(edits) = cdi::resolve(&devices, &dirs) {
        let mut runtime = serde_json::json!({"process": {"env": ["A=1"]}, "linux": {}});
        cdi::apply(&mut runtime, &edits, n & 2 == 2);
    }
}

/// An OCI hook file, and the container it is matched with.
pub fn hooks(data: &[u8]) {
    use velarx_core::services::hooks;
    if let Ok(h) = hooks::parse(data) {
        let annotations = std::collections::HashMap::from([("a".to_string(), "b".to_string())]);
        let _ = h.when.matches(&annotations, Some("/bin/sh"), true);
        let _ = h.when.matches(&annotations, None, false);
        let mut spec = serde_json::json!({"annotations": {"a": "b"}, "process": {"args": ["x"]}});
        let all = std::collections::BTreeMap::from([("h".to_string(), h)]);
        let _ = hooks::inject(&mut spec, &all, true);
    }
}

/// The bodies of the API frontends' requests to the engine: build
/// parameters, pod specs, and the JSON as Go's decoder reads it.
pub fn api_body(data: &[u8]) {
    let Some((&n, rest)) = data.split_first() else {
        return;
    };
    match n % 3 {
        0 => {
            let _ = serde_json::from_slice::<velarx_proto::buildspec::BuildSpec>(rest);
        }
        1 => {
            let _ = velarx_proto::pod::PodSpec::from_document(rest);
        }
        _ => match velarx_proto::godecode::first_value(rest) {
            Ok(_) => {
                let _ = velarx_proto::godecode::from_slice::<
                    std::collections::BTreeMap<String, Vec<String>>,
                >(rest);
            }
            Err(e) => {
                let _ = velarx_proto::godecode::go_error(rest, &e);
            }
        },
    }
}
