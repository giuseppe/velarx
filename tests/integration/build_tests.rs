// SPDX-License-Identifier: Apache-2.0
//! Builds: the Containerfile parser, and the copies of COPY and ADD run by
//! the confined build worker.

use crate::common;

use std::io::Read;
use std::os::unix::fs::symlink;
use std::path::Path;
use velarx_core::services::build::copy::{CopyJob, Item, Source};
use velarx_core::services::build::worker::{JobSource, Runner};
use velarx_core::services::build::{Containerfile, Ignore};

fn job(source: Source, items: &[(&str, &str, bool)]) -> CopyJob {
    CopyJob {
        source,
        items: items
            .iter()
            .map(|(s, d, dir)| Item {
                src: s.to_string(),
                dst: d.to_string(),
                dest_dir: *dir,
                ..Default::default()
            })
            .collect(),
        chown: None,
        chmod: None,
        parents: Vec::new(),
        ignore: Vec::new(),
        add: false,
        limits: Default::default(),
        digest: false,
        unchanged_since: None,
    }
}

fn worker() -> Runner {
    Runner {
        exe: Some(common::worker().into()),
        ..Runner::default()
    }
}

#[test]
fn test_parse_a_multistage_containerfile() {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/build/Containerfile"),
    )
    .unwrap();
    let f = Containerfile::parse(&text).unwrap();
    assert_eq!(f.global_args.len(), 1);
    let names: Vec<_> = f.stages.iter().map(|s| s.name.clone()).collect();
    assert_eq!(names, [Some("builder".into()), Some("assets".into()), None]);
    assert_eq!(f.stages[2].base, "${BASE}");
    let kw: Vec<_> = f.stages[2]
        .instrs
        .iter()
        .map(|i| i.keyword.as_str())
        .collect();
    assert_eq!(kw[..4], ["LABEL", "ENV", "ENV", "WORKDIR"]);
    assert_eq!(f.stages[2].instrs.len(), 19);
    let ig = Ignore::parse(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/build/.containerignore"),
        )
        .unwrap(),
    );
    assert!(ig.ignored("files/secret.txt"));
    assert!(ig.ignored("files/x.tmp"));
    assert!(!ig.ignored("files/keep.tmp"));
}

#[tokio::test]
async fn test_copies_through_the_worker() {
    let d = tempfile::tempdir().unwrap();
    let (ctx, out, outside) = (
        d.path().join("ctx"),
        d.path().join("out"),
        d.path().join("outside"),
    );
    for p in [&ctx, &out, &outside] {
        std::fs::create_dir(p).unwrap();
    }
    std::fs::write(ctx.join("f"), "content").unwrap();
    std::fs::write(outside.join("secret"), "SECRET").unwrap();
    symlink(&outside, ctx.join("link")).unwrap();
    symlink(&outside, ctx.join("out-link")).unwrap();

    worker()
        .run(
            job(Source::Context, &[("f", "/app/", true)]),
            &out,
            JobSource::Dir(ctx.clone()),
            &velarx_core::services::Cancel::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(out.join("app/f")).unwrap(),
        "content"
    );

    // A link out of the context leads nowhere, `..` neither.
    let err = worker()
        .run(
            job(Source::Context, &[("link/secret", "/leak", false)]),
            &out,
            JobSource::Dir(ctx.clone()),
            &velarx_core::services::Cancel::default(),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no such file"), "{err}");
    assert!(!out.join("leak").exists());

    // A context archive with a link and a file below it.
    let mut b = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Symlink);
    h.set_size(0);
    b.append_link(&mut h, "l", &outside).unwrap();
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Regular);
    h.set_size(1);
    h.set_mode(0o644);
    b.append_data(&mut h, "l/planted", &b"x"[..]).unwrap();
    let archive = d.path().join("ctx.tar");
    std::fs::write(&archive, b.into_inner().unwrap()).unwrap();
    let unpacked = d.path().join("unpacked");
    std::fs::create_dir(&unpacked).unwrap();
    worker()
        .run(
            job(Source::Unpack, &[]),
            &unpacked,
            JobSource::Stream(std::fs::File::open(&archive).unwrap().into()),
            &velarx_core::services::Cancel::default(),
        )
        .await
        .unwrap();
    assert!(!outside.join("planted").exists());
    assert!(unpacked.join("l").is_dir());
}

#[tokio::test]
async fn test_fifos_and_xattrs_are_copied() {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    let d = tempfile::tempdir().unwrap();
    let (ctx, out) = (d.path().join("ctx"), d.path().join("out"));
    std::fs::create_dir(&ctx).unwrap();
    std::fs::create_dir(&out).unwrap();
    std::fs::write(ctx.join("f"), "x").unwrap();
    std::fs::create_dir(ctx.join("dir")).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        ctx.join("pipe"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o640),
        0,
    )
    .unwrap();
    // Not every file system of the tests has user xattrs.
    std::fs::create_dir(ctx.join("dir/sub")).unwrap();
    let xattrs = xattr::set(ctx.join("f"), "user.test", b"value").is_ok()
        && xattr::set(ctx.join("dir"), "user.dir", b"d").is_ok()
        && xattr::set(ctx.join("dir/sub"), "user.dir", b"s").is_ok();

    worker()
        .run(
            job(
                Source::Context,
                &[
                    ("f", "/app/", true),
                    ("pipe", "/app/", true),
                    ("dir", "/app/dir", false),
                ],
            ),
            &out,
            JobSource::Dir(ctx.clone()),
            &velarx_core::services::Cancel::default(),
        )
        .await
        .unwrap();
    let m = std::fs::symlink_metadata(out.join("app/pipe")).unwrap();
    assert!(m.file_type().is_fifo());
    assert_eq!(m.permissions().mode() & 0o7777, 0o640);
    if xattrs {
        assert_eq!(
            xattr::get(out.join("app/f"), "user.test")
                .unwrap()
                .as_deref(),
            Some(&b"value"[..])
        );
        // (the directory a directory is copied to is not the source
        // directory: its xattrs are not copied, its content's are, as
        // buildah's)
        assert_eq!(xattr::get(out.join("app/dir"), "user.dir").unwrap(), None);
        assert_eq!(
            xattr::get(out.join("app/dir/sub"), "user.dir")
                .unwrap()
                .as_deref(),
            Some(&b"s"[..])
        );
    }

    // From a tar (COPY --from, ADD of an archive): a fifo, the xattrs of
    // the PAX records, not the ones a copy does not keep.
    let mut b = tar::Builder::new(Vec::new());
    b.append_pax_extensions([
        ("SCHILY.xattr.user.k", &b"v"[..]),
        ("SCHILY.xattr.trusted.no", &b"x"[..]),
    ])
    .unwrap();
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Regular);
    h.set_size(1);
    h.set_mode(0o644);
    b.append_data(&mut h, "0/file", &b"y"[..]).unwrap();
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Fifo);
    h.set_size(0);
    h.set_mode(0o600);
    b.append_data(&mut h, "0/fifo", std::io::empty()).unwrap();
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Char);
    h.set_size(0);
    h.set_mode(0o666);
    h.set_device_major(1).unwrap();
    h.set_device_minor(3).unwrap();
    b.append_data(&mut h, "0/null", std::io::empty()).unwrap();
    let archive = d.path().join("from.tar");
    std::fs::write(&archive, b.into_inner().unwrap()).unwrap();
    let out2 = d.path().join("out2");
    std::fs::create_dir(&out2).unwrap();
    worker()
        .run(
            job(Source::Tar, &[("", "/t", false)]),
            &out2,
            JobSource::Stream(std::fs::File::open(&archive).unwrap().into()),
            &velarx_core::services::Cancel::default(),
        )
        .await
        .unwrap();
    assert!(std::fs::symlink_metadata(out2.join("t/fifo"))
        .unwrap()
        .file_type()
        .is_fifo());
    assert!(!out2.join("t/null").exists());
    if xattrs {
        assert_eq!(
            xattr::get(out2.join("t/file"), "user.k")
                .unwrap()
                .as_deref(),
            Some(&b"v"[..])
        );
    }
}

#[tokio::test]
async fn test_the_worker_stops_bombs_and_hangs() {
    let d = tempfile::tempdir().unwrap();
    let (ctx, out) = (d.path().join("ctx"), d.path().join("out"));
    std::fs::create_dir(&ctx).unwrap();
    std::fs::create_dir(&out).unwrap();
    // 64 MiB of zeros in a few KiB of gzip.
    let mut b = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Regular);
    h.set_size(64 << 20);
    h.set_mode(0o644);
    b.append_data(&mut h, "zeros", std::io::repeat(0).take(64 << 20))
        .unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    std::io::Write::write_all(&mut gz, &b.into_inner().unwrap()).unwrap();
    std::fs::write(ctx.join("bomb.tar.gz"), gz.finish().unwrap()).unwrap();
    let mut j = job(Source::Context, &[("bomb.tar.gz", "/x", false)]);
    j.add = true;
    j.limits.max_bytes = 1 << 20;
    let err = worker()
        .run(
            j,
            &out,
            JobSource::Dir(ctx.clone()),
            &velarx_core::services::Cancel::default(),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("bytes to write"), "{err}");

    // A stream that never ends: the worker is killed.
    let (reader, writer) = std::io::pipe().unwrap();
    let runner = Runner {
        exe: Some(common::worker().into()),
        timeout: std::time::Duration::from_secs(1),
    };
    let err = runner
        .run(
            job(Source::Unpack, &[]),
            &out,
            JobSource::Stream(reader.into()),
            &velarx_core::services::Cancel::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
    drop(writer);
}

#[test]
fn test_the_build_worker_is_confined() {
    use std::os::fd::AsRawFd;
    let d = tempfile::tempdir().unwrap();
    let dest = std::fs::File::open(d.path()).unwrap();
    let src = std::fs::File::open(d.path()).unwrap();
    let (dr, sr) = (dest.as_raw_fd(), src.as_raw_fd());
    let mut cmd = std::process::Command::new(common::worker());
    cmd.args(["build-worker", "--self-test"])
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped());
    velarx_sys::exec::place_fds(&mut cmd, vec![(dr, 3), (sr, 4)]);
    let mut child = cmd.spawn().unwrap();
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    child.wait().unwrap();
    let report = out
        .strip_prefix("self-test ")
        .unwrap_or_else(|| panic!("{out}"));
    let results: Vec<(String, bool)> = serde_json::from_str(report).unwrap();
    let failed: Vec<_> = results.iter().filter(|(_, ok)| !ok).collect();
    assert!(failed.is_empty(), "{failed:?}");
    assert!(results.len() >= 10);
}

#[test]
fn test_the_git_helper_is_confined() {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    let d = tempfile::tempdir().unwrap();
    let dest = std::fs::File::open(d.path()).unwrap();
    let raw = dest.as_raw_fd();
    let mut cmd = std::process::Command::new(common::worker());
    cmd.arg("git-clone")
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    velarx_sys::exec::place_fds(&mut cmd, vec![(raw, 3)]);
    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            br#"{"source":{"url":"https://h/r.git","reference":"HEAD","subdir":""},"max_bytes":1048576,"max_entries":1000,"ssh_auth_sock":null,"known_hosts":null,"self_test":true}"#,
        )
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let out = String::from_utf8_lossy(&out.stdout);
    let report = out
        .strip_prefix("self-test ")
        .unwrap_or_else(|| panic!("{out}"));
    let results: Vec<(String, bool)> = serde_json::from_str(report).unwrap();
    let failed: Vec<_> = results.iter().filter(|(_, ok)| !ok).collect();
    assert!(failed.is_empty(), "{failed:?}");
    assert!(results.len() >= 10);
}

/// The progress a build sends while it pulls its base, as a command renders
/// it.
#[tokio::test]
async fn test_the_base_pull_of_a_build_tells_its_progress() {
    use crate::common::{build_chunked, build_gzip, env, sample, Item, GZIP, ZSTD};
    use velarx_core::services::build::{BuildContext, BuildOptions, BuildProgress};
    let e = env().await;
    let base = build_chunked(&sample());
    let upper = build_gzip(&[Item::File {
        name: "usr/top",
        data: b"top\n".to_vec(),
        chunk: 4096,
    }]);
    e.publish(&[&base, &upper], &[ZSTD, GZIP]);

    let tmp = tempfile::tempdir().unwrap();
    let svc = build_service(&e, tmp.path());
    let context = tmp.path().join("context");
    std::fs::create_dir(&context).unwrap();
    std::fs::write(
        context.join("Containerfile"),
        format!("FROM {}/test:latest\nLABEL a=b\n", e.host),
    )
    .unwrap();
    let ctx = BuildContext::new(&context, None).unwrap();

    let (tx, mut rx) = tokio::sync::mpsc::channel(256);
    let opts = BuildOptions {
        tls_verify: false,
        ..Default::default()
    };
    let collector = tokio::spawn(async move {
        let mut events = Vec::new();
        while let Some(p) = rx.recv().await {
            events.push(p);
        }
        events
    });
    svc.build(&ctx, &opts, Some(tx), Default::default())
        .await
        .unwrap();
    let events = collector.await.unwrap();

    // the blobs of the FROM step: after its line, before the next step
    // (whose commit reports the layers of the base again)
    let pulling = events
        .iter()
        .position(
            |p| matches!(p, BuildProgress::Report { output } if output.starts_with("Pulling ")),
        )
        .expect("the build says it pulls the base");
    let blobs: Vec<_> = events[pulling..]
        .iter()
        .take_while(|p| !matches!(p, BuildProgress::StepStarted { .. }))
        .filter_map(|p| match p {
            BuildProgress::Blob(b) if !b.subject.to_string().is_empty() => Some(b),
            _ => None,
        })
        .collect();
    let layers = [common::sha(&base.blob), common::sha(&upper.blob)];
    for d in &layers {
        assert!(
            blobs
                .iter()
                .any(|b| b.subject.to_string() == d.to_string() && b.status == "complete"),
            "{d} is pulled: {blobs:?}"
        );
    }
    let text = Text::default();
    let mut renderer = velarx::cli::progress::Renderer::lines_to(Box::new(text.clone()));
    for b in &blobs {
        use velarx_proto::workload::{TransferProgress, TransferStatus};
        let (status, message) = match b.status.as_str() {
            "downloading" => (TransferStatus::Downloading, String::new()),
            "exists" => (TransferStatus::Exists, String::new()),
            "complete" => (TransferStatus::Complete, String::new()),
            s => (TransferStatus::Phase, s.to_string()),
        };
        renderer.event(&TransferProgress {
            layer: b.subject.to_string(),
            status,
            message,
            current_bytes: b.current_bytes,
            total_bytes: b.total_bytes,
            complete: b.complete,
        });
    }
    renderer.finish();
    let out = String::from_utf8(text.0.lock().unwrap().clone()).unwrap();
    for d in &layers {
        let short = &d.hex()[..12];
        assert!(
            out.contains(&format!("{short} complete")),
            "{short} in\n{out}"
        );
    }
}

#[derive(Clone, Default)]
struct Text(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Text {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A build service over the store of `e`.
/// Asks of a build for credentials, and what the client answers.
#[derive(Debug, Default)]
struct Asked(std::sync::Mutex<Vec<Vec<String>>>);

#[async_trait::async_trait]
impl velarx_core::services::build::CredentialSource for Asked {
    async fn credentials(
        &self,
        scopes: &[String],
    ) -> Result<std::collections::BTreeMap<String, velarx_registry::Credentials>, String> {
        self.0.lock().unwrap().push(scopes.to_vec());
        Ok(Default::default())
    }
}

/// A build asks for the credentials of the registries of the images it
/// pulls, one question for each, and for nothing else.
#[tokio::test]
async fn test_a_build_asks_credentials_for_the_references_it_pulls() {
    use crate::common::{build_chunked, env, sample, ZSTD};
    use velarx_core::services::build::{BuildContext, BuildOptions};
    let e = env().await;
    let base = build_chunked(&sample());
    e.publish(&[&base], &[ZSTD]);
    let tmp = tempfile::tempdir().unwrap();
    let svc = build_service(&e, tmp.path());
    let context = tmp.path().join("context");
    std::fs::create_dir(&context).unwrap();
    std::fs::write(
        context.join("Containerfile"),
        format!(
            "FROM scratch\nFROM {host}/test:latest\nLABEL a=b\n",
            host = e.host
        ),
    )
    .unwrap();
    let ctx = BuildContext::new(&context, None).unwrap();
    let asked = std::sync::Arc::new(Asked::default());
    let opts = BuildOptions {
        tls_verify: false,
        credentials: Some(asked.clone()),
        ..Default::default()
    };
    svc.build(&ctx, &opts, None, Default::default())
        .await
        .unwrap();
    let asked = asked.0.lock().unwrap();
    assert_eq!(asked.len(), 1, "scratch asks nothing: {asked:?}");
    assert_eq!(asked[0], [format!("{}/test", e.host)]);
}

fn build_service(
    e: &common::Env,
    dir: &std::path::Path,
) -> velarx_core::services::build::BuildService {
    build_service_with(e, dir, Default::default())
}

fn build_service_with(
    e: &common::Env,
    dir: &std::path::Path,
    settings: velarx_core::services::build::BuildSettings,
) -> velarx_core::services::build::BuildService {
    use std::sync::Arc;
    use velarx_core::services::build::BuildService;
    use velarx_core::services::{ContainerService, VolumeService};
    let image_service = Arc::new((*e.service).clone());
    let volumes = Arc::new(VolumeService::new(e.db.clone(), dir.join("volumes")).unwrap());
    let userns = Arc::new(velarx_runtime::userns::UserNamespaceManager::new(
        e.db.clone(),
        &Default::default(),
    ));
    let containers = Arc::new(
        ContainerService::new(velarx_core::services::ContainerParts {
            db: e.db.clone(),
            image_service: image_service.clone(),
            userns_manager: userns,
            root_dir: dir.join("root"),
            state_dir: dir.join("state"),
            cgroup_manager: None,
            network_providers: Default::default(),
            volume_service: volumes,
        })
        .unwrap(),
    );
    BuildService::new(
        image_service,
        containers,
        dir.join("build"),
        Some(common::worker().into()),
        settings,
    )
    .unwrap()
}

/// A Containerfile whose target stage needs entitlements is refused at
/// planning: no step starts, its base is not pulled (the registry does not
/// exist), the error names what is missing, and a stage the target does
/// not use is not counted.
#[tokio::test]
async fn test_a_build_needing_an_entitlement_fails_before_its_first_step() {
    use velarx_base::entitlement::Entitlement::{NetworkHost, SecurityInsecure};
    use velarx_core::services::build::entitlement::Allow;
    use velarx_core::services::build::{BuildContext, BuildOptions, BuildProgress, BuildSettings};
    let e = common::env().await;
    let tmp = tempfile::tempdir().unwrap();
    let context = tmp.path().join("context");
    std::fs::create_dir(&context).unwrap();
    std::fs::write(
        context.join("Containerfile"),
        "FROM nowhere.invalid/base AS unused\nRUN --network=host --security=insecure true\n\
         FROM nowhere.invalid/base\nRUN true\nRUN --network=host true\n\
         RUN --security=insecure true\n",
    )
    .unwrap();
    let ctx = BuildContext::new(&context, None).unwrap();
    let run = |enabled: Vec<_>, allow: Allow| {
        let svc = build_service_with(
            &e,
            tmp.path(),
            BuildSettings {
                entitlements: enabled,
                ..Default::default()
            },
        );
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let ctx = &ctx;
        async move {
            let opts = BuildOptions {
                allow,
                tls_verify: false,
                ..Default::default()
            };
            let err = svc
                .build(ctx, &opts, Some(tx), Default::default())
                .await
                .unwrap_err()
                .to_string();
            let mut started = false;
            while let Ok(p) = rx.try_recv() {
                started |= matches!(
                    p,
                    BuildProgress::Started { .. } | BuildProgress::StepStarted { .. }
                );
            }
            assert!(!started, "no step starts: {err}");
            err
        }
    };
    let err = run(vec![], Allow::Listed(vec![])).await;
    assert!(
        err.contains("network.host is not allowed (line 5: RUN --network=host)"),
        "{err}"
    );
    assert!(
        err.contains("security.insecure is not allowed (line 6: RUN --security=insecure)"),
        "{err}"
    );
    assert!(!err.contains("line 2"), "{err}");
    let err = run(
        vec![NetworkHost, SecurityInsecure],
        Allow::Listed(vec![NetworkHost]),
    )
    .await;
    assert!(!err.contains("network.host is not allowed"), "{err}");
    assert!(err.contains("security.insecure is not allowed"), "{err}");
    assert!(
        err.contains("start the build with --allow security.insecure"),
        "{err}"
    );
    let err = run(vec![], Allow::Listed(vec![NetworkHost])).await;
    assert!(
        err.starts_with("--allow network.host: network.host is not enabled"),
        "{err}"
    );
    let err = run(vec![NetworkHost], Allow::ByConfig).await;
    assert!(
        err.contains("security.insecure is not allowed") && !err.contains("network.host is"),
        "{err}"
    );
}

/// `--squash` keeps the layers of the base and adds one; `--squash-all`
/// makes the image one layer; the files and the configuration are the
/// same as the build without.
#[tokio::test]
async fn test_squash_and_squash_all() {
    use crate::common::{build_chunked, build_gzip, env, sample, Item, GZIP, ZSTD};
    use velarx_core::services::build::{BuildContext, BuildOptions};
    use velarx_types::OciManifest;

    let e = env().await;
    let l1 = build_chunked(&sample());
    let l2 = build_gzip(&[
        Item::File {
            name: "etc/.wh.small",
            data: vec![],
            chunk: 1,
        },
        Item::File {
            name: "usr/top",
            data: b"top\n".to_vec(),
            chunk: 4096,
        },
    ]);
    let l3 = build_gzip(&[Item::File {
        name: "usr/top",
        data: b"over\n".to_vec(),
        chunk: 4096,
    }]);
    e.publish(&[&l1, &l2, &l3], &[ZSTD, GZIP, GZIP]);

    let tmp = tempfile::tempdir().unwrap();
    let svc = build_service(&e, tmp.path());
    let context = tmp.path().join("context");
    std::fs::create_dir(&context).unwrap();
    std::fs::write(context.join("one"), "1\n").unwrap();
    std::fs::write(context.join("two"), "2\n").unwrap();
    std::fs::write(
        context.join("Containerfile"),
        format!(
            "FROM {}/test:latest\nENV A=b\nLABEL a=b\nCOPY one /one\nCOPY two /two\nCMD [\"/one\"]\n",
            e.host
        ),
    )
    .unwrap();
    let ctx = BuildContext::new(&context, None).unwrap();

    let mut images = Vec::new();
    for (squash, squash_all) in [(false, false), (true, false), (false, true), (true, true)] {
        let opts = BuildOptions {
            tls_verify: false,
            squash,
            squash_all,
            ..Default::default()
        };
        let id = svc
            .build(&ctx, &opts, None, Default::default())
            .await
            .unwrap();
        let image = e.service.get(&id).await.unwrap();
        let m: OciManifest = serde_json::from_str(&image.manifest).unwrap();
        let config: serde_json::Value = serde_json::from_str(&image.config).unwrap();
        let tocs: Vec<velarx_storage::Toc> =
            e.db.get_image_layers(&image.id)
                .await
                .unwrap()
                .iter()
                .map(|l| serde_json::from_str(l.toc.as_deref().unwrap()).unwrap())
                .collect();
        let tree = velarx_fuse::MergedTree::build(&tocs.iter().collect::<Vec<_>>()).unwrap();
        let mut files = Vec::new();
        let mut todo = vec![(0usize, String::new())];
        while let Some((i, path)) = todo.pop() {
            let n = tree.node(i).unwrap();
            for (name, &c) in &n.children {
                let e = &tree.node(c).unwrap().entry;
                files.push(format!("{path}/{name} {:?} {:?}", e.entry_type, e.verity()));
                todo.push((c, format!("{path}/{name}")));
            }
        }
        files.sort();
        images.push((m.layers.len(), config, files));
    }
    let layers: Vec<_> = images.iter().map(|i| i.0).collect();
    // 3 of the base and 2 COPY; the new layers in one; everything in one
    assert_eq!(layers, [5, 4, 1, 1]);
    for i in &images[1..] {
        assert_eq!(i.2, images[0].2, "the same files");
        assert_eq!(
            i.1["config"], images[0].1["config"],
            "the same configuration"
        );
    }
    assert!(images[0].2.iter().all(|f| !f.starts_with("/etc/small ")));
    assert_eq!(images[2].1["history"].as_array().unwrap().len(), 1);
    assert_eq!(
        images[2].1["rootfs"]["diff_ids"].as_array().unwrap().len(),
        1
    );
}

/// The password of the URL of an ADD is in no line of the output, in no error
/// and not in the history of the image (a push carries the history).
#[tokio::test]
async fn test_the_credentials_of_an_add_url_are_hidden() {
    use crate::common::env;
    use std::io::{Read, Write};
    use velarx_core::services::build::{BuildContext, BuildOptions};

    let e = env().await;
    let tmp = tempfile::tempdir().unwrap();
    let svc = build_service(&e, tmp.path());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut c, _) = listener.accept().unwrap();
        let mut buf = [0u8; 2048];
        let _ = c.read(&mut buf).unwrap();
        c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc")
            .unwrap();
    });
    let context = tmp.path().join("context");
    std::fs::create_dir(&context).unwrap();
    std::fs::write(
        context.join("Containerfile"),
        format!("FROM scratch\nADD http://user:ADDMARK-4444@127.0.0.1:{port}/f?access_token=TOKMARK-1 /f\n"),
    )
    .unwrap();
    let ctx = BuildContext::new(&context, None).unwrap();
    let opts = BuildOptions {
        tls_verify: false,
        ..Default::default()
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel(256);
    let seen = tokio::spawn(async move {
        let mut all = String::new();
        while let Some(p) = rx.recv().await {
            all.push_str(&format!("{p:?}\n"));
        }
        all
    });
    let id = svc
        .build(&ctx, &opts, Some(tx), Default::default())
        .await
        .unwrap();
    server.join().unwrap();
    let output = seen.await.unwrap();
    assert!(output.contains("Downloading"), "{output}");
    assert!(output.contains("user:xxxxx@"), "{output}");
    let image = e.service.get(&id).await.unwrap();
    let config: serde_json::Value = serde_json::from_str(&image.config).unwrap();
    let history = config["history"].to_string();
    for text in [&output, &history, &image.config] {
        assert!(
            !text.contains("ADDMARK") && !text.contains("TOKMARK"),
            "{text}"
        );
    }
    assert!(history.contains("user:xxxxx@"), "{history}");

    // a download that fails says where without the password
    std::fs::write(
        context.join("Containerfile"),
        "FROM scratch\nADD https://user:ADDMARK-4444@127.0.0.1:1/f /f\n",
    )
    .unwrap();
    let ctx = BuildContext::new(&context, None).unwrap();
    let err = svc
        .build(&ctx, &opts, None, Default::default())
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("127.0.0.1:1") && !err.contains("ADDMARK"),
        "{err}"
    );
}

/// What a cancelled build leaves: nothing in the staging area, no lease,
/// no container, no image, nothing in its work directory.
async fn assert_nothing_left(e: &common::Env, dir: &Path) {
    assert_eq!(e.staged_leftovers(), 0, "files of the staging area");
    assert!(e.db.list_leases().await.unwrap().is_empty(), "a lease");
    assert!(e.db.list_containers(true).await.unwrap().is_empty());
    assert!(e.db.list_images().await.unwrap().is_empty(), "an image");
    // (one directory for the process, then one for each build)
    let work: Vec<_> = std::fs::read_dir(dir.join("build"))
        .into_iter()
        .flatten()
        .flatten()
        .flat_map(|p| std::fs::read_dir(p.path()).into_iter().flatten().flatten())
        .map(|e| e.file_name())
        .collect();
    assert!(work.is_empty(), "the work directory of the build: {work:?}");
}

/// Run a build that is told to stop when `when` says so of its events:
/// its result and how it ended.
async fn cancelled_build(
    svc: &velarx_core::services::build::BuildService,
    ctx: &velarx_core::services::build::BuildContext,
    when: impl Fn(&velarx_core::services::build::BuildProgress) -> bool + Send + 'static,
) -> Result<String, velarx_core::services::build::BuildError> {
    let (stop, cancel) = velarx_core::services::Cancel::new();
    let (tx, mut rx) = tokio::sync::mpsc::channel(256);
    let watcher = tokio::spawn(async move {
        while let Some(p) = rx.recv().await {
            if when(&p) {
                let _ = stop.send(true);
            }
        }
    });
    let opts = velarx_core::services::build::BuildOptions {
        tls_verify: false,
        ..Default::default()
    };
    let built = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        svc.build(ctx, &opts, Some(tx), cancel),
    )
    .await
    .expect("a cancelled build ends at once");
    watcher.await.unwrap();
    built
}

/// A build told to stop while it pulls its base (a blob that the registry
/// does not send) ends at once and leaves nothing.
#[tokio::test]
async fn test_a_build_cancelled_during_the_pull_of_its_base_leaves_nothing() {
    use crate::common::{build_chunked, env, sample, ZSTD};
    use velarx_core::services::build::{BuildContext, BuildError, BuildProgress};
    let e = env().await;
    e.publish(&[&build_chunked(&sample())], &[ZSTD]);
    // an hour before the first byte of a blob
    e.reg
        .delay_ms
        .store(3_600_000, std::sync::atomic::Ordering::SeqCst);
    let tmp = tempfile::tempdir().unwrap();
    let svc = build_service(&e, tmp.path());
    let context = tmp.path().join("context");
    std::fs::create_dir(&context).unwrap();
    std::fs::write(
        context.join("Containerfile"),
        format!("FROM {}/test:latest\nLABEL a=b\n", e.host),
    )
    .unwrap();
    let ctx = BuildContext::new(&context, None).unwrap();
    let built = cancelled_build(
        &svc,
        &ctx,
        |p| matches!(p, BuildProgress::Report { output } if output.starts_with("Pulling ")),
    )
    .await;
    assert!(matches!(built, Err(BuildError::Cancelled)), "{built:?}");
    assert_nothing_left(&e, tmp.path()).await;
}

/// A build told to stop while a COPY runs (in the worker) ends at once and
/// leaves nothing.
#[tokio::test]
async fn test_a_build_cancelled_during_a_copy_leaves_nothing() {
    use crate::common::env;
    use velarx_core::services::build::{BuildContext, BuildError, BuildProgress};
    let e = env().await;
    let tmp = tempfile::tempdir().unwrap();
    let svc = build_service(&e, tmp.path());
    let context = tmp.path().join("context");
    std::fs::create_dir(&context).unwrap();
    let mut big = std::fs::File::create(context.join("big")).unwrap();
    std::io::copy(&mut std::io::repeat(7).take(64 << 20), &mut big).unwrap();
    std::fs::write(
        context.join("Containerfile"),
        "FROM scratch\nCOPY big /big\nCOPY big /big2\n",
    )
    .unwrap();
    let ctx = BuildContext::new(&context, None).unwrap();
    let built = cancelled_build(&svc, &ctx, |p| {
        matches!(p, BuildProgress::StepStarted { instruction, .. } if instruction.contains("COPY big /big"))
    })
    .await;
    assert!(matches!(built, Err(BuildError::Cancelled)), "{built:?}");
    assert_nothing_left(&e, tmp.path()).await;
}

/// A build that waits for its turn and is asked to stop (its client went
/// away) ends at once; the end of the engine stops every build, those that
/// wait and those that run, and they leave nothing.
#[tokio::test]
async fn test_a_queued_build_is_given_up_and_the_end_of_the_engine_stops_all() {
    use crate::common::{build_chunked, env, sample, ZSTD};
    use velarx_core::services::build::{
        BuildContext, BuildError, BuildOptions, BuildProgress, BuildSettings,
    };
    use velarx_core::services::Cancel;
    let e = env().await;
    let tmp = tempfile::tempdir().unwrap();
    let svc = std::sync::Arc::new(build_service_with(
        &e,
        tmp.path(),
        BuildSettings {
            max_concurrent: 1,
            ..Default::default()
        },
    ));
    let context = tmp.path().join("context");
    std::fs::create_dir(&context).unwrap();
    std::fs::write(context.join("f"), "x").unwrap();
    std::fs::write(context.join("Containerfile"), "FROM scratch\nCOPY f /f\n").unwrap();
    let ctx = BuildContext::new(&context, None).unwrap();
    let opts = BuildOptions {
        tls_verify: false,
        layers: false,
        ..Default::default()
    };

    // A holds the only turn (its base never comes), B waits for it
    e.publish(&[&build_chunked(&sample())], &[ZSTD]);
    e.reg
        .delay_ms
        .store(3_600_000, std::sync::atomic::Ordering::SeqCst);
    let pulling = tmp.path().join("pulling");
    std::fs::create_dir(&pulling).unwrap();
    std::fs::write(
        pulling.join("Containerfile"),
        format!("FROM {}/test:latest\nLABEL a=b\n", e.host),
    )
    .unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(256);
    let (started_tx, started) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut started_tx = Some(started_tx);
        while let Some(p) = rx.recv().await {
            if matches!(&p, BuildProgress::Report { output } if output.starts_with("Pulling ")) {
                if let Some(t) = started_tx.take() {
                    let _ = t.send(());
                }
            }
        }
    });
    let a = tokio::spawn({
        let (svc, opts) = (svc.clone(), opts.clone());
        let ctx = BuildContext::new(&pulling, None).unwrap();
        async move { svc.build(&ctx, &opts, Some(tx), Default::default()).await }
    });
    started.await.unwrap();
    let (stop, cancel) = Cancel::new();
    let b = tokio::spawn({
        let (svc, opts, ctx) = (svc.clone(), opts.clone(), ctx.clone());
        async move { svc.build(&ctx, &opts, None, cancel).await }
    });
    stop.send(true).unwrap();
    let b = tokio::time::timeout(std::time::Duration::from_secs(60), b)
        .await
        .expect("a build that waits is given up at once")
        .unwrap();
    assert!(matches!(b, Err(BuildError::Cancelled)), "{b:?}");

    let left = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        svc.stop_all(std::time::Duration::from_secs(30)),
    )
    .await
    .unwrap();
    assert_eq!(left, 0, "the builds that did not end");
    let a = a.await.unwrap();
    assert!(matches!(a, Err(BuildError::Cancelled)), "{a:?}");
    // (and one that comes after the end does not start)
    let late = svc.build(&ctx, &opts, None, Default::default()).await;
    assert!(matches!(late, Err(BuildError::Cancelled)), "{late:?}");
    assert_nothing_left(&e, tmp.path()).await;
}

/// A job that waits for a stream that never ends, in a worker or in the
/// process, is stopped at once.
#[tokio::test]
async fn test_a_cancelled_copy_stops_its_worker_and_its_thread() {
    use velarx_core::services::Cancel;
    let d = tempfile::tempdir().unwrap();
    let out = d.path().join("out");
    std::fs::create_dir(&out).unwrap();
    for runner in [worker(), Runner::default()] {
        let (reader, writer) = std::io::pipe().unwrap();
        // a regular file of the archive that never ends, as far as
        // the job reads: the feeder counts what it wrote
        let (fed, first) = std::sync::mpsc::channel();
        let feeder = std::thread::spawn(move || {
            use std::io::Write;
            let mut w = writer;
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Regular);
            h.set_size(1 << 35);
            h.set_mode(0o644);
            h.set_path("endless").unwrap();
            h.set_cksum();
            let mut written = 0u64;
            let mut put = |data: &[u8]| -> bool {
                let ok = w.write_all(data).is_ok();
                let before = written;
                written += data.len() as u64;
                if before < 1 << 20 && written >= 1 << 20 {
                    let _ = fed.send(());
                }
                ok
            };
            if !put(h.as_bytes()) {
                return written;
            }
            while put(&[0u8; 64 * 1024]) {}
            written
        });
        let (stop, cancel) = Cancel::new();
        let watcher = tokio::task::spawn_blocking(move || {
            let _ = first.recv();
            let _ = stop.send(true);
        });
        let err = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            runner.run(
                job(Source::Unpack, &[]),
                &out,
                JobSource::Stream(reader.into()),
                &cancel,
            ),
        )
        .await
        .expect("a cancelled job ends at once")
        .unwrap_err();
        assert_eq!(err.to_string(), "cancelled", "{err}");
        watcher.await.unwrap();
        let written = feeder.join().unwrap();
        assert!(written < 1 << 35);
    }
}

/// A layer that is told to stop is not finished: nothing is left of it.
#[tokio::test]
async fn test_a_cancelled_commit_leaves_nothing() {
    use crate::common::env;
    use velarx_core::services::{Cancel, CommitOptions};
    let e = env().await;
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().join("changes");
    std::fs::create_dir(&dir).unwrap();
    for i in 0..8 {
        let mut f = std::fs::File::create(dir.join(format!("f{i}"))).unwrap();
        std::io::copy(&mut std::io::repeat(i).take(8 << 20), &mut f).unwrap();
    }
    let (stop, cancel) = Cancel::new();
    let (tx, mut rx) = tokio::sync::mpsc::channel(256);
    // the layer reports once it starts: that is when it is told to stop
    let watcher = tokio::spawn(async move {
        if rx.recv().await.is_some() {
            let _ = stop.send(true);
        }
        while rx.recv().await.is_some() {}
    });
    let opts = CommitOptions {
        progress: Some(tx),
        cancel,
        ..Default::default()
    };
    let r = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        e.service.commit_dir(None, Some(&dir), &opts),
    )
    .await
    .expect("a cancelled commit ends at once");
    drop(opts);
    watcher.await.unwrap();
    let err = r.unwrap_err();
    assert!(err.to_string().contains("cancelled"), "{err}");
    assert_eq!(e.staged_leftovers(), 0);
    assert!(e.db.list_images().await.unwrap().is_empty());
}

/// A context that is a directory descriptor is built from in place: what
/// the build reads is the directory the descriptor is, whatever the path it
/// was opened by becomes (renamed, and another directory put there), with
/// the names a shell trips on (a leading dash, spaces, a newline, not
/// ASCII), links kept as links and never followed, and a file that changes
/// after the descriptor was taken is read as it is when a step reads it.
#[tokio::test]
async fn test_a_build_reads_the_directory_of_its_descriptor_in_place() {
    use crate::common::env;
    use velarx_core::services::build::{BuildContext, BuildOptions};
    let e = env().await;
    let tmp = tempfile::tempdir().unwrap();
    let svc = build_service(&e, tmp.path());
    let context = tmp.path().join("context");
    std::fs::create_dir_all(context.join("sub dir/-x")).unwrap();
    std::fs::write(context.join("sub dir/-x/new\nline"), "n").unwrap();
    std::fs::write(context.join("-file name"), "dash").unwrap();
    std::fs::write(context.join("caf\u{e9} x"), "bytes").unwrap();
    std::fs::write(context.join("later"), "before").unwrap();
    symlink("/etc/passwd", context.join("out")).unwrap();
    symlink("-file name", context.join("in")).unwrap();
    std::fs::write(
        context.join("Containerfile"),
        "FROM scratch\nCOPY [\"-file name\", \"/dash\"]\nCOPY . /all/\nCOPY later /later\n",
    )
    .unwrap();
    let fd = rustix::fs::open(
        &context,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    let ctx = BuildContext::from_fd(fd, None).unwrap();
    // the path now names another directory with another Containerfile; the
    // directory of the descriptor is elsewhere, and a file of it changes
    // before the step that copies it
    let moved = tmp.path().join("moved");
    std::fs::rename(&context, &moved).unwrap();
    std::fs::create_dir(&context).unwrap();
    std::fs::write(
        context.join("Containerfile"),
        "FROM scratch\nCOPY decoy /decoy\n",
    )
    .unwrap();
    std::fs::write(context.join("decoy"), "decoy").unwrap();
    std::fs::write(moved.join("later"), "after").unwrap();
    let opts = BuildOptions {
        tls_verify: false,
        ..Default::default()
    };
    let id = svc
        .build(&ctx, &opts, None, Default::default())
        .await
        .unwrap();
    let image = e.service.get(&id).await.unwrap();
    let tocs: Vec<velarx_storage::Toc> =
        e.db.get_image_layers(&image.id)
            .await
            .unwrap()
            .iter()
            .map(|l| serde_json::from_str(l.toc.as_deref().unwrap()).unwrap())
            .collect();
    let tree = velarx_fuse::MergedTree::build(&tocs.iter().collect::<Vec<_>>()).unwrap();
    let mut files = Vec::new();
    let mut todo = vec![(0usize, String::new())];
    while let Some((i, path)) = todo.pop() {
        for (name, &c) in &tree.node(i).unwrap().children {
            let n = tree.node(c).unwrap();
            files.push(format!("{path}/{name} {:?}", n.entry.entry_type));
            todo.push((c, format!("{path}/{name}")));
        }
    }
    files.sort();
    for wanted in [
        "/dash Reg",
        "/later Reg",
        "/all/Containerfile Reg",
        "/all/-file name Reg",
        "/all/caf\u{e9} x Reg",
        "/all/sub dir Dir",
        "/all/sub dir/-x/new\nline Reg",
        "/all/out Symlink",
        "/all/in Symlink",
    ] {
        assert!(files.iter().any(|f| f == wanted), "{wanted:?} in {files:?}");
    }
    assert!(!files.iter().any(|f| f.contains("decoy")), "{files:?}");
    // what the step copied is the file as it was when the step read it
    let later = tree.resolve("later").unwrap();
    assert_eq!(
        tree.node(later).unwrap().entry.size,
        "after".len() as u64,
        "{files:?}"
    );
}

/// The manifest of the built image has buildah's annotations (those of the
/// base, its name and digest, the time; `--annotation`,
/// `--unsetannotation`), the configuration `--os-version` and
/// `--os-feature`; no history entry is added, and a build that the cache
/// has entirely gives the same image.
#[tokio::test]
async fn test_the_annotations_and_the_os_of_the_built_image() {
    use crate::common::env;
    use std::collections::HashMap;
    use velarx_core::services::build::{BuildContext, BuildOptions};
    use velarx_wire::buildopts::BuildFlags;
    let e = env().await;
    let tmp = tempfile::tempdir().unwrap();
    let svc = build_service(&e, tmp.path());
    let context = tmp.path().join("context");
    std::fs::create_dir(&context).unwrap();
    std::fs::write(context.join("f"), "x").unwrap();
    std::fs::write(context.join("Containerfile"), "FROM scratch\nCOPY f /f\n").unwrap();
    let build = |flags: BuildFlags, tag: &str, file: &str| {
        let opts = BuildOptions {
            tls_verify: false,
            layers: true,
            tags: vec![tag.to_string()],
            flags,
            ..Default::default()
        };
        let ctx = BuildContext::new(&context, Some(std::path::Path::new(file))).unwrap();
        let svc = &svc;
        async move {
            svc.build(&ctx, &opts, None, Default::default())
                .await
                .unwrap()
        }
    };
    let of = |id: String| {
        let e = &e;
        async move {
            let image = e.service.get(&id).await.unwrap();
            let m: serde_json::Value = serde_json::from_str(&image.manifest).unwrap();
            let c: serde_json::Value = serde_json::from_str(&image.config).unwrap();
            let mut a: HashMap<String, String> =
                serde_json::from_value(m["annotations"].clone()).unwrap_or_default();
            // (the store's own)
            a.remove("composefs.merged.erofs.v1.fsverity-sha256-12");
            (a, c)
        }
    };
    let flags = BuildFlags {
        annotations: vec!["a=b".into(), "c=d".into()],
        unset_annotations: vec!["c".into()],
        os_version: Some("10.0".into()),
        os_features: vec!["win32k".into()],
        timestamp: Some(1_600_000_000),
        ..Default::default()
    };
    let id = build(flags.clone(), "localhost/annotated:1", "Containerfile").await;
    let (a, c) = of(id.clone()).await;
    let expected: HashMap<String, String> = [
        ("a", "b"),
        ("org.opencontainers.image.base.name", ""),
        ("org.opencontainers.image.base.digest", ""),
        ("org.opencontainers.image.created", "2020-09-13T12:26:40Z"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    assert_eq!(a, expected);
    assert_eq!(c["os.version"], "10.0");
    assert_eq!(c["os.features"], serde_json::json!(["win32k"]));
    assert_eq!(c["history"].as_array().unwrap().len(), 1, "{c}");
    assert_eq!(
        build(flags, "localhost/annotated:1", "Containerfile").await,
        id,
        "a build the cache has"
    );

    // a child keeps the annotations of its base and names it
    std::fs::write(
        context.join("Child"),
        "FROM localhost/annotated:1\nCOPY f /g\n",
    )
    .unwrap();
    let (a, _) = of(build(BuildFlags::default(), "localhost/child:1", "Child").await).await;
    assert_eq!(a["a"], "b");
    assert_eq!(
        a["org.opencontainers.image.base.name"],
        "localhost/annotated:1"
    );
    assert!(a["org.opencontainers.image.base.digest"].starts_with("sha256:"));
    assert_ne!(
        a["org.opencontainers.image.created"],
        "2020-09-13T12:26:40Z"
    );
    let (a, _) = of(build(
        BuildFlags {
            inherit_annotations: false,
            created_annotation: false,
            ..Default::default()
        },
        "localhost/child:2",
        "Child",
    )
    .await)
    .await;
    assert!(a.is_empty(), "{a:?}");

    // a stage FROM a stage has the base of that stage (buildah); the
    // features of the base stay, FEATURE- removes one; NAME alone is an
    // empty annotation; the time of the annotation is the configuration's
    std::fs::write(
        context.join("Stages"),
        "FROM localhost/annotated:1 AS one
COPY f /h
FROM one
COPY f /i
",
    )
    .unwrap();
    let (a, c) = of(build(
        BuildFlags {
            annotations: vec!["empty".into()],
            os_features: vec!["win32k-".into(), "other".into()],
            ..Default::default()
        },
        "localhost/stages:1",
        "Stages",
    )
    .await)
    .await;
    assert_eq!(
        a["org.opencontainers.image.base.name"],
        "localhost/annotated:1"
    );
    assert_eq!(a["a"], "b");
    assert_eq!(a["empty"], "");
    assert_eq!(c["os.features"], serde_json::json!(["other"]));
    assert_eq!(c["created"], a["org.opencontainers.image.created"]);
}

/// `tar` compressed by the system program `program` (none: not installed).
fn compressed_tar(program: &str, tar: &[u8]) -> Option<Vec<u8>> {
    use std::io::Write;
    let mut child = std::process::Command::new(program)
        .arg("-c")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    let mut stdin = child.stdin.take().unwrap();
    let data = tar.to_vec();
    let feed = std::thread::spawn(move || stdin.write_all(&data));
    let out = child.wait_with_output().ok()?;
    feed.join().unwrap().ok()?;
    out.status.success().then_some(out.stdout)
}

fn small_tar() -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Regular);
    h.set_size(5);
    h.set_mode(0o644);
    b.append_data(&mut h, "dir/hello", &b"hello"[..]).unwrap();
    b.into_inner().unwrap()
}

/// ADD extracts the xz and bzip2 archives, which the worker leaves to the
/// system programs, from the context and as the stream of a context.
#[tokio::test]
async fn test_add_extracts_xz_and_bzip2_archives() {
    for (program, ext) in [("xz", "xz"), ("bzip2", "bz2")] {
        let Some(archive) = compressed_tar(program, &small_tar()) else {
            eprintln!("{program} is not installed: skipped");
            continue;
        };
        let d = tempfile::tempdir().unwrap();
        let (ctx, out, out2) = (
            d.path().join("ctx"),
            d.path().join("out"),
            d.path().join("out2"),
        );
        for p in [&ctx, &out, &out2] {
            std::fs::create_dir(p).unwrap();
        }
        let name = format!("a.tar.{ext}");
        std::fs::write(ctx.join(&name), &archive).unwrap();
        let mut j = job(Source::Context, &[(&name, "/x", false)]);
        j.add = true;
        worker()
            .run(
                j,
                &out,
                JobSource::Dir(ctx.clone()),
                &velarx_core::services::Cancel::default(),
            )
            .await
            .unwrap_or_else(|e| panic!("{program}: {e}"));
        assert_eq!(
            std::fs::read_to_string(out.join("x/dir/hello")).unwrap(),
            "hello",
            "{program}"
        );
        // a context that arrives compressed
        let stream = std::fs::File::open(ctx.join(&name)).unwrap();
        worker()
            .run(
                job(Source::Unpack, &[]),
                &out2,
                JobSource::Stream(stream.into()),
                &velarx_core::services::Cancel::default(),
            )
            .await
            .unwrap_or_else(|e| panic!("{program}: {e}"));
        assert_eq!(
            std::fs::read_to_string(out2.join("dir/hello")).unwrap(),
            "hello",
            "{program}"
        );
    }
}

/// The limits of the worker apply to what the program makes, and a corrupt
/// archive is the program's failure, not a hang or a silent success.
#[tokio::test]
async fn test_add_of_xz_and_bzip2_bombs_and_corrupt_archives() {
    for (program, ext) in [("xz", "xz"), ("bzip2", "bz2")] {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_size(32 << 20);
        h.set_mode(0o644);
        b.append_data(&mut h, "zeros", std::io::repeat(0).take(32 << 20))
            .unwrap();
        let Some(bomb) = compressed_tar(program, &b.into_inner().unwrap()) else {
            eprintln!("{program} is not installed: skipped");
            continue;
        };
        let d = tempfile::tempdir().unwrap();
        let (ctx, out) = (d.path().join("ctx"), d.path().join("out"));
        std::fs::create_dir(&ctx).unwrap();
        std::fs::create_dir(&out).unwrap();
        let name = format!("bomb.tar.{ext}");
        std::fs::write(ctx.join(&name), &bomb).unwrap();
        let mut j = job(Source::Context, &[(&name, "/x", false)]);
        j.add = true;
        j.limits.max_bytes = 1 << 20;
        let err = worker()
            .run(
                j,
                &out,
                JobSource::Dir(ctx.clone()),
                &velarx_core::services::Cancel::default(),
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("bytes to write"),
            "{program}: {err}"
        );

        let mut bad = compressed_tar(program, &small_tar()).unwrap();
        let n = bad.len();
        bad[n / 2] ^= 0xff;
        bad[n / 2 + 1] ^= 0xff;
        let name = format!("bad.tar.{ext}");
        std::fs::write(ctx.join(&name), &bad).unwrap();
        let mut j = job(Source::Context, &[(&name, "/y", false)]);
        j.add = true;
        let err = worker()
            .run(
                j,
                &out,
                JobSource::Dir(ctx.clone()),
                &velarx_core::services::Cancel::default(),
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains(&format!("{program} -dc")),
            "{program}: {err}"
        );
    }
}
