// SPDX-License-Identifier: Apache-2.0
//! The confinement of velarx-p2p, tried in a child process (the
//! test binary again): what it may not do once confined, and that it can
//! still serve its socket and reach the network.

use std::io::Write;
use std::path::Path;

const CHILD: &str = "VELARX_P2P_SANDBOX_CHILD";
/// Set in the child that is confined as the overlay node.
const OVERLAY: &str = "VELARX_P2P_SANDBOX_OVERLAY";

/// In the child: confine, try, print `what=ok` lines.
fn child(dir: &Path) {
    let overlay = std::env::var_os(OVERLAY).is_some();
    let role = if overlay {
        velarx_p2p::Role::Overlay
    } else {
        velarx_p2p::Role::Content
    };
    let mut config = velarx_config::Config::default();
    config.server.socket = dir.join("api.sock");
    let conf_path = dir.join("config.toml");
    std::fs::write(&conf_path, "").unwrap();
    let key = dir.join("swarm.key");
    velarx_p2p::control::generate_swarm_key(&key).unwrap();
    std::fs::set_permissions(&key, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let settings = velarx_p2p::settings::Settings {
        private_key_path: Some(key.clone()),
        max_incoming_mib: 1,
        ..Default::default()
    };
    // (started as a shell or a user unit starts it: a soft limit of open
    // files below the hard one)
    let files = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    rustix::process::setrlimit(
        rustix::process::Resource::Nofile,
        rustix::process::Rlimit {
            current: Some(256),
            maximum: files.maximum,
        },
    )
    .unwrap();
    // (bound before, as the service binds its sockets: one in the services
    // directory, as the store service's is, and one elsewhere, as the
    // engine's is)
    let services = config.services_dir();
    velarx_base::ipc::ensure_private_dir(&services).unwrap();
    let store_sock = services.join("store.sock");
    let _store = std::os::unix::net::UnixListener::bind(&store_sock).unwrap();
    let engine_sock = dir.join("engine.sock");
    let _engine = std::os::unix::net::UnixListener::bind(&engine_sock).unwrap();
    // (a file it was given and keeps open)
    let kept = std::fs::File::create(dir.join("kept")).unwrap();
    // (a file it staged, open read-only as fs-verity wants it: one open for
    // writing would wait for its writer)
    std::fs::write(dir.join("staged"), "x").unwrap();
    let staged = std::fs::File::open(dir.join("staged")).unwrap();
    // (the store service is reached through a process forked before)
    let connector =
        velarx_sys::connector::Connector::start_beside_idle_threads(&store_sock).unwrap();
    velarx_p2p::sandbox::enter_role_thread(role, &config, &settings, &[&conf_path]).unwrap();
    let mut out = Vec::new();
    let mut probe = |what: &str, ok: bool| out.push(format!("{what}={ok}"));
    probe(
        "write outside",
        std::fs::write(dir.join("outside"), "x").is_err(),
    );
    probe("read /etc/passwd", std::fs::read("/etc/passwd").is_err());
    // enabling fs-verity reads the page size: it must not need the aux
    // vector through prctl or /proc (the file system may refuse fs-verity,
    // but the call returns an error and does not panic)
    {
        let manager = velarx_storage::FsVerityManager::new();
        let tried = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = manager.enable_file_keeping_mode(&staged, &dir.join("staged"));
        }));
        probe("fs-verity is enabled without a panic", tried.is_ok());
        // (rustix takes the aux vector from the C library, `use-libc-auxv`:
        // its own lazy read panics once confined)
        let read = std::panic::catch_unwind(|| {
            rustix::param::page_size().is_power_of_two()
                && rustix::param::clock_ticks_per_second() > 0
        });
        probe(
            "the aux vector is read without a panic",
            read.unwrap_or(false),
        );
    }
    // a file it was given and kept cannot be grown past `max_incoming_mib`
    // (the signal that would end the process is ignored)
    if !overlay {
        use std::os::unix::fs::FileExt;
        probe(
            "a kept file is bounded",
            kept.write_all_at(&vec![1u8; 512 * 1024], 0).is_ok()
                && kept
                    .write_all_at(&vec![1u8; 1024 * 1024], 512 * 1024)
                    .is_err(),
        );
    }
    probe("read the configuration", std::fs::read(&conf_path).is_ok());
    probe(
        "make no file in the services directory",
        std::fs::write(services.join("made"), "x").is_err(),
    );
    probe(
        "bind no socket by name",
        std::os::unix::net::UnixListener::bind(services.join("p2p.sock")).is_err(),
    );
    probe(
        "remove no socket of another service",
        std::fs::remove_file(&store_sock).is_err(),
    );
    if !overlay {
        probe(
            "connect to the store service's socket through its connector",
            connector.connect().is_ok(),
        );
    }
    // (the stager's sealed memory files: the content service's only)
    probe(
        "a sealed memory file",
        rustix::fs::memfd_create(
            "x",
            rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
        )
        .is_ok()
            != overlay,
    );
    for (what, sock) in [
        ("the store service's socket", &store_sock),
        ("the engine's socket", &engine_sock),
    ] {
        // (the overlay node makes no UNIX socket at all)
        probe(
            &format!("connect to no socket by name: {what}"),
            std::os::unix::net::UnixStream::connect(sock)
                .err()
                .and_then(|e| e.raw_os_error())
                == Some(if overlay { libc::EPERM } else { libc::EACCES }),
        );
    }
    probe(
        "an IPv4 socket",
        std::net::UdpSocket::bind("127.0.0.1:0").is_ok(),
    );
    probe(
        "a packet socket",
        rustix::net::socket(
            rustix::net::AddressFamily::PACKET,
            rustix::net::SocketType::RAW,
            None,
        )
        .is_err(),
    );
    probe("fork", velarx_sys::process::fork_status(|| 0).is_err());
    velarx_sys::process::try_exec(c"/bin/true");
    probe("execve", true);
    probe(
        "unshare",
        velarx_sys::namespace::unshare(rustix::thread::UnshareFlags::NEWNS).is_err(),
    );
    probe(
        "mount",
        rustix::mount::mount(
            "none",
            "/tmp",
            "tmpfs",
            rustix::mount::MountFlags::empty(),
            None,
        )
        .is_err(),
    );
    let status = std::fs::read_to_string("/proc/thread-self/status").unwrap_or_default();
    probe(
        "no capability",
        status.lines().any(|l| l == "CapEff:\t0000000000000000"),
    );
    probe(
        "no_new_privs",
        status.lines().any(|l| l == "NoNewPrivs:\t1"),
    );
    probe("a thread", std::thread::spawn(|| 2).join().ok() == Some(2));
    // (the dial filter asks the kernel for the addresses of the interfaces:
    // netlink is allowed to the confined service)
    probe(
        "the addresses of the interfaces are known",
        velarx_p2p::dial_filter::interface_addresses()
            .contains(&std::net::Ipv4Addr::LOCALHOST.into()),
    );
    let files = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    probe(
        "open files up to the hard limit",
        files.current == files.maximum,
    );
    // A node of the service: its key read, listening, mDNS on (netlink).
    let listening = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async move {
            let node = velarx_p2p::P2PNode::with_config(velarx_p2p::P2PConfig {
                role,
                dial: velarx_p2p::dial_filter::Rules::on_one_host(),
                listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".into()],
                enable_mdns: !overlay,
                private_key_path: Some(key),
                ..Default::default()
            })
            .await
            .map_err(|e| eprintln!("node: {e}"))
            .ok()?;
            let mut status = node.status_updates();
            let up = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                status.wait_for(|s| !s.listen_addresses.is_empty()),
            )
            .await;
            up.is_ok_and(|r| r.is_ok()).then_some(())
        });
    probe("a node listens", listening.is_some());
    // The DNS sockets that the overlay helper hands over, served by the
    // confined service: a container's name asked over UDP and over TCP.
    let dns = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let udp = std::net::UdpSocket::bind("127.0.0.1:0").ok()?;
            let tcp = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
            let (udp_addr, tcp_addr) = (udp.local_addr().ok()?, tcp.local_addr().ok()?);
            let gossip = std::sync::Arc::new(velarx_p2p::OverlayGossip::default());
            gossip
                .add_dns_record(velarx_p2p::DnsRecord {
                    name: "web".into(),
                    ipv4: "10.200.1.9".parse().unwrap(),
                    container_id: "c1".into(),
                })
                .await;
            let handler = std::sync::Arc::new(velarx_p2p::dns_server::DnsHandler::new(
                gossip,
                std::net::Ipv4Addr::new(10, 200, 1, 1),
                Vec::new(),
            ));
            let serving = tokio::spawn(velarx_p2p::dns_sockets::serve(
                udp.into(),
                tcp.into(),
                handler,
                std::net::Ipv4Addr::LOCALHOST,
            ));
            let mut q = vec![0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
            q.extend_from_slice(b"\x03web\x06velarx\x00\x00\x01\x00\x01");
            let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
            client.send_to(&q, udp_addr).await.ok()?;
            let mut buf = vec![0u8; 512];
            let n = client.recv(&mut buf).await.ok()?;
            let over_udp = buf[n - 4..n] == [10, 200, 1, 9];
            let mut stream = tokio::net::TcpStream::connect(tcp_addr).await.ok()?;
            stream
                .write_all(&(q.len() as u16).to_be_bytes())
                .await
                .ok()?;
            stream.write_all(&q).await.ok()?;
            let mut len = [0u8; 2];
            stream.read_exact(&mut len).await.ok()?;
            let mut a = vec![0u8; usize::from(u16::from_be_bytes(len))];
            stream.read_exact(&mut a).await.ok()?;
            serving.abort();
            Some(over_udp && a[a.len() - 4..] == [10, 200, 1, 9])
        });
    probe("the DNS sockets are served", dns == Some(true));
    let mut stdout = std::io::stdout();
    for l in out {
        let _ = writeln!(stdout, "PROBE {l}");
    }
}

#[test]
fn test_the_p2p_service_is_confined() {
    confined("test_the_p2p_service_is_confined", false);
}

/// The overlay node, confined for what it does: its sockets, its DNS and
/// its node, and none of the content service's calls.
#[test]
fn test_the_overlay_node_is_confined() {
    confined("test_the_overlay_node_is_confined", true);
}

/// Run the test `name` again as the child that confines itself, and check
/// what it tried.
fn confined(name: &str, overlay: bool) {
    if let Some(dir) = std::env::var_os(CHILD) {
        child(Path::new(&dir));
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            &format!("p2p_sandbox_tests::{name}"),
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, dir.path());
    if overlay {
        command.env(OVERLAY, "1");
    }
    let out = command.output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let probes: Vec<&str> = text
        .lines()
        .filter_map(|l| l.strip_prefix("PROBE "))
        .collect();
    assert!(probes.len() >= 15, "{text}");
    let failed: Vec<&&str> = probes.iter().filter(|p| !p.ends_with("=true")).collect();
    assert!(failed.is_empty(), "{failed:?}");
}

const RESOLVE_CHILD: &str = "VELARX_RESOLVE_UNIX_FD";

/// In the child: Landlock handling every right of ABI 9 (it restricts the
/// connect to a socket by path, `RESOLVE_UNIX`) with no rule at all; report
/// whether the connect by path and by descriptor work.
fn resolve_child(path: &Path, fd: i32) {
    use landlock::{Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, ABI};
    let abi = ABI::V9;
    let status = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))
        .unwrap()
        .create()
        .unwrap()
        .restrict_self()
        .unwrap();
    println!("PROBE enforced={:?}", status.ruleset);
    let by_path = std::os::unix::net::UnixStream::connect(path).is_ok();
    let by_fd = std::os::unix::net::UnixStream::connect(format!("/proc/self/fd/{fd}")).is_ok();
    println!("PROBE by path={by_path}");
    println!("PROBE by descriptor={by_fd}");
}

/// What a newer Landlock does to the connect to a socket: recorded so that a
/// change of the ruleset's ABI cannot surprise the fetchers.
#[test]
fn test_connecting_by_descriptor_under_landlock_abi_9() {
    if let Some(fd) = std::env::var_os(RESOLVE_CHILD) {
        let path = std::env::var_os(CHILD).unwrap();
        resolve_child(Path::new(&path), fd.to_str().unwrap().parse().unwrap());
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("s.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let fd = rustix::fs::open(
        &socket,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::empty()).unwrap();
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "p2p_sandbox_tests::test_connecting_by_descriptor_under_landlock_abi_9",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, &socket)
        .env(
            RESOLVE_CHILD,
            std::os::fd::AsRawFd::as_raw_fd(&fd).to_string(),
        )
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}");
    let probe = |what: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("PROBE {what}=")))
            .unwrap_or_else(|| panic!("no {what} in {text}"))
            .to_string()
    };
    // the descriptor is no way around the rules about sockets, and no
    // more restricted than the path: what resolves is the socket itself
    assert_eq!(probe("by path"), probe("by descriptor"), "{text}");
}

const STAGER_CHILD: &str = "VELARX_P2P_STAGER_CHILD";

/// In the child: confine as the P2P service is, with the store under `dir`,
/// then write a file of a layer by the object contract beneath the staging
/// of the layers (it must work), and try to write next to it and outside
/// (it must not).
fn stager_child(dir: &Path) {
    let mut config = velarx_config::Config::default();
    config.server.socket = dir.join("api.sock");
    config.storage.root = dir.join("store");
    let conf_path = dir.join("config.toml");
    std::fs::write(&conf_path, "").unwrap();
    velarx_p2p::sandbox::enter_thread(
        &config,
        &velarx_p2p::settings::Settings::default(),
        &[&conf_path],
    )
    .unwrap();
    let layers = config.storage.staging_dir().join("layers");
    let layer = std::fs::File::open(layers.join("one")).unwrap();
    let data = b"the bytes of a file";
    let content = velarx_types::digest::Digest::of(velarx_types::digest::Algorithm::Sha256, data);
    let staged = (|| {
        let file = velarx_content::stager::Unnamed::begin(
            std::os::fd::AsFd::as_fd(&layer),
            data.len() as u64,
        )?;
        file.write_chunk(0, data, None)?;
        file.finish(
            std::os::fd::AsFd::as_fd(&layer),
            &velarx_content::stager::Name::Content(content),
            false,
        )
    })();
    println!(
        "PROBE a file is staged beneath the staging={}",
        staged.is_ok()
    );
    if let Err(e) = staged {
        eprintln!("{e}");
    }
    println!(
        "PROBE nothing is made next to the staging={}",
        std::fs::write(config.storage.staging_dir().join("next"), "x").is_err()
    );
    println!(
        "PROBE nothing is made in the store={}",
        std::fs::write(config.storage.root.join("x"), "x").is_err()
    );
    println!(
        "PROBE nothing is removed beneath the staging={}",
        std::fs::remove_dir(layers.join("two")).is_err()
    );
}

/// The P2P service, confined, writes the files of a layer beneath the
/// staging of the layers of the store by the object contract, and nothing
/// next to it, in the store or removed: tried from inside.
#[test]
fn test_a_confined_p2p_service_writes_only_beneath_the_staging() {
    if std::env::var_os(STAGER_CHILD).is_some() {
        let dir = std::env::var_os(CHILD).unwrap();
        stager_child(Path::new(&dir));
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let layers = dir.path().join("store").join("staging").join("layers");
    std::fs::create_dir_all(layers.join("one")).unwrap();
    std::fs::create_dir_all(layers.join("two")).unwrap();
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "p2p_sandbox_tests::test_a_confined_p2p_service_writes_only_beneath_the_staging",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, dir.path())
        .env(STAGER_CHILD, "1")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{text}{err}");
    for probe in [
        "a file is staged beneath the staging",
        "nothing is made next to the staging",
        "nothing is made in the store",
        "nothing is removed beneath the staging",
    ] {
        assert!(
            text.contains(&format!("PROBE {probe}=true")),
            "{probe}: {text}{err}"
        );
    }
    let named = std::fs::read_dir(layers.join("one").join("files"))
        .unwrap()
        .count();
    assert_eq!(named, 1, "the file has its name");
}
