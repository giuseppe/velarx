// SPDX-License-Identifier: Apache-2.0
//! The bridge networks end to end, without containers: two pinned network
//! namespaces on a bridge reach each other by address and by name, a
//! published port is reachable from the host side, and the teardown leaves
//! nothing behind.
//!
//! Root only, and only in a network namespace of its own (never the one of
//! the host):
//!
//! ```text
//! unshare -n target/debug/deps/integration-HASH bridge_tests:: --test-threads=1
//! ```

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use velarx_base::testing::find_nft;
use velarx_netkernel::bridge::{
    self, Attachment, BridgeContainer, BridgeOptions, NetDef, NetnsFate,
};
use velarx_netkernel::firewall::Firewall;
use velarx_wire::addr::{PortSpec, Subnet, Subnet6};

/// The network namespace of the tests, which they change as a whole (its
/// links, its tables): one test at a time.
static NAMESPACE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A new network namespace with its loopback up, pinned on `path` (a bind
/// mount) for the commands of the test that name it by a file.
fn pin_netns(path: &Path) -> std::io::Result<()> {
    let ns = velarx_netkernel::netns::Netns::create()?;
    std::fs::File::create(path)?;
    bridge::bind_netns(&ns.path(), path)
}

/// Root, in a network namespace that is not the one of PID 1, with nft: the
/// namespace for the test, held until its end.
fn usable() -> Option<std::sync::MutexGuard<'static, ()>> {
    if !rustix::process::geteuid().is_root() {
        eprintln!("skipped: not root");
        return None;
    }
    let ino = |p: &str| std::fs::metadata(p).map(|m| m.ino()).ok();
    if ino("/proc/self/ns/net").is_none() || ino("/proc/self/ns/net") == ino("/proc/1/ns/net") {
        eprintln!("skipped: run in a network namespace of its own (unshare -n)");
        return None;
    }
    // A new namespace has its loopback down, the host has it up.
    let _ = std::process::Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status();
    find_nft()?;
    Some(NAMESPACE.lock().unwrap_or_else(|e| e.into_inner()))
}

/// Run a script with the nft binary, which the test uses as another view of
/// the ruleset than ours.
fn nft_script(script: &str) {
    use std::io::Write;
    let mut child = std::process::Command::new(find_nft().unwrap())
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());
}

fn net(dns: bool) -> NetDef {
    NetDef {
        id: "testnet-id".into(),
        name: "testnet".into(),
        bridge: "shtb0".into(),
        subnet: Subnet::parse("10.213.7.0/24").unwrap(),
        gateway: "10.213.7.1".parse().unwrap(),
        internal: false,
        dns,
        mtu: 1400,
        dns_servers: vec![],
        subnet6: None,
        gateway6: None,
        macvlan: None,
        routes: vec![],
    }
}

fn container(id: &str, name: &str, ip: &str, ports: &[&str]) -> BridgeContainer {
    BridgeContainer {
        id: id.into(),
        name: name.into(),
        attachments: vec![Attachment {
            net: net(true),
            ifname: "eth0".into(),
            ip: ip.parse().unwrap(),
            mac: Some([
                0x02,
                0x42,
                10,
                213,
                7,
                ip.rsplit('.').next().unwrap().parse().unwrap(),
            ]),
            aliases: vec![format!("{name}-alias")],
            ip6: None,
        }],
        ports: ports.iter().map(|p| PortSpec::parse(p).unwrap()).collect(),
    }
}

/// Run F in the namespace pinned on PATH.
fn inside<T: Send + 'static>(
    path: &Path,
    f: impl FnOnce() -> std::io::Result<T> + Send + 'static,
) -> T {
    let ns = std::fs::File::open(path).unwrap();
    bridge::in_netns(ns.as_fd(), f).unwrap()
}

/// A server in the namespace on PATH that answers MSG on PORT, forever.
fn serve(path: &Path, port: u16, msg: &'static str) {
    let ns = std::fs::File::open(path)
        .unwrap()
        .as_fd()
        .try_clone_to_owned()
        .unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        rustix::thread::move_into_link_name_space(
            ns.as_fd(),
            Some(rustix::thread::LinkNameSpaceType::Network),
        )
        .unwrap();
        let l = TcpListener::bind(("0.0.0.0", port)).unwrap();
        tx.send(()).unwrap();
        for s in l.incoming().flatten() {
            let mut s = s;
            let _ = s.write_all(msg.as_bytes());
        }
    });
    rx.recv().unwrap();
}

fn fetch(addr: SocketAddr) -> std::io::Result<String> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(3))?;
    s.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut out = String::new();
    s.read_to_string(&mut out)?;
    Ok(out)
}

/// An A query for NAME to SERVER: the addresses of the answer.
fn resolve(server: SocketAddr, name: &str) -> std::io::Result<Vec<Ipv4Addr>> {
    let mut q = vec![0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in name.split('.') {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    let s = UdpSocket::bind("0.0.0.0:0")?;
    s.set_read_timeout(Some(Duration::from_secs(3)))?;
    s.send_to(&q, server)?;
    let mut buf = [0u8; 512];
    let n = s.recv(&mut buf)?;
    let r = &buf[..n];
    let count = u16::from_be_bytes([r[6], r[7]]) as usize;
    // The answers are at the end: 16 bytes each with an A record.
    Ok((0..count)
        .map(|i| {
            let end = n - (count - 1 - i) * 16;
            Ipv4Addr::new(r[end - 4], r[end - 3], r[end - 2], r[end - 1])
        })
        .collect())
}

fn dns_exe() -> PathBuf {
    PathBuf::from(crate::common::worker())
}

#[test]
fn bridge_end_to_end() {
    let Some(_namespace) = usable() else {
        return;
    };
    let work = tempfile::Builder::new()
        .prefix("shnet-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let opts = BridgeOptions {
        state_dir: work.path().join("networks"),
        firewall: Firewall {
            table: "shtest".into(),
        },
        dns_exe: dns_exe(),
        netns: None,
    };
    let (pa, pb) = (work.path().join("a.netns"), work.path().join("b.netns"));
    pin_netns(&pa).unwrap();
    pin_netns(&pb).unwrap();
    let a = container("aaaa", "alpha", "10.213.7.2", &[]);
    let b = container(
        "bbbb",
        "beta",
        "10.213.7.3",
        &["18080:80", "127.0.0.1:18081:81"],
    );
    bridge::setup(&opts, &pa, &a).unwrap();
    bridge::setup(&opts, &pb, &b).unwrap();

    // The container side: address, MTU, MAC, default route.
    let link = std::process::Command::new("nsenter")
        .arg(format!("--net={}", pb.display()))
        .args(["ip", "-o", "addr", "show", "eth0"])
        .output()
        .unwrap();
    let link = String::from_utf8_lossy(&link.stdout);
    assert!(link.contains("inet 10.213.7.3/24"), "{link}");
    let link = std::process::Command::new("nsenter")
        .arg(format!("--net={}", pb.display()))
        .args(["ip", "-o", "link", "show", "eth0"])
        .output()
        .unwrap();
    let link = String::from_utf8_lossy(&link.stdout);
    assert!(
        link.contains("mtu 1400") && link.contains("link/ether 02:42:0a:d5:07:03"),
        "{link}"
    );
    let route = inside(&pb, || {
        std::fs::read_to_string("/proc/thread-self/net/route")
    });
    assert!(
        route
            .lines()
            .any(|l| l.split_whitespace().nth(1) == Some("00000000")),
        "{route}"
    );

    serve(&pb, 80, "from-b");
    serve(&pb, 81, "from-b81");
    let got = inside(&pa, || fetch("10.213.7.3:80".parse().unwrap()));
    assert_eq!(got, "from-b");
    let names = inside(&pa, || {
        let mut out = Vec::new();
        for n in ["beta", "beta-alias", "BETA.dns.podman", "alpha"] {
            out.push(resolve("10.213.7.1:53".parse().unwrap(), n)?);
        }
        Ok(out)
    });
    assert_eq!(names[0], vec![Ipv4Addr::new(10, 213, 7, 3)]);
    assert_eq!(names[1], vec![Ipv4Addr::new(10, 213, 7, 3)]);
    assert_eq!(names[2], vec![Ipv4Addr::new(10, 213, 7, 3)]);
    assert_eq!(names[3], vec![Ipv4Addr::new(10, 213, 7, 2)]);

    // Published ports from the host side: the bridge address, 127.0.0.1
    // (route_localnet), the address bound to 127.0.0.1 only.
    assert_eq!(
        fetch("10.213.7.1:18080".parse().unwrap()).unwrap(),
        "from-b"
    );
    assert_eq!(fetch("127.0.0.1:18080".parse().unwrap()).unwrap(), "from-b");
    assert_eq!(
        fetch("127.0.0.1:18081".parse().unwrap()).unwrap(),
        "from-b81"
    );
    // Hairpin: a container of the network through the published port.
    let got = inside(&pa, || fetch("10.213.7.1:18080".parse().unwrap()));
    assert_eq!(got, "from-b");

    // The same port published twice fails and leaves the first in place.
    let pc = work.path().join("c.netns");
    pin_netns(&pc).unwrap();
    let c = container("cccc", "gamma", "10.213.7.4", &["18080:80"]);
    assert!(bridge::setup(&opts, &pc, &c).is_err());
    assert_eq!(fetch("127.0.0.1:18080".parse().unwrap()).unwrap(), "from-b");
    bridge::unpin_netns(&pc);

    // Teardown: the first container leaves the bridge in place.
    bridge::teardown(&opts, Some(&pa), &a, NetnsFate::Stays).unwrap();
    assert!(bridge_exists("shtb0"));
    assert!(
        inside(&pa, || std::fs::read_to_string("/proc/thread-self/net/dev"))
            .lines()
            .all(|l| !l.contains("eth0"))
    );
    bridge::teardown(&opts, Some(&pb), &b, NetnsFate::Stays).unwrap();
    bridge::unpin_netns(&pa);
    bridge::unpin_netns(&pb);
    // The bridge and the table stay with no container, until the network goes.
    assert!(bridge_exists("shtb0"));
    bridge::network_remove(&opts, &a.attachments[0].net).unwrap();

    // Nothing left: no bridge, no veth, no rule, no record, no DNS server.
    assert!(!bridge_exists("shtb0"));
    let dev = std::fs::read_to_string("/proc/self/net/dev").unwrap();
    assert!(!dev.contains("veth"), "{dev}");
    let table = std::process::Command::new(find_nft().unwrap())
        .args(["list", "table", "ip", "shtest"])
        .output()
        .unwrap();
    // The table went with the last bridge.
    assert!(
        !table.status.success(),
        "{}",
        String::from_utf8_lossy(&table.stdout)
    );
    let dns = std::fs::read_dir(opts.state_dir.join("dns")).unwrap();
    let left: Vec<_> = dns
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != "server.lock" && n != "server.log")
        .collect();
    assert!(
        left.iter().all(|n| n == "control.sock") || left.is_empty(),
        "{left:?}"
    );
    let sock = opts.state_dir.join("dns/control.sock");
    assert!(
        velarx_base::testing::wait_gone(&sock, Duration::from_secs(5)),
        "the DNS server did not exit"
    );
    let _ = std::process::Command::new(find_nft().unwrap())
        .args(["delete", "table", "ip", "shtest"])
        .status();
}

fn bridge_exists(name: &str) -> bool {
    std::fs::read_to_string("/proc/self/net/dev")
        .map(|d| {
            d.lines()
                .any(|l| l.trim_start().starts_with(&format!("{name}:")))
        })
        .unwrap_or(false)
}

#[test]
fn network_remove_and_stale_rules() {
    let Some(_namespace) = usable() else {
        return;
    };
    let work = tempfile::Builder::new()
        .prefix("shnet-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let opts = BridgeOptions {
        state_dir: work.path().join("networks"),
        firewall: Firewall {
            table: "shtest2".into(),
        },
        dns_exe: dns_exe(),
        netns: None,
    };
    // Rules a killed process left for a bridge that is gone.
    let stale =
        "table ip shtest2 {\n map net_post { type ipv4_addr : verdict; flags interval; }\n}\n\
                 add chain ip shtest2 shstale0-post\n\
                 add element ip shtest2 net_post { 10.213.9.0/24 : jump shstale0-post }\n";
    nft_script(stale);
    let mut n = net(false);
    n.bridge = "shtb1".into();
    n.subnet = Subnet::parse("10.213.9.0/24").unwrap();
    n.gateway = "10.213.9.1".parse().unwrap();
    let mut c = container("dddd", "delta", "10.213.9.2", &[]);
    c.attachments[0].net = n.clone();
    let p = work.path().join("d.netns");
    pin_netns(&p).unwrap();
    bridge::setup(&opts, &p, &c).unwrap();
    let list = |t: &str| {
        let o = std::process::Command::new(find_nft().unwrap())
            .args(["list", "table", "ip", t])
            .output()
            .unwrap();
        String::from_utf8_lossy(&o.stdout).into_owned()
    };
    assert!(!list("shtest2").contains("shstale0"));
    // The network goes while the namespace is pinned: its bridge stays.
    bridge::network_remove(&opts, &n).unwrap();
    assert!(bridge_exists("shtb1"));
    bridge::unpin_netns(&p);
    // The veth goes with the namespace (the kernel ends it in a work queue):
    // the removal waits for the bridge to have no port (netlink).
    bridge::network_remove(&opts, &n).unwrap();
    assert!(!bridge_exists("shtb1"));
    assert!(!list("shtest2").contains("10.213.9"));
    let _ = std::process::Command::new(find_nft().unwrap())
        .args(["delete", "table", "ip", "shtest2"])
        .status();
}

/// Run a shell command (root, in the namespace of the test).
fn sh(cmd: &str) -> String {
    let o = std::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .unwrap();
    String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr)
}

/// The response code of an A query for NAME to SERVER.
fn rcode(server: SocketAddr, name: &str) -> std::io::Result<u8> {
    let mut q = vec![0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in name.split('.') {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    let s = UdpSocket::bind("0.0.0.0:0")?;
    s.set_read_timeout(Some(Duration::from_secs(2)))?;
    s.send_to(&q, server)?;
    let mut buf = [0u8; 512];
    let n = s.recv(&mut buf)?;
    Ok(if n >= 4 { buf[3] & 0x0f } else { 0xff })
}

fn opts(work: &Path, table: &str) -> BridgeOptions {
    BridgeOptions {
        state_dir: work.join("networks"),
        firewall: Firewall {
            table: table.into(),
        },
        dns_exe: dns_exe(),
        netns: None,
    }
}

/// A network of its own for a test.
fn own_net(bridge: &str, third: u8, internal: bool) -> NetDef {
    NetDef {
        id: format!("{bridge}-id"),
        name: bridge.into(),
        bridge: bridge.into(),
        subnet: Subnet::parse(&format!("10.213.{third}.0/24")).unwrap(),
        gateway: format!("10.213.{third}.1").parse().unwrap(),
        internal,
        dns: true,
        mtu: 0,
        dns_servers: vec![],
        subnet6: None,
        gateway6: None,
        macvlan: None,
        routes: vec![],
    }
}

fn on(n: &NetDef, id: &str, last: u8, ports: &[&str]) -> BridgeContainer {
    let ip: Ipv4Addr = format!(
        "{}.{last}",
        n.gateway.to_string().rsplit_once('.').unwrap().0
    )
    .parse()
    .unwrap();
    BridgeContainer {
        id: id.into(),
        name: id.into(),
        attachments: vec![Attachment {
            net: n.clone(),
            ifname: "eth0".into(),
            ip,
            mac: None,
            aliases: vec![],
            ip6: n
                .subnet6
                .map(|s| std::net::Ipv6Addr::from(s.network() + u128::from(last))),
        }],
        ports: ports.iter().map(|p| PortSpec::parse(p).unwrap()).collect(),
    }
}

/// An interface of the host named like a network, or with an address in
/// its subnet, is never taken, changed or deleted.
#[test]
fn host_interfaces_are_never_touched() {
    let Some(_namespace) = usable() else {
        return;
    };
    let work = tempfile::Builder::new()
        .prefix("shnet-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let o = opts(work.path(), "shown");
    let p = work.path().join("a.netns");
    pin_netns(&p).unwrap();
    for kind in ["dummy", "bridge"] {
        sh(&format!("ip link add shhost0 type {kind}"));
        let mut n = own_net("shhost0", 20, false);
        n.bridge = "shhost0".into();
        let c = on(&n, "own1", 2, &[]);
        let e = bridge::setup(&o, &p, &c).unwrap_err().to_string();
        assert!(e.contains("is not the bridge"), "{kind}: {e}");
        bridge::teardown(&o, Some(&p), &c, NetnsFate::Stays).unwrap();
        bridge::network_remove(&o, &n).unwrap();
        let link = sh("ip -o link show shhost0; ip -o addr show shhost0");
        assert!(
            link.contains("shhost0:") && !link.contains("10.213.20.1"),
            "{kind}: {link}"
        );
        sh("ip link del shhost0");
    }
    sh("ip link add shhost1 type dummy; ip addr add 10.213.21.7/24 dev shhost1");
    let n = own_net("shtb5", 21, false);
    let e = bridge::setup(&o, &p, &on(&n, "own2", 2, &[]))
        .unwrap_err()
        .to_string();
    assert!(e.contains("overlaps"), "{e}");
    assert!(!bridge_exists("shtb5"));
    sh("ip link set shhost1 up; ip route add 10.213.22.0/25 dev shhost1");
    let n = own_net("shtb6", 22, false);
    assert!(bridge::setup(&o, &p, &on(&n, "own3", 2, &[])).is_err());
    sh("ip link del shhost1");
    bridge::unpin_netns(&p);
    let _ = sh("nft delete table ip shown");
}

/// What containers and the LAN may reach: no host 127.0.0.1 service from a
/// container, no unpublished port and no DNS from the LAN, no forwarding of
/// names from an internal network; the DNS worker runs as nobody without
/// capabilities.
#[test]
fn security_boundaries() {
    let Some(_namespace) = usable() else {
        return;
    };
    let work = tempfile::Builder::new()
        .prefix("shnet-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let o = opts(work.path(), "shsec");
    let (pa, pi) = (work.path().join("a.netns"), work.path().join("i.netns"));
    pin_netns(&pa).unwrap();
    pin_netns(&pi).unwrap();
    let n = own_net("shtb2", 30, false);
    let ni = own_net("shtb3", 31, true);
    let a = on(&n, "seca", 2, &["18090:80"]);
    let i = on(&ni, "seci", 2, &[]);
    bridge::setup(&o, &pa, &a).unwrap();
    bridge::setup(&o, &pi, &i).unwrap();
    serve(&pa, 80, "from-a");
    serve(&pa, 81, "unpublished");

    // A service of the host on 127.0.0.1, reached from the container
    // through the bridge (route_localnet is on for the published ports).
    let local = TcpListener::bind("127.0.0.1:18091").unwrap();
    local.set_nonblocking(true).unwrap();
    let ns = format!("nsenter --net={}", pa.display());
    sh(&format!(
        "{ns} sh -c 'ip route del local 127.0.0.0/8 dev lo table local; \
         echo 1 > /proc/sys/net/ipv4/conf/eth0/route_localnet; \
         ip route add 127.0.0.1/32 via 10.213.30.1 dev eth0'"
    ));
    let got = inside(
        &pa,
        || Ok(fetch("127.0.0.1:18091".parse().unwrap()).is_ok()),
    );
    assert!(!got, "a container reached 127.0.0.1 of the host");
    assert!(
        local.accept().is_err(),
        "the host service saw the container"
    );
    // The published port from 127.0.0.1 still works.
    assert_eq!(fetch("127.0.0.1:18090".parse().unwrap()).unwrap(), "from-a");

    // A host of the LAN that routes the subnet through us.
    let pl = work.path().join("lan.netns");
    pin_netns(&pl).unwrap();
    let lan = format!("nsenter --net={}", pl.display());
    sh(&format!(
        "{lan} sleep 30 & P=$!; ip link add shlanh type veth peer name shlanp; \
         ip link set shlanp netns $P; kill $P; \
         ip addr add 192.168.213.1/24 dev shlanh; ip link set shlanh up; \
         {lan} sh -c 'ip addr add 192.168.213.2/24 dev shlanp; ip link set shlanp up; \
         ip route add 10.213.30.0/24 via 192.168.213.1; ip route add 10.213.31.0/24 via 192.168.213.1'"
    ));
    let to_unpublished = inside(&pl, || Ok(fetch("10.213.30.2:81".parse().unwrap()).is_ok()));
    assert!(
        !to_unpublished,
        "the LAN reached an unpublished port: {}",
        sh("nft list ruleset; ip route; ip -o addr")
    );
    let to_published = inside(&pl, || fetch("192.168.213.1:18090".parse().unwrap()));
    assert_eq!(to_published, "from-a");
    let dns_from_lan = inside(&pl, || {
        Ok(rcode("10.213.30.1:53".parse().unwrap(), "seca").is_ok())
    });
    assert!(!dns_from_lan, "the DNS server answered the LAN");
    let own = inside(&pa, || resolve("10.213.30.1:53".parse().unwrap(), "seca"));
    assert_eq!(own, vec![Ipv4Addr::new(10, 213, 30, 2)]);

    // An internal network: its names, nothing else.
    let other = inside(&pi, || {
        rcode("10.213.31.1:53".parse().unwrap(), "example.com")
    });
    assert_eq!(other, 2, "an internal network forwarded a name");
    let own = inside(&pi, || resolve("10.213.31.1:53".parse().unwrap(), "seci"));
    assert_eq!(own, vec![Ipv4Addr::new(10, 213, 31, 2)]);

    // The DNS keeper keeps only CAP_NET_BIND_SERVICE, CAP_SETGID and
    // CAP_SETUID (for its workers), the worker is nobody
    // without capabilities.
    let state = work.path().join("networks");
    let mut seen = Vec::new();
    for p in std::fs::read_dir("/proc").unwrap().flatten() {
        let cmd = std::fs::read(p.path().join("cmdline")).unwrap_or_default();
        let cmd = String::from_utf8_lossy(&cmd);
        if !cmd.contains("dns-server") || !cmd.contains(&*state.to_string_lossy()) {
            continue;
        }
        let status = std::fs::read_to_string(p.path().join("status")).unwrap_or_default();
        let field = |k: &str| {
            status
                .lines()
                .find(|l| l.starts_with(k))
                .map(|l| l.split_whitespace().nth(1).unwrap_or("").to_string())
                .unwrap_or_default()
        };
        seen.push((field("Uid:"), field("CapEff:")));
    }
    seen.sort();
    assert_eq!(
        seen,
        vec![
            ("0".to_string(), "00000000000004c0".to_string()),
            ("65534".to_string(), "0000000000000000".to_string())
        ]
    );

    bridge::teardown(&o, Some(&pa), &a, NetnsFate::Stays).unwrap();
    bridge::teardown(&o, Some(&pi), &i, NetnsFate::Stays).unwrap();
    sh("ip link del shlanh");
    for p in [&pa, &pi, &pl] {
        bridge::unpin_netns(p);
    }
    bridge::network_remove(&o, &a.attachments[0].net).unwrap();
    bridge::network_remove(&o, &i.attachments[0].net).unwrap();
    assert!(!bridge_exists("shtb2") && !bridge_exists("shtb3"));
    let _ = sh("nft delete table ip shsec");
}

/// `network create` refuses the name of a link of the host, a subnet of
/// the host and the options only the API layer writes.
#[tokio::test]
// (the lock is the namespace's, held across the test: the other tests that
// wait for it run on threads of their own)
#[allow(clippy::await_holding_lock)]
async fn network_create_checks_the_host() {
    let Some(_namespace) = usable() else {
        return;
    };
    use std::collections::HashMap;
    use velarx_runtime::network::engine::{ContainerNetworks, EngineOptions};
    use velarx_runtime::network::{CreateNetworkRequest, NetworkDriver, NetworkService};
    let work = tempfile::Builder::new()
        .prefix("shnet-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let db = velarx_db::Database::open_in_memory().await.unwrap();
    let cfg = velarx_config::NetworkConfig::default();
    let engine = std::sync::Arc::new(
        ContainerNetworks::new(
            db.clone(),
            EngineOptions {
                state_dir: work.path().to_path_buf(),
                db_path: work.path().join("db.sqlite"),
                bridge: cfg.bridge.clone(),
                table: "shcreate".into(),
                dns_exe: dns_exe(),
                cni: cfg.cni.clone(),
                providers: Vec::new(),
            },
        )
        .unwrap(),
    );
    let svc = NetworkService::new(db, cfg, engine);
    let req = |name: &str, subnet: &str, opts: &[(&str, &str)]| CreateNetworkRequest {
        name: name.into(),
        driver: NetworkDriver::Bridge,
        subnet: Some(subnet.into()),
        gateway: None,
        subnet6: None,
        gateway6: None,
        options: opts
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<HashMap<_, _>>(),
        routes: vec![],
    };
    sh("ip link add shhost2 type dummy; ip addr add 10.213.41.1/24 dev shhost2");
    let e = svc
        .create(req(
            "n1",
            "10.213.40.0/24",
            &[("interface_name", "shhost2")],
        ))
        .await
        .unwrap_err();
    assert!(e.to_string().contains("exists on the host"), "{e}");
    let e = svc
        .create(req("n2", "10.213.41.0/24", &[]))
        .await
        .unwrap_err();
    assert!(e.to_string().contains("overlaps"), "{e}");
    assert!(svc
        .create(req(
            "n3",
            "10.213.40.0/24",
            &[("podman.interface_name", "shhost2")]
        ))
        .await
        .is_err());
    svc.create(req("n4", "10.213.40.0/24", &[])).await.unwrap();
    sh("ip link del shhost2");
}

/// An AAAA query for NAME to SERVER: the addresses of the answer.
fn resolve6(server: SocketAddr, name: &str) -> std::io::Result<Vec<std::net::Ipv6Addr>> {
    let mut q = vec![0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in name.split('.') {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 28, 0, 1]);
    let s = UdpSocket::bind("0.0.0.0:0")?;
    s.set_read_timeout(Some(Duration::from_secs(3)))?;
    s.send_to(&q, server)?;
    let mut buf = [0u8; 512];
    let n = s.recv(&mut buf)?;
    let r = &buf[..n];
    let count = u16::from_be_bytes([r[6], r[7]]) as usize;
    // The answers are at the end: 28 bytes each with an AAAA record.
    Ok((0..count)
        .map(|i| {
            let end = n - (count - 1 - i) * 28;
            let b: [u8; 16] = r[end - 16..end].try_into().unwrap();
            std::net::Ipv6Addr::from(b)
        })
        .collect())
}

/// A server on [::]:PORT in the namespace on PATH that answers MSG.
fn serve6(path: &Path, port: u16, msg: &'static str) {
    let ns = std::fs::File::open(path)
        .unwrap()
        .as_fd()
        .try_clone_to_owned()
        .unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        rustix::thread::move_into_link_name_space(
            ns.as_fd(),
            Some(rustix::thread::LinkNameSpaceType::Network),
        )
        .unwrap();
        let l = TcpListener::bind(("::", port)).unwrap();
        tx.send(()).unwrap();
        for s in l.incoming().flatten() {
            let mut s = s;
            let _ = s.write_all(msg.as_bytes());
        }
    });
    rx.recv().unwrap();
}

/// A dual-stack network: the containers reach each other over IPv6, by
/// address and by name (AAAA), a port is published on IPv6 too, and the
/// teardown leaves no IPv6 table behind.
#[test]
fn dual_stack_end_to_end() {
    let Some(_namespace) = usable() else {
        return;
    };
    let work = tempfile::Builder::new()
        .prefix("shnet-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let o = opts(work.path(), "shtest6");
    let mut n = own_net("shtb6", 50, false);
    n.subnet6 = Subnet6::parse("fd00:213:50::/64");
    n.gateway6 = Some("fd00:213:50::1".parse().unwrap());
    let (pa, pb) = (work.path().join("a.netns"), work.path().join("b.netns"));
    pin_netns(&pa).unwrap();
    pin_netns(&pb).unwrap();
    let a = on(&n, "six1", 2, &[]);
    let b = on(&n, "six2", 3, &["18090:80"]);
    bridge::setup(&o, &pa, &a).unwrap();
    bridge::setup(&o, &pb, &b).unwrap();

    let route = sh(&format!(
        "nsenter --net={} ip -6 route show default",
        pb.display()
    ));
    assert!(
        route.contains("default via fd00:213:50::1 dev eth0"),
        "{route}"
    );
    let addr = sh(&format!(
        "nsenter --net={} ip -6 -o addr show eth0",
        pb.display()
    ));
    let global = addr.lines().find(|l| l.contains("fd00:213:50::3/64"));
    assert!(global.is_some_and(|l| !l.contains("tentative")), "{addr}");

    serve6(&pb, 80, "from-six2");
    let to_b: SocketAddr = "[fd00:213:50::3]:80".parse().unwrap();
    assert_eq!(inside(&pa, move || fetch(to_b)), "from-six2");
    // The IPv4 address answers as well (dual stack).
    let to_b4: SocketAddr = "10.213.50.3:80".parse().unwrap();
    assert_eq!(inside(&pa, move || fetch(to_b4)), "from-six2");
    // The published port, on an IPv6 address of the host.
    let published: SocketAddr = "[fd00:213:50::1]:18090".parse().unwrap();
    assert_eq!(fetch(published).unwrap(), "from-six2");
    let dns: SocketAddr = "10.213.50.1:53".parse().unwrap();
    // (the DNS server takes the record in on its own: asked again until it has it)
    let mut got = Vec::new();
    for _ in 0..50 {
        got = inside(&pa, move || resolve6(dns, "six2"))
            .into_iter()
            .collect();
        if !got.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        got,
        vec!["fd00:213:50::3".parse::<std::net::Ipv6Addr>().unwrap()],
        "the DNS server never learned six2 within 5 s"
    );
    let table = sh("nft list table ip6 shtest6");
    assert!(table.contains("fd00:213:50::/64"), "{table}");

    bridge::teardown(&o, Some(&pa), &a, NetnsFate::Stays).unwrap();
    bridge::teardown(&o, Some(&pb), &b, NetnsFate::Stays).unwrap();
    bridge::unpin_netns(&pa);
    bridge::unpin_netns(&pb);
    bridge::network_remove(&o, &a.attachments[0].net).unwrap();
    assert!(!bridge_exists("shtb6"));
    for family in ["ip", "ip6"] {
        let out = std::process::Command::new(find_nft().unwrap())
            .args(["list", "table", family, "shtest6"])
            .output()
            .unwrap();
        assert!(!out.status.success(), "the {family} table is left");
    }
}

/// The DNS server says why it does not serve a network: a gateway whose port
/// 53 is taken is in its log, not silently left without DNS.
#[test]
fn the_dns_server_says_why_it_does_not_serve_a_network() {
    let Some(_namespace) = usable() else {
        return;
    };
    let work = tempfile::Builder::new()
        .prefix("shnet-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let o = opts(work.path(), "shdnslog");
    sh("ip addr add 10.213.60.1/24 dev lo");
    let taken = TcpListener::bind("10.213.60.1:53").unwrap();
    let n = own_net("shdl0", 60, false);
    let c = on(&n, "logged", 2, &[]);
    velarx_netkernel::dnsrec::register(&o.state_dir, &c, &o.dns_exe).unwrap();
    let log = o.state_dir.join("dns/server.log");
    let said = velarx_base::testing::wait_file(&log, Duration::from_secs(30), |t| !t.is_empty())
        .expect("the server said nothing");
    assert!(
        said.contains("shdl0") && said.contains("10.213.60.1:53"),
        "{said}"
    );
    drop(taken);
    velarx_netkernel::dnsrec::unregister(&o.state_dir, &c);
    let sock = o.state_dir.join("dns/control.sock");
    assert!(velarx_base::testing::wait_gone(
        &sock,
        Duration::from_secs(10)
    ));
    sh("ip addr del 10.213.60.1/24 dev lo");
}

/// A network whose record cannot be read is removed by its id (`network rm
/// --force`): the bridge with its owner mark goes, and its rules and DNS
/// elements with it, as if the record had been read.  A bridge of another
/// network stays.
#[test]
fn a_network_is_removed_by_the_mark_of_its_bridge() {
    let Some(_namespace) = usable() else {
        return;
    };
    let work = tempfile::Builder::new()
        .prefix("shnet-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let o = opts(work.path(), "shmark");
    let mut n = own_net("shmk0", 61, false);
    n.subnet6 = Subnet6::parse("fd00:213:61::/64");
    n.gateway6 = "fd00:213:61::1".parse().ok();
    let other = own_net("shmk1", 62, false);
    let (pa, pb) = (work.path().join("a.netns"), work.path().join("b.netns"));
    for (p, c) in [
        (&pa, on(&n, "marked", 2, &[])),
        (&pb, on(&other, "kept", 2, &[])),
    ] {
        pin_netns(p).unwrap();
        bridge::setup(&o, p, &c).unwrap();
    }
    bridge::unpin_netns(&pa);
    let list = |family: &str| sh(&format!("nft list table {family} shmark"));
    assert!(list("ip").contains("shmk0"), "{}", list("ip"));
    bridge::network_remove_by_mark(&o, &n.id).unwrap();
    assert!(!bridge_exists("shmk0"));
    assert!(bridge_exists("shmk1"));
    let (v4, v6) = (list("ip"), list("ip6"));
    assert!(!v4.contains("shmk0") && !v4.contains("10.213.61"), "{v4}");
    assert!(!v6.contains("shmk0") && !v6.contains("fd00:213:61"), "{v6}");
    assert!(v4.contains("shmk1"), "{v4}");
    // no bridge with the mark any more: nothing to do, no error
    bridge::network_remove_by_mark(&o, &n.id).unwrap();
    bridge::unpin_netns(&pb);
    bridge::network_remove(&o, &other).unwrap();
    assert!(!bridge_exists("shmk1"));
}
