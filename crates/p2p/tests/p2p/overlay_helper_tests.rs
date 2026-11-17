// SPDX-License-Identifier: Apache-2.0
//! The privileged helper of the P2P overlay, for real: as root, in a
//! network namespace of its own (`unshare -n`), the helper being this test
//! binary again.  It makes the veth of a container, hands a packet socket
//! over, routes in the container's namespace only when its eth0 is that
//! veth, refuses what is not its job, and is confined.

use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::process::{Child, Command, Stdio};
use velarx_p2p::overlay_helper::{self, Client, DnsRouting, Reply, Request};

const CHILD: &str = "VELARX_OVERLAY_HELPER_CHILD";
const ID: &str = "0123abcdef0123abcdef";

fn overlay() -> ipnet::Ipv4Net {
    "10.213.0.0/16".parse().unwrap()
}

/// The network namespace of the tests, which they change as a whole (the
/// links of the container `ID`): one test at a time.
static NAMESPACE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Root, in a network namespace that is not the one of PID 1: the
/// namespace for the test, held until its end.
fn usable() -> Option<std::sync::MutexGuard<'static, ()>> {
    if !rustix::process::geteuid().is_root() {
        eprintln!("skipped: not root");
        return None;
    }
    let ino = |p: &str| std::fs::metadata(p).map(|m| m.ino()).ok();
    if ino("/proc/self/ns/net") == ino("/proc/1/ns/net") {
        eprintln!("skipped: run in a network namespace of its own (unshare -n)");
        return None;
    }
    Some(NAMESPACE.lock().unwrap_or_else(|e| e.into_inner()))
}

fn sh(cmd: &str) -> String {
    let o = Command::new("sh").arg("-c").arg(cmd).output().unwrap();
    String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr)
}

fn helper() -> (Client, Child) {
    let (mine, theirs) = overlay_helper::socketpair().unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "overlay_helper_tests::helper_child",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, overlay_helper::args(&overlay()).join(" "))
        .stdin(Stdio::from(theirs))
        .spawn()
        .unwrap();
    (Client::new(mine), child)
}

/// The helper: confine and serve (run by `helper`).
#[test]
fn helper_child() {
    let Some(args) = std::env::var_os(CHILD) else {
        return;
    };
    let args: Vec<String> = args
        .to_string_lossy()
        .split(' ')
        .map(String::from)
        .collect();
    // The test harness has threads: the confinement applies to this one,
    // which serves.
    overlay_helper::main(&args).unwrap();
}

/// The network namespace of the process PID, as the engine passes it.
fn netns(pid: u32) -> std::fs::File {
    std::fs::File::open(format!("/proc/{pid}/ns/net")).unwrap()
}

/// A process in a network namespace of its own: the container.
/// A process in a network namespace of its own, returned once it is in it
/// (it says so).
fn container() -> Child {
    let mut c = Command::new("unshare")
        .args(["-n", "sh", "-c", "echo in; exec sleep 60"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(c.stdout.as_mut().unwrap()),
        &mut line,
    )
    .unwrap();
    assert_eq!(line, "in\n", "the namespace of the container");
    c
}

#[test]
fn the_helper_makes_the_overlay_of_a_container() {
    let Some(_namespace) = usable() else {
        return;
    };
    let _ = Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status();
    let (client, mut child) = helper();

    let refused = |r: Request| client.call(&r).unwrap_err().to_string();
    let refused_in = |r: Request, pid: u32| {
        client
            .call_with(&r, Some(netns(pid).as_fd()))
            .unwrap_err()
            .to_string()
    };
    // Nothing before the node's subnet, a subnet in the overlay, once.
    assert!(refused(Request::Forwarding).contains("no Init"));
    let outside = Request::Init {
        node_subnet: "10.214.90.0/24".into(),
        dns_table: DnsRouting::DEFAULT.table,
        dns_rule_priority: DnsRouting::DEFAULT.rule_priority,
    };
    assert!(refused(outside).contains("not one of the overlay"));
    let init = Request::Init {
        node_subnet: "10.213.90.0/24".into(),
        dns_table: DnsRouting::DEFAULT.table,
        dns_rule_priority: DnsRouting::DEFAULT.rule_priority,
    };
    assert_eq!(client.call(&init).unwrap().0, Reply::Ok);
    assert!(refused(init).contains("already"));

    // Not its job.
    let bad_ip = Request::Prepare {
        id: ID.into(),
        ip: "10.213.91.2".parse().unwrap(),
    };
    assert!(refused(bad_ip).contains("not one of a container"));
    let bad_id = Request::Prepare {
        id: "../../x".into(),
        ip: "10.213.90.2".parse().unwrap(),
    };
    assert!(refused(bad_id).contains("invalid container id"));

    assert_eq!(client.call(&Request::Forwarding).unwrap().0, Reply::Ok);
    assert_eq!(sh("cat /proc/sys/net/ipv4/ip_forward").trim(), "1");

    let (reply, fd) = client
        .call(&Request::Prepare {
            id: ID.into(),
            ip: "10.213.90.2".parse().unwrap(),
        })
        .unwrap();
    let Reply::Prepared {
        veth_host,
        veth_container,
        ..
    } = reply
    else {
        panic!("{reply:?}");
    };
    let packets = fd.expect("a packet socket");
    assert_eq!(veth_host, "veth0123abcd");
    // The DNS of the node's address is routed to the host (it is no
    // address of the host); the DNS sockets are made on it for the
    // container that has a veth, bound to that veth.
    assert!(!sh("ip -o addr").contains("10.213.90.1/"));
    assert_eq!(dns_rules("10.213.90.1"), 2, "{}", sh("ip rule"));
    let dns = |id: &str, tcp| client.call(&Request::Dns { id: id.into(), tcp });
    assert!(dns("1111abcdef", true)
        .unwrap_err()
        .to_string()
        .contains("no veth"));
    let (reply, udp) = dns(ID, false).unwrap();
    assert_eq!(reply, Reply::Ok);
    let udp = std::net::UdpSocket::from(udp.expect("a UDP socket"));
    assert_eq!(udp.local_addr().unwrap().to_string(), "10.213.90.1:53");
    let (_, tcp) = dns(ID, true).unwrap();
    let tcp = std::net::TcpListener::from(tcp.expect("a listening TCP socket"));
    assert_eq!(tcp.local_addr().unwrap().to_string(), "10.213.90.1:53");
    // (only the veth's own traffic: the host has no way to the address,
    // which is none of its own)
    assert_eq!(
        std::net::TcpStream::connect("10.213.90.1:53")
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NetworkUnreachable
    );
    drop((udp, tcp));
    assert!(sh(&format!("ip -o addr show {veth_container}")).contains("10.213.90.2/32"));
    assert!(sh("ip route").contains(&format!("10.213.90.2 dev {veth_host}")));

    // The runtime moves the container's side into its namespace as eth0.
    let mut c = container();
    let pid = c.id();
    sh(&format!(
        "ip link set {veth_container} netns {pid} name eth0"
    ));
    // Not the host's namespace, not a process whose eth0 is not the veth.
    let me = Request::Started {
        id: ID.into(),
        default_route: true,
    };
    let e = refused_in(me.clone(), std::process::id());
    assert!(e.contains("host's"), "{e}");
    // A descriptor that is not a network namespace, or none.
    let file = std::fs::File::open("/dev/null").unwrap();
    let e = client
        .call_with(&me, Some(file.as_fd()))
        .unwrap_err()
        .to_string();
    assert!(e.contains("network namespace"), "{e}");
    assert!(refused(me).contains("not passed"));
    let mut other = container();
    sh(&format!(
        "ip link add shov0 type veth peer name eth0 netns {}",
        other.id()
    ));
    let wrong = Request::Started {
        id: ID.into(),
        default_route: true,
    };
    assert!(refused_in(wrong, other.id()).contains("is not the veth"));
    let _ = other.kill();
    let _ = other.wait();
    sh("ip link del shov0");

    let started = Request::Started {
        id: ID.into(),
        default_route: true,
    };
    // the answer carries the address of the container's eth0
    let Reply::Started { mac } = client
        .call_with(&started, Some(netns(pid).as_fd()))
        .unwrap()
        .0
    else {
        panic!("Started is answered with the address of eth0");
    };
    let eth0 = sh(&format!(
        "nsenter --net=/proc/{pid}/ns/net ip -o link show eth0"
    ));
    let mac_text = mac.map(|b| format!("{b:02x}")).join(":");
    assert!(
        eth0.contains(&format!("link/ether {mac_text} ")),
        "{mac_text} {eth0}"
    );
    let inside = sh(&format!("nsenter --net=/proc/{pid}/ns/net ip route"));
    assert!(
        inside.contains("default via 10.213.90.1 dev eth0 onlink"),
        "{inside}"
    );

    // The service reads the container's frames on the socket: the ARP
    // request of a ping to the gateway.
    rustix::net::sockopt::set_socket_timeout(
        &packets,
        rustix::net::sockopt::Timeout::Recv,
        Some(std::time::Duration::from_secs(3)),
    )
    .unwrap();
    let ping = Command::new("nsenter")
        .args([
            &format!("--net=/proc/{pid}/ns/net"),
            "ping",
            "-c",
            "1",
            "-W",
            "1",
            "10.213.90.1",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut got_arp = false;
    let mut buf = [0u8; 2048];
    for _ in 0..20 {
        let n = rustix::net::recv(&packets, &mut buf, rustix::net::RecvFlags::empty())
            .map_or(0, |(n, _)| n);
        if n < 14 {
            break;
        }
        if buf[12..14] == [0x08, 0x06] {
            got_arp = true;
            break;
        }
    }
    let mut ping = ping;
    let _ = ping.wait();
    assert!(got_arp, "no ARP frame on the packet socket");

    // The thread of the helper that serves keeps its four capabilities
    // (CAP_NET_BIND_SERVICE, CAP_NET_ADMIN, CAP_NET_RAW, CAP_SYS_ADMIN) and has
    // no new privileges, under seccomp.
    let confined = std::fs::read_dir(format!("/proc/{}/task", child.id()))
        .unwrap()
        .flatten()
        .filter_map(|t| std::fs::read_to_string(t.path().join("status")).ok())
        .any(|st| {
            st.lines().any(|l| l == "NoNewPrivs:\t1")
                && st.lines().any(|l| l == "CapEff:\t0000000000203400")
                && st.lines().any(|l| l == "Seccomp:\t2")
        });
    assert!(confined, "no confined thread in the helper");

    assert_eq!(
        client.call(&Request::Cleanup { id: ID.into() }).unwrap().0,
        Reply::Ok
    );
    assert!(!sh("ip -o link").contains(&veth_host));
    let _ = c.kill();
    let _ = c.wait();
    // the helper ends with the service: the routing of the DNS goes
    drop(client);
    let _ = child.wait();
    assert_eq!(dns_rules("10.213.90.1"), 0, "{}", sh("ip rule"));
    assert!(sh("ip route show table all").find("10.213.90.1").is_none());
}

/// The rules that route the DNS of the node's address NODE_IP to the host.
fn dns_rules(node_ip: &str) -> usize {
    sh("ip rule")
        .lines()
        .filter(|l| l.contains(&format!("to {node_ip} ")) && l.contains("dport 53"))
        .count()
}

/// A helper that was killed leaves the routing of the DNS (nothing of it
/// can run): the next one removes it, and makes it once.
#[test]
fn a_killed_helpers_routing_is_removed_by_the_next() {
    let Some(_namespace) = usable() else {
        return;
    };
    let init = Request::Init {
        node_subnet: "10.213.94.0/24".into(),
        dns_table: DnsRouting::DEFAULT.table,
        dns_rule_priority: DnsRouting::DEFAULT.rule_priority,
    };
    let (client, mut child) = helper();
    assert_eq!(client.call(&init).unwrap().0, Reply::Ok);
    assert_eq!(dns_rules("10.213.94.1"), 2);
    child.kill().unwrap();
    let _ = child.wait();
    assert_eq!(dns_rules("10.213.94.1"), 2, "left by the killed helper");
    assert!(!sh("ip -o addr").contains("10.213.94.1/"));
    let (client, mut child) = helper();
    assert_eq!(client.call(&init).unwrap().0, Reply::Ok);
    assert_eq!(dns_rules("10.213.94.1"), 2, "{}", sh("ip rule"));
    let routes = sh("ip route show table all");
    assert_eq!(routes.matches("local 10.213.94.1 ").count(), 1, "{routes}");
    drop(client);
    let _ = child.wait();
    assert_eq!(dns_rules("10.213.94.1"), 0, "{}", sh("ip rule"));
    assert!(sh("ip route show table all").find("10.213.94.1").is_none());
}

/// A second Prepare of an id whose Cleanup never came replaces the veth
/// left over (it was refused: "the container has its veth already"): one
/// pair, the new address and route, the old ones gone with it.
#[test]
fn a_prepare_replaces_the_veth_left_over() {
    let Some(_namespace) = usable() else {
        return;
    };
    let init = Request::Init {
        node_subnet: "10.213.95.0/24".into(),
        dns_table: DnsRouting::DEFAULT.table,
        dns_rule_priority: DnsRouting::DEFAULT.rule_priority,
    };
    let (client, mut child) = helper();
    assert_eq!(client.call(&init).unwrap().0, Reply::Ok);
    let prepare = |ip: &str| {
        client
            .call(&Request::Prepare {
                id: ID.into(),
                ip: ip.parse().unwrap(),
            })
            .unwrap()
    };
    let (first, _packets) = prepare("10.213.95.2");
    assert!(matches!(first, Reply::Prepared { .. }), "{first:?}");
    let (second, packets) = prepare("10.213.95.3");
    let Reply::Prepared {
        veth_host,
        veth_container,
        ..
    } = second
    else {
        panic!("{second:?}");
    };
    assert!(packets.is_some(), "a packet socket");
    let links = sh("ip -o link");
    assert_eq!(
        links.matches(&format!("{veth_host}@")).count(),
        1,
        "{links}"
    );
    let addrs = sh(&format!("ip -o addr show {veth_container}"));
    assert!(addrs.contains("10.213.95.3/32"), "{addrs}");
    assert!(!addrs.contains("10.213.95.2/"), "{addrs}");
    let routes = sh("ip route");
    assert!(
        routes.contains(&format!("10.213.95.3 dev {veth_host}")),
        "{routes}"
    );
    assert!(!routes.contains("10.213.95.2 "), "{routes}");
    assert_eq!(
        client.call(&Request::Cleanup { id: ID.into() }).unwrap().0,
        Reply::Ok
    );
    assert!(!sh("ip -o link").contains(&veth_host));
    drop(client);
    let _ = child.wait();
}

/// The table and the priority of the DNS routing are the ones asked for
/// (the host may use the defaults), and the helper refuses the kernel's.
#[test]
fn the_dns_is_routed_by_the_table_and_the_priority_asked_for() {
    let Some(_namespace) = usable() else {
        return;
    };
    let (client, child) = helper();
    let mut child = child;
    let init = |table, rule_priority| Request::Init {
        node_subnet: "10.213.95.0/24".into(),
        dns_table: table,
        dns_rule_priority: rule_priority,
    };
    let e = client.call(&init(254, 700)).unwrap_err().to_string();
    assert!(e.contains("kernel's"), "{e}");
    let e = client.call(&init(7777, 32766)).unwrap_err().to_string();
    assert!(e.contains("priority"), "{e}");
    assert_eq!(dns_rules("10.213.95.1"), 0);
    assert_eq!(client.call(&init(7777, 700)).unwrap().0, Reply::Ok);
    let rules = sh("ip rule");
    let ours: Vec<&str> = rules
        .lines()
        .filter(|l| l.contains("to 10.213.95.1 ") && l.contains("dport 53"))
        .collect();
    assert_eq!(ours.len(), 2, "{rules}");
    assert!(
        ours.iter()
            .all(|l| l.starts_with("700:") && l.contains("lookup 7777")),
        "{rules}"
    );
    assert!(sh("ip route show table 7777").contains("local 10.213.95.1"));
    drop(client);
    let _ = child.wait();
    assert_eq!(dns_rules("10.213.95.1"), 0, "{}", sh("ip rule"));
}

/// The unprivileged side: the overlay manager of the service, on the
/// helper's packet sockets (it opens none, makes no link, writes no
/// sysctl), answers the ARP request of a container for its gateway with
/// the host side's address.
#[test]
fn the_service_relays_on_the_helpers_sockets() {
    let Some(_namespace) = usable() else {
        return;
    };
    let _ = Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status();
    let (client, mut child) = helper();
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("swarm.key");
    velarx_p2p::control::generate_swarm_key(&key).unwrap();
    std::fs::set_permissions(&key, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut c = container();
    let pid = c.id();
    let neigh = rt.block_on(async {
        let node = std::sync::Arc::new(
            velarx_p2p::P2PNode::with_config(velarx_p2p::P2PConfig {
                role: velarx_p2p::Role::Overlay,
                dial: velarx_p2p::dial_filter::Rules::on_one_host(),
                listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".into()],
                enable_mdns: false,
                private_key_path: Some(key),
                ..Default::default()
            })
            .await
            .unwrap(),
        );
        let subnet: ipnet::Ipv4Net = "10.213.91.0/24".parse().unwrap();
        let init = Request::Init {
            node_subnet: subnet.to_string(),
            dns_table: DnsRouting::DEFAULT.table,
            dns_rule_priority: DnsRouting::DEFAULT.rule_priority,
        };
        assert_eq!(client.call(&init).unwrap().0, Reply::Ok);
        let mut m = velarx_p2p::tun_overlay::TunOverlayManager::new(
            node.peer_id(),
            "10.213.0.0/16".parse().unwrap(),
            subnet,
            node,
            std::sync::Arc::new(client),
            Vec::new(),
        );
        m.start().await.unwrap();
        let (o, dev) = m.prepare_container(ID).await.unwrap();
        sh(&format!(
            "ip link set {} netns {pid} name {}",
            dev.host_if_name, dev.container_if_name
        ));
        m.container_started(ID, netns(pid).into(), true)
            .await
            .unwrap();
        let ns = format!("--net=/proc/{pid}/ns/net");
        let _ = Command::new("nsenter")
            .args([ns.as_str(), "ping", "-c", "1", "-W", "1", "10.213.91.1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let neigh = sh(&format!("nsenter {ns} ip neigh show 10.213.91.1"));
        m.cleanup_container(ID).await.unwrap();
        (neigh, o.host_mac)
    });
    let mac = neigh
        .1
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    assert!(neigh.0.contains(&format!("lladdr {mac}")), "{}", neigh.0);
    let _ = c.kill();
    let _ = c.wait();
    let _ = child.kill();
    let _ = child.wait();
}

/// Two containers of the node reach each other through the service: the
/// ARP of each for the gateway is answered, and the packets of one go to
/// the MAC address of the other's `eth0` that the helper told, both ways.
/// A third one that sends with the address of the first is not heard (the
/// kernel forwards between the containers of a node: its filter of the
/// source addresses of each veth is strict).
#[test]
fn the_containers_of_a_node_reach_each_other() {
    let Some(_namespace) = usable() else {
        return;
    };
    let _ = Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status();
    let (client, mut child) = helper();
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("swarm.key");
    velarx_p2p::control::generate_swarm_key(&key).unwrap();
    std::fs::set_permissions(&key, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (mut c1, mut c2, mut c3) = (container(), container(), container());
    let (pid1, pid2, pid3) = (c1.id(), c2.id(), c3.id());
    let (ids, pinged) = rt.block_on(async {
        let node = std::sync::Arc::new(
            velarx_p2p::P2PNode::with_config(velarx_p2p::P2PConfig {
                role: velarx_p2p::Role::Overlay,
                dial: velarx_p2p::dial_filter::Rules::on_one_host(),
                listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".into()],
                enable_mdns: false,
                private_key_path: Some(key),
                ..Default::default()
            })
            .await
            .unwrap(),
        );
        let subnet: ipnet::Ipv4Net = "10.213.92.0/24".parse().unwrap();
        let init = Request::Init {
            node_subnet: subnet.to_string(),
            dns_table: DnsRouting::DEFAULT.table,
            dns_rule_priority: DnsRouting::DEFAULT.rule_priority,
        };
        assert_eq!(client.call(&init).unwrap().0, Reply::Ok);
        let mut m = velarx_p2p::tun_overlay::TunOverlayManager::new(
            node.peer_id(),
            "10.213.0.0/16".parse().unwrap(),
            subnet,
            node,
            std::sync::Arc::new(client),
            Vec::new(),
        );
        m.start().await.unwrap();
        let ids = [
            "1111abcdef0123abcdef",
            "2222abcdef0123abcdef",
            "3333abcdef0123abcdef",
        ];
        let mut ips = Vec::new();
        for (id, pid) in ids.iter().zip([pid1, pid2, pid3]) {
            let (o, dev) = m.prepare_container(id).await.unwrap();
            // (the runtime moves a net device with its addresses, as the
            // OCI runtime spec asks; `ip link` leaves them behind)
            sh(&format!(
                "ip link set {} netns {pid} name {} && \
                 nsenter --net=/proc/{pid}/ns/net ip addr add {}/32 dev {}",
                dev.host_if_name, dev.container_if_name, o.overlay_ip, dev.container_if_name
            ));
            m.container_started(id, netns(pid).into(), true)
                .await
                .unwrap();
            ips.push(o.overlay_ip);
        }
        let ping = |pid: u32, ip: std::net::Ipv4Addr| {
            Command::new("nsenter")
                .args([
                    format!("--net=/proc/{pid}/ns/net").as_str(),
                    "ping",
                    "-c",
                    "2",
                    "-W",
                    "2",
                    &ip.to_string(),
                ])
                .output()
                .unwrap()
        };
        let (ip1, ip2) = (ips[0], ips[1]);
        let pinged = (
            tokio::task::spawn_blocking(move || ping(pid1, ip2))
                .await
                .unwrap(),
            tokio::task::spawn_blocking(move || ping(pid2, ip1))
                .await
                .unwrap(),
        );
        // the kernel delivers the packets, the service does not do it again
        let (dups, tcp, udp, own, spoofed) = tokio::task::spawn_blocking(move || {
            (
                ping_duplicates(pid1, ip2),
                tcp_transfer(pid1, pid2, ip2, 4 << 20),
                udp_datagrams(pid2, pid1, ip1, None),
                udp_datagrams(pid3, pid2, ip2, None),
                udp_datagrams(pid3, pid2, ip2, Some(ip1)),
            )
        })
        .await
        .unwrap();
        assert!(own >= 5, "UDP of a third container, as itself: {own}");
        assert_eq!(spoofed, 0, "UDP with the address of another container");
        assert_eq!(dups, (true, 0), "the packets came twice");
        assert_eq!(tcp, 4 << 20, "TCP between the containers of a node");
        assert!(udp >= 5, "UDP between the containers of a node: {udp}");
        for id in ids {
            m.cleanup_container(id).await.unwrap();
        }
        (ids, pinged)
    });
    for (id, out) in ids.iter().zip([pinged.0, pinged.1]) {
        assert!(
            out.status.success(),
            "{id}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    for c in [&mut c1, &mut c2, &mut c3] {
        let _ = c.kill();
        let _ = c.wait();
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// A TCP server in the namespace of PID (it prints the bytes it got) and
/// the transfer of `bytes` from the namespace of FROM to it: the bytes the
/// server read.  What the container stack does with a packet whose
/// checksum is wrong is to drop it: the transfer would not come.
fn tcp_transfer(from: u32, server: u32, ip: std::net::Ipv4Addr, bytes: usize) -> usize {
    const SERVER: &str = "import socket\ns=socket.socket()\ns.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\ns.bind(('0.0.0.0',5001))\ns.listen(1)\ns.settimeout(15)\nc,_=s.accept()\nc.settimeout(15)\nn=0\nwhile True:\n d=c.recv(65536)\n if not d: break\n n+=len(d)\nprint(n)\n";
    const CLIENT: &str = "import socket,sys,time\nend=time.time()+10\nwhile True:\n try:\n  c=socket.create_connection((sys.argv[1],5001),timeout=3)\n  break\n except OSError:\n  if time.time()>end: raise\n  time.sleep(0.3)\nc.sendall(b'x'*int(sys.argv[2]))\nc.close()\n";
    let nsenter = |pid: u32| format!("--net=/proc/{pid}/ns/net");
    let server = Command::new("nsenter")
        .args([nsenter(server).as_str(), "python3", "-c", SERVER])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let client = Command::new("nsenter")
        .args([
            nsenter(from).as_str(),
            "python3",
            "-c",
            CLIENT,
            &ip.to_string(),
            &bytes.to_string(),
        ])
        .output()
        .unwrap();
    assert!(
        client.status.success(),
        "tcp client: {}",
        String::from_utf8_lossy(&client.stderr)
    );
    let out = server.wait_with_output().unwrap();
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .unwrap_or(0)
}

/// UDP datagrams from the namespace of FROM to a server in that of SERVER:
/// how many of ten arrived (each is of 1000 bytes: the checksum of each is
/// the stack's to verify).
/// With `spoof`, from that address (added to the interface of FROM).
fn udp_datagrams(
    from: u32,
    server: u32,
    ip: std::net::Ipv4Addr,
    spoof: Option<std::net::Ipv4Addr>,
) -> usize {
    const SERVER: &str = "import socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\ns.bind(('0.0.0.0',5002))\ns.settimeout(6)\nn=0\ntry:\n while n<10:\n  d,_=s.recvfrom(2000)\n  n+=len(d)==1000\nexcept socket.timeout: pass\nprint(n)\n";
    const CLIENT: &str = "import socket,sys,time\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\nif len(sys.argv)>2: s.bind((sys.argv[2],0))\nfor _ in range(10):\n s.sendto(b'u'*1000,(sys.argv[1],5002))\n time.sleep(0.2)\n";
    let nsenter = |pid: u32| format!("--net=/proc/{pid}/ns/net");
    let server = Command::new("nsenter")
        .args([nsenter(server).as_str(), "python3", "-c", SERVER])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(500));
    let mut args = vec![ip.to_string()];
    if let Some(spoof) = spoof {
        let added = Command::new("nsenter")
            .args([nsenter(from).as_str(), "ip", "addr", "add"])
            .arg(format!("{spoof}/32"))
            .args(["dev", "eth0"])
            .status()
            .unwrap();
        assert!(added.success(), "the address is added to the sender");
        args.push(spoof.to_string());
    }
    let client = Command::new("nsenter")
        .args([nsenter(from).as_str(), "python3", "-c", CLIENT])
        .args(&args)
        .output()
        .unwrap();
    assert!(client.status.success(), "udp client");
    let out = server.wait_with_output().unwrap();
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .unwrap_or(0)
}

/// A ping of IP from the namespace of PID: the replies, and how many of
/// them were duplicates (what two data planes make of one packet).
fn ping_duplicates(pid: u32, ip: std::net::Ipv4Addr) -> (bool, usize) {
    let out = Command::new("nsenter")
        .args([
            format!("--net=/proc/{pid}/ns/net").as_str(),
            "ping",
            "-c",
            "3",
            "-W",
            "2",
            &ip.to_string(),
        ])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    (out.status.success(), text.matches("(DUP!)").count())
}

/// The helper of a node whose host network is the namespace of PID.
fn helper_in(pid: u32) -> (Client, Child) {
    let (mine, theirs) = overlay_helper::socketpair().unwrap();
    let child = Command::new("nsenter")
        .arg(format!("--net=/proc/{pid}/ns/net"))
        .arg(std::env::current_exe().unwrap())
        .args([
            "overlay_helper_tests::helper_child",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, overlay_helper::args(&overlay()).join(" "))
        .stdin(Stdio::from(theirs))
        .spawn()
        .unwrap();
    (Client::new(mine), child)
}

/// Containers of two nodes, each node with a network namespace of its own
/// for its host side (the helpers' packet sockets are theirs, the services
/// are in this one), reach each other over the tunnel: pings come once,
/// TCP brings 4 MiB and UDP its datagrams (a frame read from a veth has the
/// checksum its sender left to the device), and a packet for a container of
/// the other node is not also sent out of the host by the kernel.
#[test]
fn the_containers_of_two_nodes_exchange_tcp_and_udp() {
    use velarx_p2p::tun_overlay::TunOverlayManager;
    let Some(_namespace) = usable() else {
        return;
    };
    let _ = Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status();
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("swarm.key");
    velarx_p2p::control::generate_swarm_key(&key).unwrap();
    std::fs::set_permissions(&key, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    // the host of node B, and the containers of both
    let mut host_b = container();
    let _ = Command::new("nsenter")
        .args([
            format!("--net=/proc/{}/ns/net", host_b.id()).as_str(),
            "ip",
            "link",
            "set",
            "lo",
            "up",
        ])
        .status();
    let host_b_pid = host_b.id();
    let (client_a, mut child_a) = helper();
    let (client_b, mut child_b) = helper_in(host_b_pid);
    let (mut ca, mut cb) = (container(), container());
    let (pid_a, pid_b) = (ca.id(), cb.id());
    let result = rt.block_on(async {
        use super::support::{address, connected_within};
        let node = |key: &std::path::Path| {
            let key = key.to_path_buf();
            async move {
                std::sync::Arc::new(
                    velarx_p2p::P2PNode::with_config(velarx_p2p::P2PConfig {
                        role: velarx_p2p::Role::Overlay,
                        dial: velarx_p2p::dial_filter::Rules::on_one_host(),
                        listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".into()],
                        enable_mdns: false,
                        private_key_path: Some(key),
                        ..Default::default()
                    })
                    .await
                    .unwrap(),
                )
            }
        };
        let (node_a, node_b) = (node(&key).await, node(&key).await);
        // (a node may only claim a subnet that its peer id gives)
        let base: ipnet::Ipv4Net = "10.213.0.0/16".parse().unwrap();
        let subnet_a = velarx_p2p::overlay_router::subnet_for(base, &node_a.peer_id(), 0);
        let mut subnet_b = velarx_p2p::overlay_router::subnet_for(base, &node_b.peer_id(), 0);
        if subnet_b == subnet_a {
            subnet_b = velarx_p2p::overlay_router::subnet_for(base, &node_b.peer_id(), 1);
        }
        let mut managers = Vec::new();
        let mut ips = Vec::new();
        for (node, client, subnet, id, pid, host) in [
            (
                &node_a,
                client_a,
                subnet_a,
                "1111abcdef0123abcdef",
                pid_a,
                String::new(),
            ),
            (
                &node_b,
                client_b,
                subnet_b,
                "2222abcdef0123abcdef",
                pid_b,
                format!("nsenter --net=/proc/{host_b_pid}/ns/net"),
            ),
        ] {
            let init = Request::Init {
                node_subnet: subnet.to_string(),
                dns_table: DnsRouting::DEFAULT.table,
                dns_rule_priority: DnsRouting::DEFAULT.rule_priority,
            };
            assert_eq!(client.call(&init).unwrap().0, Reply::Ok);
            let mut m = TunOverlayManager::new(
                node.peer_id(),
                base,
                subnet,
                node.clone(),
                std::sync::Arc::new(client),
                Vec::new(),
            );
            m.start().await.unwrap();
            let (o, dev) = m.prepare_container(id).await.unwrap();
            // (the veth is in the namespace of the host of its node)
            sh(&format!(
                "{host} ip link set {} netns {pid} name {} && \
                 nsenter --net=/proc/{pid}/ns/net ip addr add {}/32 dev {}",
                dev.host_if_name, dev.container_if_name, o.overlay_ip, dev.container_if_name
            ));
            m.container_started(id, netns(pid).into(), true)
                .await
                .unwrap();
            ips.push(o.overlay_ip);
            managers.push(m);
        }
        node_a.dial(address(&node_b).await).await.unwrap();
        for (a, b) in [(&node_a, &node_b), (&node_b, &node_a)] {
            assert!(connected_within(a, b, std::time::Duration::from_secs(10)).await);
        }
        for (node, m) in [&node_a, &node_b].into_iter().zip(&managers) {
            node.announce_tun_overlay(m.node_subnet()).await.unwrap();
        }
        let (ip_a, ip_b) = (ips[0], ips[1]);
        // (the first packets wait for the routes: ping until one is answered)
        let mut pinged = (false, 0);
        for _ in 0..10 {
            pinged = tokio::task::spawn_blocking(move || ping_duplicates(pid_a, ip_b))
                .await
                .unwrap();
            if pinged.0 {
                break;
            }
        }
        let (tcp, udp, back) = tokio::task::spawn_blocking(move || {
            (
                tcp_transfer(pid_a, pid_b, ip_b, 4 << 20),
                udp_datagrams(pid_b, pid_a, ip_a, None),
                tcp_transfer(pid_b, pid_a, ip_a, 1 << 20),
            )
        })
        .await
        .unwrap();
        // what the host of A sends out of its own network: nothing for the
        // overlay (the kernel has no route for it but the blackhole)
        let route = sh("ip route show");
        for (m, id) in managers
            .iter()
            .zip(["1111abcdef0123abcdef", "2222abcdef0123abcdef"])
        {
            m.cleanup_container(id).await.unwrap();
        }
        (pinged, tcp, udp, back, route)
    });
    for c in [&mut ca, &mut cb, &mut host_b] {
        let _ = c.kill();
        let _ = c.wait();
    }
    for c in [&mut child_a, &mut child_b] {
        let _ = c.kill();
        let _ = c.wait();
    }
    let (pinged, tcp, udp, back, route) = result;
    assert_eq!(pinged, (true, 0), "ping over the tunnel");
    assert_eq!(tcp, 4 << 20, "TCP from A to B");
    assert_eq!(back, 1 << 20, "TCP from B to A");
    assert!(udp >= 5, "UDP from B to A: {udp}");
    assert!(route.contains("blackhole 10.213.0.0/16"), "{route}");
}

/// A DNS query for NAME (type A, no EDNS).
fn dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = id.to_be_bytes().to_vec();
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

/// The name server of the host for the test: an answer of 3000 bytes to any
/// query, over UDP and over TCP, once each (the thread ends after).
fn big_upstream() -> std::net::SocketAddr {
    use std::io::{Read, Write};
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = tcp.local_addr().unwrap();
    let udp = std::net::UdpSocket::bind(addr).unwrap();
    let answer = |query: &[u8]| {
        let mut a = query.to_vec();
        a[2] |= 0x80;
        a.resize(3000, 0xab);
        a
    };
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let (n, client) = udp.recv_from(&mut buf).unwrap();
        udp.send_to(&answer(&buf[..n]), client).unwrap();
    });
    std::thread::spawn(move || {
        let (mut s, _) = tcp.accept().unwrap();
        let mut len = [0u8; 2];
        s.read_exact(&mut len).unwrap();
        let mut q = vec![0u8; usize::from(u16::from_be_bytes(len))];
        s.read_exact(&mut q).unwrap();
        let a = answer(&q);
        s.write_all(&(a.len() as u16).to_be_bytes()).unwrap();
        s.write_all(&a).unwrap();
    });
    addr
}

/// A container resolves names through the overlay's DNS, over UDP and over
/// TCP (a client of its own in the container's namespace, no tool): a
/// container's name over TCP, two queries on one connection, and a name of
/// the host's name server whose answer is too large for UDP: the UDP answer
/// is cut and truncated, and the retry over TCP gets it whole.
#[test]
fn a_container_resolves_over_udp_and_tcp() {
    use std::io::{Read, Write};
    let Some(_namespace) = usable() else {
        return;
    };
    let _ = Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status();
    let (client, mut child) = helper();
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("swarm.key");
    velarx_p2p::control::generate_swarm_key(&key).unwrap();
    std::fs::set_permissions(&key, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut c = container();
    let pid = c.id();
    let upstream = big_upstream();
    let id = "3333abcdef0123abcdef";
    rt.block_on(async {
        let node = std::sync::Arc::new(
            velarx_p2p::P2PNode::with_config(velarx_p2p::P2PConfig {
                role: velarx_p2p::Role::Overlay,
                dial: velarx_p2p::dial_filter::Rules::on_one_host(),
                listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".into()],
                enable_mdns: false,
                private_key_path: Some(key),
                ..Default::default()
            })
            .await
            .unwrap(),
        );
        node.overlay()
            .add_dns_record(velarx_p2p::DnsRecord {
                name: "web".into(),
                ipv4: "10.213.93.77".parse().unwrap(),
                container_id: "other".into(),
            })
            .await;
        let subnet: ipnet::Ipv4Net = "10.213.93.0/24".parse().unwrap();
        let init = Request::Init {
            node_subnet: subnet.to_string(),
            dns_table: DnsRouting::DEFAULT.table,
            dns_rule_priority: DnsRouting::DEFAULT.rule_priority,
        };
        assert_eq!(client.call(&init).unwrap().0, Reply::Ok);
        let mut m = velarx_p2p::tun_overlay::TunOverlayManager::new(
            node.peer_id(),
            "10.213.0.0/16".parse().unwrap(),
            subnet,
            node,
            std::sync::Arc::new(client),
            vec![upstream],
        );
        m.start().await.unwrap();
        let (o, dev) = m.prepare_container(id).await.unwrap();
        sh(&format!(
            "ip link set {} netns {pid} name {} && \
             nsenter --net=/proc/{pid}/ns/net ip addr add {}/32 dev {}",
            dev.host_if_name, dev.container_if_name, o.overlay_ip, dev.container_if_name
        ));
        m.container_started(id, netns(pid).into(), true)
            .await
            .unwrap();
        let server = m.node_ip();
        // A service of the host on the wildcard address, TCP and UDP: the
        // node's address must not reach it from a container (only its DNS)
        let host_tcp = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        host_tcp.set_nonblocking(true).unwrap();
        let host_port = host_tcp.local_addr().unwrap().port();
        let host_udp = std::net::UdpSocket::bind(("0.0.0.0", host_port)).unwrap();
        host_udp.set_nonblocking(true).unwrap();
        let asked = tokio::task::spawn_blocking(move || {
            // (the sockets are made in the container's namespace; the
            // timeouts are only upper bounds)
            in_netns(netns(pid), move || {
                let limit = Some(std::time::Duration::from_secs(10));
                let tcp_ask = |s: &mut std::net::TcpStream, q: &[u8]| {
                    s.write_all(&(q.len() as u16).to_be_bytes())?;
                    s.write_all(q)?;
                    let mut len = [0u8; 2];
                    s.read_exact(&mut len)?;
                    let mut a = vec![0u8; usize::from(u16::from_be_bytes(len))];
                    s.read_exact(&mut a)?;
                    Ok::<_, std::io::Error>(a)
                };
                // a container's name, twice on one connection
                let mut s = std::net::TcpStream::connect((server, 53))?;
                s.set_read_timeout(limit)?;
                let first = tcp_ask(&mut s, &dns_query(1, "web.velarx"))?;
                let second = tcp_ask(&mut s, &dns_query(2, "web.velarx"))?;
                // a name of the name server: UDP cut and truncated ...
                let udp = std::net::UdpSocket::bind("0.0.0.0:0")?;
                udp.set_read_timeout(limit)?;
                let q = dns_query(3, "big.example");
                udp.send_to(&q, (server, 53))?;
                let mut buf = vec![0u8; 4096];
                let n = udp.recv(&mut buf)?;
                let cut = buf[..n].to_vec();
                // ... and whole over TCP
                let mut t = std::net::TcpStream::connect((server, 53))?;
                t.set_read_timeout(limit)?;
                let whole = tcp_ask(&mut t, &q)?;
                // the host's service: not reached (the datagram goes first,
                // on the path of the connection; the timeout is an upper
                // bound: the host has no route to the node's address and
                // says so)
                udp.send_to(b"to the host", (server, host_port))?;
                let to_host = std::net::TcpStream::connect_timeout(
                    &(server, host_port).into(),
                    std::time::Duration::from_secs(5),
                );
                assert!(to_host.is_err(), "a host service reached: {to_host:?}");
                Ok((first, second, cut, whole))
            })
        })
        .await
        .unwrap()
        .unwrap();
        let (first, second, cut, whole) = asked;
        assert!(
            host_tcp.accept().is_err(),
            "no connection from the container"
        );
        let mut buf = [0u8; 64];
        assert!(
            host_udp.recv_from(&mut buf).is_err(),
            "no datagram from the container"
        );
        for (a, id) in [(&first, 1u16), (&second, 2)] {
            assert_eq!(a[..2], id.to_be_bytes());
            assert_eq!(a[6..8], [0, 1], "one answer");
            assert_eq!(a[a.len() - 4..], [10, 213, 93, 77]);
        }
        assert_eq!(cut[..2], 3u16.to_be_bytes());
        assert_ne!(cut[2] & 0x02, 0, "truncated");
        assert!(cut.len() < 100, "cut to the question");
        assert_eq!(whole.len(), 3000);
        assert_eq!(whole[..2], 3u16.to_be_bytes());
        assert_eq!(whole[2] & 0x02, 0, "not truncated");
        m.cleanup_container(id).await.unwrap();
    });
    let _ = c.kill();
    let _ = c.wait();
    let _ = child.kill();
    let _ = child.wait();
}

/// F in a thread in the network namespace NETNS.
fn in_netns<T: Send + 'static>(
    netns: std::fs::File,
    f: impl FnOnce() -> std::io::Result<T> + Send + 'static,
) -> std::io::Result<T> {
    velarx_netkernel::bridge::in_netns(netns.as_fd(), f)
}
