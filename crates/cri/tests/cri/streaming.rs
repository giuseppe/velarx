// SPDX-License-Identifier: Apache-2.0
//! The WebSocket exec stream, over an in-memory connection.

use crate::mock::Mock;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use velarx_cri::engine::{Engine, ExecSpec, ExecStream};
use velarx_cri::stream::{encode_frame, parse_frame, run_exec, Channels};

fn masked(payload: &[u8]) -> Vec<u8> {
    let key = [9u8, 8, 7, 6];
    let mut out = vec![0x82];
    match u16::try_from(payload.len()) {
        Ok(n) if n < 126 => out.push(0x80 | n as u8),
        Ok(n) => {
            out.push(0x80 | 126);
            out.extend_from_slice(&n.to_be_bytes());
        }
        Err(_) => panic!("a message of a test is less than 64 KiB"),
    }
    out.extend_from_slice(&key);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
    out
}

/// The binary messages the server sends until it closes.
async fn collect(mut rd: impl AsyncReadExt + Unpin) -> Vec<Vec<u8>> {
    let mut buf = Vec::new();
    let mut msgs = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        while let Some((f, used)) = parse_frame(&buf).unwrap() {
            buf.drain(..used);
            if f.opcode == 0x8 {
                return msgs;
            }
            msgs.push(f.payload);
        }
        match rd.read(&mut chunk).await {
            Ok(0) | Err(_) => return msgs,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

#[tokio::test]
async fn exec_echo_and_status() {
    let (mock, cri) = Mock::cri();
    drop(cri);
    mock.st
        .lock()
        .unwrap()
        .containers
        .push(velarx_proto::workload::ContainerRecord {
            id: "c".into(),
            ..Default::default()
        });
    mock.st.lock().unwrap().exec_exit = 3;
    let es = mock
        .exec_open(
            "c",
            &ExecSpec {
                cmd: vec!["cat".into()],
                stdin: true,
                stdout: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (server, mut client) = tokio::io::duplex(8192);
    let task = tokio::spawn(run_exec(
        mock.clone(),
        server,
        es,
        Channels {
            stdin: true,
            stdout: true,
            stderr: false,
            input_ends: false,
        },
        true,
    ));
    // stdin data, a resize, then the close of stdin
    client.write_all(&masked(b"\x00hello")).await.unwrap();
    client
        .write_all(&masked(b"\x04{\"Width\":80,\"Height\":24}"))
        .await
        .unwrap();
    client.write_all(&masked(b"\xff\x00")).await.unwrap();
    let (rd, _wr) = tokio::io::split(client);
    // the mock echoes stdin as output and ends when its stdin is closed
    let msgs = tokio::time::timeout(std::time::Duration::from_secs(10), collect(rd))
        .await
        .unwrap();
    task.await.unwrap();
    assert!(
        msgs.contains(&vec![1, b'h', b'e', b'l', b'l', b'o']),
        "{msgs:?}"
    );
    let status = msgs
        .iter()
        .find(|m| m[0] == 3 && m.len() > 1)
        .expect("a status");
    let text = String::from_utf8_lossy(&status[1..]);
    assert!(
        text.contains("NonZeroExitCode") && text.contains("\"message\":\"3\""),
        "{text}"
    );
    assert!(mock.calls().contains(&"resize 80x24".to_string()));
}

/// A size that cannot be applied does not end the session, and is not
/// dropped without a word: the log says why.
#[tokio::test]
async fn a_resize_that_fails_is_logged_and_the_session_goes_on() {
    let log = velarx_wire::logcapture::capture(tracing::Level::WARN);
    let (mock, cri) = Mock::cri();
    drop(cri);
    {
        let mut s = mock.st.lock().unwrap();
        s.containers.push(velarx_proto::workload::ContainerRecord {
            id: "c".into(),
            ..Default::default()
        });
        s.resize_fails = Some(crate::mock::Fail::Unavailable);
    }
    let es = mock
        .exec_open(
            "c",
            &ExecSpec {
                cmd: vec!["cat".into()],
                stdin: true,
                stdout: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (server, mut client) = tokio::io::duplex(8192);
    let task = tokio::spawn(run_exec(
        mock.clone(),
        server,
        es,
        Channels {
            stdin: true,
            stdout: true,
            stderr: false,
            input_ends: false,
        },
        true,
    ));
    client.write_all(&masked(b"\x00hi")).await.unwrap();
    client
        .write_all(&masked(b"\x04{\"Width\":80,\"Height\":24}"))
        .await
        .unwrap();
    client.write_all(&masked(b"\x04not a size")).await.unwrap();
    client.write_all(&masked(b"\xff\x00")).await.unwrap();
    let (rd, _wr) = tokio::io::split(client);
    let msgs = tokio::time::timeout(std::time::Duration::from_secs(10), collect(rd))
        .await
        .unwrap();
    task.await.unwrap();
    assert!(msgs.contains(&vec![1, b'h', b'i']), "{msgs:?}");
    let text = log.text();
    assert!(
        text.contains("cannot resize the terminal") && text.contains("engine is gone"),
        "{text}"
    );
    assert!(text.contains("terminal size"), "{text}");
}

/// A client that sends much more input than the pipes hold while it reads
/// the output: the command (the mock: a `cat` behind buffers of 4 KiB) takes
/// its input only as its output is read, so the output goes on while the
/// input waits, and every byte comes back once, in order.
#[tokio::test]
async fn a_large_input_and_its_output_go_together() {
    let (mock, cri) = Mock::cri();
    drop(cri);
    mock.st
        .lock()
        .unwrap()
        .containers
        .push(velarx_proto::workload::ContainerRecord {
            id: "c".into(),
            ..Default::default()
        });
    let spec = ExecSpec {
        cmd: vec!["cat".into()],
        stdin: true,
        stdout: true,
        ..Default::default()
    };
    let es = mock.exec_open("c", &spec).await.unwrap();
    let (server, client) = tokio::io::duplex(8192);
    let channels = Channels {
        stdin: true,
        stdout: true,
        stderr: false,
        input_ends: false,
    };
    let task = tokio::spawn(run_exec(mock.clone(), server, es, channels, true));
    // (a counter, so that a stream gone wrong shows where)
    let want: Vec<u8> = (0..1u32 << 20).map(|i| (i / 7 % 251) as u8).collect();
    let (rd, mut wr) = tokio::io::split(client);
    let sent = want.clone();
    let feeder = tokio::spawn(async move {
        for piece in sent.chunks(16 * 1024) {
            let mut msg = vec![0u8];
            msg.extend_from_slice(piece);
            wr.write_all(&masked(&msg)).await.unwrap();
        }
        wr.write_all(&masked(b"\xff\x00")).await.unwrap();
        wr
    });
    // (an upper bound: a relay that waits to pass the input before it reads
    // the output waits for ever)
    let msgs = tokio::time::timeout(Duration::from_secs(20), collect(rd))
        .await
        .expect("the input and the output waited for each other");
    let got: Vec<u8> = msgs
        .iter()
        .filter(|m| m.first() == Some(&1))
        .flat_map(|m| m[1..].to_vec())
        .collect();
    let at = got.iter().zip(&want).position(|(a, b)| a != b);
    assert_eq!((at, got.len()), (None, want.len()), "first difference");
    let _wr = feeder.await.unwrap();
    task.await.unwrap();
}

/// A command without a terminal whose client goes away is killed, and its
/// stream ends; one that ended by itself is not.
#[tokio::test]
async fn an_exec_is_killed_when_its_client_goes_away() {
    let (mock, cri) = Mock::cri();
    drop(cri);
    mock.st
        .lock()
        .unwrap()
        .containers
        .push(velarx_proto::workload::ContainerRecord {
            id: "c".into(),
            ..Default::default()
        });
    let channels = Channels {
        stdin: true,
        stdout: true,
        stderr: false,
        input_ends: false,
    };
    let spec = ExecSpec {
        cmd: vec!["cat".into()],
        stdin: true,
        stdout: true,
        ..Default::default()
    };
    let es = mock.exec_open("c", &spec).await.unwrap();
    let (server, client) = tokio::io::duplex(8192);
    let task = tokio::spawn(run_exec(mock.clone(), server, es, channels, true));
    drop(client);
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap();
    assert!(
        mock.calls().contains(&"exec kill exec1".to_string()),
        "{:?}",
        mock.calls()
    );

    let es = mock.exec_open("c", &spec).await.unwrap();
    let (server, mut client) = tokio::io::duplex(8192);
    let task = tokio::spawn(run_exec(mock.clone(), server, es, channels, true));
    let before = mock.calls().len();
    client.write_all(&masked(b"\xff\x00")).await.unwrap();
    let (rd, _wr) = tokio::io::split(client);
    tokio::time::timeout(Duration::from_secs(10), collect(rd))
        .await
        .unwrap();
    task.await.unwrap();
    assert!(
        !mock.calls()[before..]
            .iter()
            .any(|c| c.starts_with("exec kill")),
        "{:?}",
        mock.calls()
    );
}

#[tokio::test]
async fn frames_roundtrip() {
    let f = encode_frame(0x2, &[1, 2, 3]);
    assert_eq!(parse_frame(&f).unwrap().unwrap().0.payload, [1, 2, 3]);
}

/// The data frames the server sends on SPDY, by stream, until it closes.
async fn spdy_data(
    mut rd: impl AsyncReadExt + Unpin,
    until: impl Fn(&std::collections::HashMap<u32, Vec<u8>>, usize) -> bool,
) -> (std::collections::HashMap<u32, Vec<u8>>, usize) {
    let mut data: std::collections::HashMap<u32, Vec<u8>> = Default::default();
    let mut resets = 0;
    while !until(&data, resets) {
        let mut head = [0u8; 8];
        if rd.read_exact(&mut head).await.is_err() {
            break;
        }
        let len = u32::from_be_bytes([0, head[5], head[6], head[7]]) as usize;
        let mut payload = vec![0u8; len];
        rd.read_exact(&mut payload).await.unwrap();
        if head[0] & 0x80 == 0 {
            let id = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
            data.entry(id).or_default().extend_from_slice(&payload);
        } else if head[3] == 3 {
            resets += 1;
        }
    }
    (data, resets)
}

fn pf_headers(kind: &str, request: usize) -> Vec<(String, String)> {
    vec![
        ("streamtype".into(), kind.into()),
        ("port".into(), "80".into()),
        ("requestid".into(), request.to_string()),
    ]
}

#[tokio::test]
async fn port_forward_spdy_counts_the_connections_open_not_all_of_them() {
    use velarx_cri::spdy::{syn_stream, Encoder};
    use velarx_cri::stream::{run_ports_spdy, MAX_FORWARDS};
    let (mock, cri) = Mock::cri();
    drop(cri);
    let (server, client) = tokio::io::duplex(1 << 20);
    let task = tokio::spawn(run_ports_spdy(
        mock.clone(),
        server,
        "p".into(),
        vec![],
        Duration::ZERO,
    ));
    let (crd, mut cwr) = tokio::io::split(client);
    let mut enc = Encoder::new();
    // more requests than the cap, one after the other: each one ends (the mock
    // refuses to dial) and gives its place back
    let n = MAX_FORWARDS + 6;
    for r in 0..n {
        let id = 1 + 4 * r as u32;
        cwr.write_all(&syn_stream(&mut enc, id, &pf_headers("error", r), false))
            .await
            .unwrap();
        cwr.write_all(&syn_stream(&mut enc, id + 2, &pf_headers("data", r), false))
            .await
            .unwrap();
    }
    let (data, _) = spdy_data(crd, |d, _| {
        (0..n).all(|r| d.get(&(1 + 4 * r as u32)).is_some_and(|e| !e.is_empty()))
    })
    .await;
    for r in 0..n {
        let err = String::from_utf8_lossy(&data[&(1 + 4 * r as u32)]).into_owned();
        assert!(err.contains("connecting to port 80"), "request {r}: {err}");
    }
    cwr.shutdown().await.unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn port_forward_spdy_refuses_too_many_half_open_requests() {
    use velarx_cri::spdy::{syn_stream, Encoder};
    use velarx_cri::stream::{run_ports_spdy, MAX_HALF_OPEN};
    let (mock, cri) = Mock::cri();
    drop(cri);
    let (server, client) = tokio::io::duplex(1 << 20);
    let task = tokio::spawn(run_ports_spdy(
        mock.clone(),
        server,
        "p".into(),
        vec![],
        Duration::ZERO,
    ));
    let (crd, mut cwr) = tokio::io::split(client);
    let mut enc = Encoder::new();
    // only the error stream of each request: the ones past the cap are reset
    for r in 0..MAX_HALF_OPEN + 3 {
        cwr.write_all(&syn_stream(
            &mut enc,
            1 + 2 * r as u32,
            &pf_headers("error", r),
            false,
        ))
        .await
        .unwrap();
    }
    let (_, resets) = spdy_data(crd, |_, resets| resets == 3).await;
    assert_eq!(resets, 3);
    cwr.shutdown().await.unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn port_forward_spdy_refuses_stream_ids_that_are_not_the_clients() {
    use velarx_cri::spdy::{syn_stream, Encoder};
    use velarx_cri::stream::run_ports_spdy;
    let (mock, cri) = Mock::cri();
    drop(cri);
    let (server, client) = tokio::io::duplex(1 << 20);
    let task = tokio::spawn(run_ports_spdy(
        mock.clone(),
        server,
        "p".into(),
        vec![],
        Duration::ZERO,
    ));
    let (crd, mut cwr) = tokio::io::split(client);
    let mut enc = Encoder::new();
    // an even id, then 1 and 3 as they should be, then 3 again and 1 (not higher)
    for (id, request) in [(2, 0), (1, 1), (3, 1), (3, 2), (1, 2), (5, 3)] {
        let kind = if id % 2 == 1 && request == 1 && id == 3 {
            "data"
        } else {
            "error"
        };
        cwr.write_all(&syn_stream(&mut enc, id, &pf_headers(kind, request), false))
            .await
            .unwrap();
    }
    // the three that are not the client's are reset (status 1 each time), and
    // the pair of the request 1 is dialed and refused by the mock
    let (data, resets) = spdy_data(crd, |d, r| r >= 3 && d.contains_key(&1)).await;
    assert_eq!(resets, 3);
    assert!(String::from_utf8_lossy(&data[&1]).contains("connecting to port 80"));
    cwr.shutdown().await.unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn spdy_data_frames_are_at_most_a_mebibyte() {
    use velarx_cri::spdy::serve;
    let (server, mut client) = tokio::io::duplex(1 << 16);
    let (_handle, mut events) = serve(server);
    // a data frame that says 2 MiB: the session ends, nothing is allocated
    let mut f = vec![0, 0, 0, 1, 0];
    f.extend_from_slice(&(2u32 << 20).to_be_bytes()[1..]);
    client.write_all(&f).await.unwrap();
    let ev = tokio::time::timeout(std::time::Duration::from_secs(10), events.recv())
        .await
        .unwrap();
    assert!(matches!(ev, Some(velarx_cri::spdy::Event::Closed)));
}

#[tokio::test]
async fn a_connection_that_does_not_drain_does_not_hold_up_the_others() {
    use velarx_cri::spdy::{data_frame, syn_stream, Encoder};
    use velarx_cri::stream::run_ports_spdy;
    let (mock, cri) = Mock::cri();
    drop(cri);
    mock.st.lock().unwrap().dial_stuck = true;
    let (server, client) = tokio::io::duplex(1 << 22);
    let task = tokio::spawn(run_ports_spdy(
        mock.clone(),
        server,
        "p".into(),
        vec![],
        Duration::ZERO,
    ));
    let (crd, mut cwr) = tokio::io::split(client);
    let mut enc = Encoder::new();
    cwr.write_all(&syn_stream(&mut enc, 1, &pf_headers("error", 0), false))
        .await
        .unwrap();
    cwr.write_all(&syn_stream(&mut enc, 3, &pf_headers("data", 0), false))
        .await
        .unwrap();
    // the pod end reads nothing: its buffer is 64 bytes, then the queue of the
    // connection (256 messages) fills and the stream is reset
    let chunk = [7u8; 1024];
    for _ in 0..400 {
        cwr.write_all(&data_frame(3, false, &chunk)).await.unwrap();
    }
    let (_, resets) = spdy_data(crd, |_, r| r >= 1).await;
    assert!(resets >= 1);
    cwr.shutdown().await.unwrap();
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn an_idle_port_forward_session_ends() {
    use velarx_cri::stream::run_ports_spdy;
    let (mock, cri) = Mock::cri();
    drop(cri);
    let (server, _client) = tokio::io::duplex(1 << 16);
    let idle = Duration::from_secs(600);
    let task = tokio::spawn(run_ports_spdy(
        mock.clone(),
        server,
        "p".into(),
        vec![],
        idle,
    ));
    // (the session has started: its idle time counts from here)
    tokio::task::yield_now().await;
    tokio::time::advance(idle - Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(!task.is_finished());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the idle session ends")
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_port_forward_session_with_a_connection_open_is_not_idle() {
    use velarx_cri::spdy::{syn_stream, Encoder};
    use velarx_cri::stream::run_ports_spdy;
    let (mock, cri) = Mock::cri();
    drop(cri);
    mock.st.lock().unwrap().dial_stuck = true;
    let (server, client) = tokio::io::duplex(1 << 20);
    let idle = Duration::from_secs(600);
    let task = tokio::spawn(run_ports_spdy(
        mock.clone(),
        server,
        "p".into(),
        vec![],
        idle,
    ));
    let (_crd, mut cwr) = tokio::io::split(client);
    let mut enc = Encoder::new();
    cwr.write_all(&syn_stream(&mut enc, 1, &pf_headers("error", 0), false))
        .await
        .unwrap();
    cwr.write_all(&syn_stream(&mut enc, 3, &pf_headers("data", 0), false))
        .await
        .unwrap();
    // the connection is open for ten times the idle time
    for _ in 0..10 {
        tokio::time::advance(idle).await;
        tokio::task::yield_now().await;
    }
    assert!(!task.is_finished());
    // the pod end closes: the idle time counts from there
    mock.st.lock().unwrap().dial_peers.clear();
    tokio::time::timeout(idle * 2, task)
        .await
        .expect("the session ends once idle")
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_port_forward_session_without_an_idle_timeout_does_not_end() {
    use velarx_cri::stream::run_ports_spdy;
    // zero, and a timeout too far to be an instant
    for idle in [Duration::ZERO, Duration::MAX] {
        let (mock, cri) = Mock::cri();
        drop(cri);
        let (server, client) = tokio::io::duplex(1 << 16);
        let task = tokio::spawn(run_ports_spdy(
            mock.clone(),
            server,
            "p".into(),
            vec![],
            idle,
        ));
        let mut task = std::pin::pin!(task);
        assert!(
            tokio::time::timeout(Duration::from_secs(1 << 30), &mut task)
                .await
                .is_err(),
            "{idle:?}"
        );
        drop(client);
        task.await.unwrap();
    }
}

#[tokio::test]
async fn the_streaming_server_holds_a_limited_number_of_connections() {
    use velarx_cri::stream::{Sessions, StreamServer};
    let (mock, cri) = Mock::cri();
    drop(cri);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let slots = Arc::new(tokio::sync::Semaphore::new(2));
    let server = Arc::new(StreamServer {
        engine: mock,
        sessions: Arc::new(Sessions::default()),
        idle_timeout: Duration::ZERO,
    });
    let task = tokio::spawn(server.serve_limited(listener, slots.clone()));
    // a request for a session that does not exist is answered 404
    let ask = |mut c: tokio::net::TcpStream| async move {
        c.write_all(b"GET /exec/none HTTP/1.1\r\nhost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 12];
        c.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"HTTP/1.1 404", "{}", String::from_utf8_lossy(&buf));
        c
    };
    let c1 = ask(tokio::net::TcpStream::connect(addr).await.unwrap()).await;
    let c2 = ask(tokio::net::TcpStream::connect(addr).await.unwrap()).await;
    // both places are taken while the two connections stay open
    assert_eq!(slots.available_permits(), 0);
    let third = tokio::spawn(ask(tokio::net::TcpStream::connect(addr).await.unwrap()));
    // the third is served once a place is given back
    drop(c1);
    let c3 = third.await.unwrap();
    drop((c2, c3));
    task.abort();
}

/// An attach without a terminal and without `stdin_once` ends with the
/// input of its client: what the client sent is passed on, the attach
/// stream of the engine gets the end of the input (the engine keeps the
/// input of the container open), and the session ends although the
/// container goes on.
#[tokio::test]
async fn an_attach_ends_with_the_input_of_its_client() {
    let (mock, cri) = Mock::cri();
    drop(cri);
    let (ours, mut container) = tokio::io::duplex(4096);
    let es = ExecStream {
        id: String::new(),
        framed: false,
        io: Box::new(ours),
    };
    let (server, mut client) = tokio::io::duplex(8192);
    let task = tokio::spawn(run_exec(
        mock,
        server,
        es,
        Channels {
            stdin: true,
            stdout: true,
            stderr: false,
            input_ends: true,
        },
        false,
    ));
    client.write_all(&masked(b"\x00hello")).await.unwrap();
    client.write_all(&masked(b"\xff\x00")).await.unwrap();
    let mut input = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), container.read_to_end(&mut input))
        .await
        .expect("the attach stream gets the end of the input")
        .unwrap();
    assert_eq!(input, b"hello");
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("the attach ends with the input of its client")
        .unwrap();
}
