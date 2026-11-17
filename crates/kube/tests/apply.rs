// SPDX-License-Identifier: Apache-2.0
//! The requests of `apply`, against a server on the loopback.

use std::io::{Read, Write};
use velarx_kube::apply::{send, Document, Request, Secrets};

/// An HTTP server on the loopback that answers each request with the next
/// of `answers` (status, body), and the requests it got.
fn server(answers: Vec<(u16, Vec<u8>)>) -> (u16, std::thread::JoinHandle<Vec<String>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let mut got = Vec::new();
        for (status, body) in answers {
            let (mut s, _) = listener.accept().unwrap();
            let mut head = vec![0u8; 64 * 1024];
            let n = s.read(&mut head).unwrap();
            got.push(String::from_utf8_lossy(&head[..n]).into_owned());
            let reply = format!(
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(reply.as_bytes());
            let _ = s.write_all(&body);
        }
        got
    });
    (port, handle)
}

fn request(port: u16, kinds: &[&str]) -> Request {
    Request {
        documents: kinds
            .iter()
            .map(|k| Document {
                url: format!("http://127.0.0.1:{port}/api/v1/namespaces/default/{k}"),
                body: format!("kind: {k}\n"),
            })
            .collect(),
        port,
        insecure: false,
        secrets: Secrets {
            token: Some("t0k".into()),
            ..Default::default()
        },
    }
}

#[tokio::test]
async fn the_documents_are_posted_with_the_token() {
    let (port, server) = server(vec![(201, Vec::new()), (201, Vec::new())]);
    send(&request(port, &["services", "pods"])).await.unwrap();
    let got = server.join().unwrap();
    assert!(got[0].starts_with("POST /api/v1/namespaces/default/services "));
    assert!(got[1].starts_with("POST /api/v1/namespaces/default/pods "));
    assert!(got.iter().all(|r| r.contains("authorization: Bearer t0k")));
    assert!(got[1].contains("kind: pods"));
}

#[tokio::test]
async fn a_refusal_keeps_the_status_and_a_bounded_body() {
    let (port, server) = server(vec![
        (403, b"no such namespace".to_vec()),
        (403, vec![b'x'; 256 * 1024]),
    ]);
    let small = send(&request(port, &["pods"])).await.unwrap_err();
    assert!(
        small.ends_with("pods: status 403: no such namespace"),
        "{small}"
    );
    let big = send(&request(port, &["pods"])).await.unwrap_err();
    assert!(big.len() < 200 + 64 * 1024, "{}", big.len());
    server.join().unwrap();
}
