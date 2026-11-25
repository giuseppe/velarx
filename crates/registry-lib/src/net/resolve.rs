// SPDX-License-Identifier: Apache-2.0
//! The channel on which names are resolved for a process that cannot do it
//! itself: a pull worker asks the fetcher's front, the front asks the runner
//! that resolves.  The same protocol on both links, one question at a time
//! per frame and several in flight: a name in, the addresses (no port) out.
//!
//! A frame is a 16-bit length and a JSON.  The side that answers treats what
//! it reads as hostile: the length of a frame and the name are checked before
//! anything is done, a bounded number of questions are being resolved (the
//! next one is read when a place is free), and a frame that breaks the rules
//! ends the channel.  What an answer may carry is bounded as well, for the
//! side that asks.

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::unix::OwnedWriteHalf;
use tokio::net::UnixStream;
use tokio::sync::{oneshot, Semaphore};
use velarx_registry::netpolicy::Resolver;

/// Longest name of DNS.
const MAX_NAME: usize = 253;
/// Longest label of a name.
const MAX_LABEL: usize = 63;
/// Longest frame of a question: its JSON, a name and a number.
const MAX_QUESTION: usize = 512;
/// Longest frame of an answer.
const MAX_ANSWER: usize = 4096;
/// The most addresses an answer carries (the rest of what the system gave
/// is not told).
pub const MAX_ADDRS: usize = 32;
/// The longest reason an answer gives.
const MAX_REASON: usize = 200;
/// The questions of a worker in flight at once.
pub const MAX_IN_FLIGHT: usize = 16;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Question {
    id: u32,
    name: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Answer {
    id: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    addrs: Vec<IpAddr>,
    /// Why there are no addresses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn invalid(why: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why.into())
}

/// Whether `name` is a name to resolve: the letters, digits, hyphens and
/// underscores of the labels of a host name (an internationalized one comes
/// in its `xn--` form), at most 253 bytes, no empty label but the last (the
/// root).
pub fn valid_name(name: &str) -> bool {
    let bare = name.strip_suffix('.').unwrap_or(name);
    !bare.is_empty()
        && bare.len() <= MAX_NAME
        && bare.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_LABEL
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8]) -> io::Result<()> {
    let len = u16::try_from(body.len()).map_err(|_| invalid("frame too long"))?;
    let mut frame = Vec::with_capacity(body.len() + 2);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(body);
    w.write_all(&frame).await
}

/// The next frame, of at most `max` bytes; none at the end of the channel.
async fn read_frame<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 2];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = usize::from(u16::from_be_bytes(len));
    if len > max {
        return Err(invalid(format!("a frame of {len} bytes, at most {max}")));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(Some(body))
}

/// Answer the questions of `stream` with `resolver`, at most `in_flight` at
/// once, until the other side ends the channel (`Ok`), or breaks the rules
/// (an error).  What is still being resolved then is given up.
pub async fn serve(
    stream: UnixStream,
    resolver: Arc<dyn Resolver>,
    in_flight: usize,
) -> io::Result<()> {
    let (mut reader, writer) = stream.into_split();
    let writer = Arc::new(tokio::sync::Mutex::new(writer));
    let slots = Arc::new(Semaphore::new(in_flight));
    let mut running = tokio::task::JoinSet::new();
    loop {
        // (a question that is given up by its asker is still being resolved:
        // the next one waits for a free place, not for the asker)
        let slot = slots
            .clone()
            .acquire_owned()
            .await
            .map_err(io::Error::other)?;
        let Some(frame) = read_frame(&mut reader, MAX_QUESTION).await? else {
            return Ok(());
        };
        let question: Question =
            serde_json::from_slice(&frame).map_err(|e| invalid(e.to_string()))?;
        let (resolver, writer) = (resolver.clone(), writer.clone());
        running.spawn(async move {
            let answer = answer(question, &*resolver).await;
            let body = serde_json::to_vec(&answer).unwrap_or_default();
            let sent = write_frame(&mut *writer.lock().await, &body).await;
            drop(slot);
            sent
        });
        // (the answers that are sent are not waited for here; one that
        // could not be sent ends the channel)
        while let Some(done) = running.try_join_next() {
            done.map_err(io::Error::other)??;
        }
    }
}

async fn answer(question: Question, resolver: &dyn Resolver) -> Answer {
    let Question { id, name } = question;
    let found = if valid_name(&name) {
        resolver.lookup(&name, 0).await
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a name to resolve",
        ))
    };
    match found {
        Ok(found) => Answer {
            id,
            addrs: found.iter().map(SocketAddr::ip).take(MAX_ADDRS).collect(),
            error: None,
        },
        Err(e) => Answer {
            id,
            addrs: Vec::new(),
            error: Some(e.to_string().chars().take(MAX_REASON).collect()),
        },
    }
}

/// The questions waiting for their answer; none once the channel is gone.
type Waiting = Arc<Mutex<Option<HashMap<u32, oneshot::Sender<Answer>>>>>;

/// The asking side of a channel.  Cancelling a question leaves nothing
/// behind: its entry goes with it and its answer, if it comes, is dropped.
/// The other side bounds the questions it resolves at once: the next ones
/// wait in the channel.
pub struct Client {
    out: tokio::sync::Mutex<OwnedWriteHalf>,
    waiting: Waiting,
    next: AtomicU32,
    reader: tokio::task::JoinHandle<()>,
    /// Closed when the reader has ended
    ended: tokio::sync::watch::Receiver<()>,
}

impl Drop for Client {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// Takes the question out of the table when its asker is done or gone.
struct Entry<'a>(&'a Waiting, u32);

impl Drop for Entry<'_> {
    fn drop(&mut self) {
        if let Some(waiting) = self.0.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            waiting.remove(&self.1);
        }
    }
}

impl Client {
    /// Ask on `stream`.  Call it within a runtime: the answers are read by a
    /// task of it.
    pub fn new(stream: UnixStream) -> Self {
        let (mut reader, writer) = stream.into_split();
        let waiting = Waiting::new(Mutex::new(Some(HashMap::new())));
        let answers = waiting.clone();
        let (ended_tx, ended) = tokio::sync::watch::channel(());
        let reader = tokio::spawn(async move {
            let _ended = ended_tx;
            // (a channel that ends or breaks the rules: the questions in
            // wait are dropped, and their askers and those who ask later
            // told it is gone)
            while let Ok(Some(frame)) = read_frame(&mut reader, MAX_ANSWER).await {
                let Ok(answer) = serde_json::from_slice::<Answer>(&frame) else {
                    break;
                };
                let asker = answers
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .as_mut()
                    .and_then(|waiting| waiting.remove(&answer.id));
                if let Some(asker) = asker {
                    let _ = asker.send(answer);
                }
            }
            *answers.lock().unwrap_or_else(|e| e.into_inner()) = None;
        });
        Self {
            out: tokio::sync::Mutex::new(writer),
            waiting,
            next: AtomicU32::new(0),
            reader,
            ended,
        }
    }

    /// Returns when the channel is gone: the other side ended or broke the
    /// rules, and every question, now or later, is told so.
    pub async fn gone(&self) {
        // (an error: the sender went with the task)
        let _ = self.ended.clone().changed().await;
    }

    /// The addresses of `name`.
    pub async fn addresses(&self, name: &str) -> io::Result<Vec<IpAddr>> {
        if !valid_name(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a name to resolve",
            ));
        }
        let gone = || io::Error::new(io::ErrorKind::BrokenPipe, "the resolver is gone");
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tell, told) = oneshot::channel();
        self.waiting
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_mut()
            .ok_or_else(gone)?
            .insert(id, tell);
        let _entry = Entry(&self.waiting, id);
        let body = serde_json::to_vec(&Question {
            id,
            name: name.to_string(),
        })
        .map_err(io::Error::other)?;
        write_frame(&mut *self.out.lock().await, &body).await?;
        let answer = told.await.map_err(|_| gone())?;
        match answer.error {
            Some(why) => Err(io::Error::other(why)),
            None if answer.addrs.len() > MAX_ADDRS => Err(invalid("too many addresses")),
            None => Ok(answer.addrs),
        }
    }
}

impl Resolver for Client {
    fn lookup<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFuture<'a, io::Result<Vec<SocketAddr>>> {
        Box::pin(async move {
            let addrs = self.addresses(host).await?;
            Ok(addrs
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A resolver that knows a few names.
    struct Known;

    impl Resolver for Known {
        fn lookup<'a>(
            &'a self,
            host: &'a str,
            port: u16,
        ) -> BoxFuture<'a, io::Result<Vec<SocketAddr>>> {
            Box::pin(async move {
                match host {
                    "registry.test" => Ok(vec![SocketAddr::new([10, 1, 2, 3].into(), port)]),
                    "many.test" => Ok((0..100u8)
                        .map(|n| SocketAddr::new([10, 0, 0, n].into(), port))
                        .collect()),
                    "slow.test" => {
                        std::future::pending::<()>().await;
                        unreachable!()
                    }
                    _ => Err(io::Error::other("no such host")),
                }
            })
        }
    }

    fn pair() -> (Client, tokio::task::JoinHandle<io::Result<()>>) {
        let (a, b) = UnixStream::pair().unwrap();
        (
            Client::new(a),
            tokio::spawn(serve(b, Arc::new(Known), MAX_IN_FLIGHT)),
        )
    }

    #[test]
    fn the_names_that_are_resolved_are_host_names() {
        for ok in [
            "quay.io",
            "a-b_c.d9.example.",
            "xn--bcher-kva.example",
            "localhost",
        ] {
            assert!(valid_name(ok), "{ok}");
        }
        let long_label = "a".repeat(64);
        let long_name = format!("{}.com", ["abcdefghi"; 30].join("."));
        for bad in [
            "",
            ".",
            "a..b",
            ".a",
            "a b",
            "a/b",
            "a:80",
            "[::1]",
            "a\0b",
            "é.example",
            "a\n",
            &long_label,
            &long_name,
        ] {
            assert!(!valid_name(bad), "{bad:?}");
        }
        assert!(valid_name(&"a".repeat(63)));
    }

    #[tokio::test]
    async fn a_name_gets_its_addresses_and_a_failure_its_reason() {
        let (client, _server) = pair();
        let found = client.lookup("registry.test", 443).await.unwrap();
        assert_eq!(found, ["10.1.2.3:443".parse().unwrap()]);
        let e = client.lookup("nowhere.test", 443).await.unwrap_err();
        assert!(e.to_string().contains("no such host"), "{e}");
        // (the channel is as good after a failure)
        assert!(client.lookup("registry.test", 80).await.is_ok());
    }

    #[tokio::test]
    async fn an_answer_carries_no_more_than_the_limit_of_addresses() {
        let (client, _server) = pair();
        let found = client.addresses("many.test").await.unwrap();
        assert_eq!(found.len(), MAX_ADDRS);
    }

    #[tokio::test]
    async fn a_name_that_is_not_one_is_not_asked() {
        let (client, _server) = pair();
        assert!(client.addresses("a b").await.is_err());
        // (the one who answers refuses it too: a worker is not trusted)
        let (a, b) = UnixStream::pair().unwrap();
        let server = tokio::spawn(serve(b, Arc::new(Known), MAX_IN_FLIGHT));
        let (mut r, mut w) = a.into_split();
        let q = serde_json::to_vec(&Question {
            id: 7,
            name: "../x".into(),
        })
        .unwrap();
        write_frame(&mut w, &q).await.unwrap();
        let frame = read_frame(&mut r, MAX_ANSWER).await.unwrap().unwrap();
        let answer: Answer = serde_json::from_slice(&frame).unwrap();
        assert_eq!(answer.id, 7);
        assert!(answer.addrs.is_empty() && answer.error.is_some());
        drop((r, w));
        server.await.unwrap().unwrap();
    }

    /// A question that is given up leaves nothing: the next ones are
    /// answered, and the table is empty.
    #[tokio::test]
    async fn a_question_that_is_given_up_leaves_nothing_behind() {
        let (client, _server) = pair();
        let slow = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            client.lookup("slow.test", 1),
        )
        .await;
        assert!(slow.is_err());
        assert!(client.waiting.lock().unwrap().as_ref().unwrap().is_empty());
        assert!(client.lookup("registry.test", 1).await.is_ok());
    }

    /// A resolver that counts the questions it is asked at once.
    struct Counting(
        std::sync::atomic::AtomicUsize,
        std::sync::atomic::AtomicUsize,
    );

    impl Resolver for Counting {
        fn lookup<'a>(&'a self, _: &'a str, _: u16) -> BoxFuture<'a, io::Result<Vec<SocketAddr>>> {
            Box::pin(async move {
                let now = self.0.fetch_add(1, Ordering::SeqCst) + 1;
                self.1.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                self.0.fetch_sub(1, Ordering::SeqCst);
                Ok(Vec::new())
            })
        }
    }

    /// No more questions than the limit are resolved at once, and all are
    /// answered.
    #[tokio::test]
    async fn no_more_questions_than_the_limit_are_resolved_at_once() {
        let counting = Arc::new(Counting(Default::default(), Default::default()));
        let (a, b) = UnixStream::pair().unwrap();
        let _server = tokio::spawn(serve(b, counting.clone(), MAX_IN_FLIGHT));
        let (mut r, mut w) = a.into_split();
        let writing = tokio::spawn(async move {
            for id in 0..(MAX_IN_FLIGHT as u32 * 3) {
                let q = Question {
                    id,
                    name: "a.test".into(),
                };
                write_frame(&mut w, &serde_json::to_vec(&q).unwrap())
                    .await
                    .unwrap();
            }
            w
        });
        for _ in 0..MAX_IN_FLIGHT * 3 {
            read_frame(&mut r, MAX_ANSWER).await.unwrap().unwrap();
        }
        let _w = writing.await.unwrap();
        assert_eq!(counting.1.load(Ordering::SeqCst), MAX_IN_FLIGHT);
    }

    #[tokio::test]
    async fn a_frame_over_the_limit_or_garbage_ends_the_channel() {
        for body in [vec![b'x'; MAX_QUESTION + 1], b"not json".to_vec()] {
            let (a, b) = UnixStream::pair().unwrap();
            let server = tokio::spawn(serve(b, Arc::new(Known), MAX_IN_FLIGHT));
            let (_r, mut w) = a.into_split();
            write_frame(&mut w, &body).await.unwrap();
            assert!(server.await.unwrap().is_err());
        }
    }

    /// Whoever answers cannot make the asker take more than the limits.
    #[tokio::test]
    async fn an_answer_over_the_limit_is_refused_by_the_asker() {
        let (a, b) = UnixStream::pair().unwrap();
        let client = Client::new(a);
        let (mut r, mut w) = b.into_split();
        let asked = tokio::spawn(async move { client.addresses("registry.test").await });
        let frame = read_frame(&mut r, MAX_QUESTION).await.unwrap().unwrap();
        let q: Question = serde_json::from_slice(&frame).unwrap();
        let addrs: Vec<IpAddr> = (0..=MAX_ADDRS as u8)
            .map(|n| [10, 0, 0, n].into())
            .collect();
        let a = serde_json::to_vec(&Answer {
            id: q.id,
            addrs,
            error: None,
        })
        .unwrap();
        write_frame(&mut w, &a).await.unwrap();
        assert!(asked.await.unwrap().is_err());
        // (and a frame longer than an answer may be ends the channel: the
        // next question is not left waiting for an answer that is not read)
        let (a, b) = UnixStream::pair().unwrap();
        let client = Arc::new(Client::new(a));
        let (_r, mut w) = b.into_split();
        let asked = tokio::spawn({
            let client = client.clone();
            async move { client.addresses("registry.test").await }
        });
        write_frame(&mut w, &vec![b' '; MAX_ANSWER + 1])
            .await
            .unwrap();
        assert!(asked.await.unwrap().is_err());
        let e = client.addresses("registry.test").await.unwrap_err();
        assert!(e.to_string().contains("gone"), "{e}");
    }

    /// The end of the channel is told to those who wait.
    #[tokio::test]
    async fn a_channel_that_ends_tells_those_who_wait() {
        let (a, b) = UnixStream::pair().unwrap();
        let client = Arc::new(Client::new(a));
        let asked = tokio::spawn({
            let client = client.clone();
            async move { client.addresses("registry.test").await }
        });
        let mut b = b;
        let _ = read_frame(&mut b, MAX_QUESTION).await.unwrap();
        drop(b);
        let e = asked.await.unwrap().unwrap_err();
        assert!(e.to_string().contains("gone"), "{e}");
    }
}
