// SPDX-License-Identifier: Apache-2.0
//! SPDY/3.1, the server side, as the Kubernetes clients speak it for exec,
//! attach and port-forward (`k8s.io/apimachinery/pkg/util/httpstream/spdy`):
//! streams the client opens with `SYN_STREAM`, `DATA` frames with the `FIN`
//! flag, `RST_STREAM`, `PING`.  Flow control is not used by those clients
//! (their library has none): `WINDOW_UPDATE` and `SETTINGS` are read and
//! ignored.  The headers of every `SYN_STREAM` and `SYN_REPLY` are one zlib
//! stream per direction, with the dictionary of SPDY/3.

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

/// The dictionary of the header compression (SPDY/3 section 2.6.10.1).
pub const DICTIONARY: &[u8] = include_bytes!("spdy_dictionary.bin");

const VERSION: u16 = 3;
const SYN_STREAM: u16 = 1;
const SYN_REPLY: u16 = 2;
const RST_STREAM: u16 = 3;
const PING: u16 = 6;
const GOAWAY: u16 = 7;
const FLAG_FIN: u8 = 1;
/// The status of a `RST_STREAM` for a stream that breaks the protocol.
const PROTOCOL_ERROR: u32 = 1;
/// The largest control frame accepted.
const MAX_CONTROL: usize = 1 << 20;
/// The most a data frame may carry (the clients send 32 KiB at most; the
/// format allows 16 MiB, which would be allocated before it is read).
const MAX_DATA: usize = 1 << 20;
/// What the frames this side sends carry at most.
pub const CHUNK: usize = 16 * 1024;

pub type Headers = Vec<(String, String)>;

/// What the client did.
#[derive(Debug, PartialEq)]
pub enum Event {
    /// A stream is opened (`fin`: the client will send nothing on it)
    Stream {
        id: u32,
        headers: Headers,
        fin: bool,
    },
    Data {
        id: u32,
        data: Vec<u8>,
        fin: bool,
    },
    Reset {
        id: u32,
    },
    /// The connection ended or went wrong
    Closed,
}

/// The headers' compressor of the frames sent.
pub struct Encoder(Compress);

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder {
    pub fn new() -> Self {
        let mut z = Compress::new(Compression::default(), true);
        z.set_dictionary(DICTIONARY).expect("the dictionary");
        Self(z)
    }

    /// The block of `headers`, flushed so that the peer can read it at once.
    pub fn block(&mut self, headers: &[(String, String)]) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend_from_slice(&(headers.len() as u32).to_be_bytes());
        for (k, v) in headers {
            for s in [k.to_ascii_lowercase(), v.clone()] {
                raw.extend_from_slice(&(s.len() as u32).to_be_bytes());
                raw.extend_from_slice(s.as_bytes());
            }
        }
        let mut out = Vec::with_capacity(raw.len() + 64);
        let mut fed = 0;
        loop {
            let before = self.0.total_in();
            let room = out.capacity() - out.len();
            if room < 64 {
                out.reserve(256);
            }
            self.0
                .compress_vec(&raw[fed..], &mut out, FlushCompress::Sync)
                .expect("deflate");
            fed += (self.0.total_in() - before) as usize;
            // done when everything is in and the output was not cut by its room
            if fed >= raw.len() && out.len() < out.capacity() {
                return out;
            }
            out.reserve(256);
        }
    }
}

/// The headers' decompressor of the frames received.
struct Decoder(Decompress);

impl Decoder {
    fn new() -> Self {
        Self(Decompress::new(true))
    }

    fn block(&mut self, data: &[u8]) -> io::Result<Headers> {
        let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_string());
        let mut out: Vec<u8> = Vec::with_capacity(1024);
        let mut fed = 0;
        loop {
            let before = self.0.total_in();
            let produced = out.len();
            if out.capacity() - out.len() < 256 {
                out.reserve(1024);
            }
            match self
                .0
                .decompress_vec(&data[fed..], &mut out, FlushDecompress::Sync)
            {
                Ok(Status::Ok | Status::BufError) => {}
                // the client's stream ended: the next headers cannot be read
                Ok(Status::StreamEnd) => return Err(bad("the header stream ended")),
                Err(e) if e.needs_dictionary().is_some() => {
                    self.0
                        .set_dictionary(DICTIONARY)
                        .map_err(|_| bad("the header dictionary"))?;
                }
                Err(_) => return Err(bad("a header block that does not inflate")),
            }
            fed += (self.0.total_in() - before) as usize;
            // input left that inflate takes nothing of, with room to write
            if fed < data.len()
                && self.0.total_in() == before
                && out.len() == produced
                && out.len() < out.capacity()
            {
                return Err(bad("a header block that does not inflate"));
            }
            if fed >= data.len() && out.len() < out.capacity() {
                break;
            }
            if out.len() > MAX_CONTROL {
                return Err(bad("headers too big"));
            }
        }
        parse_pairs(&out).ok_or_else(|| bad("a malformed header block"))
    }
}

fn parse_pairs(b: &[u8]) -> Option<Headers> {
    let n = u32::from_be_bytes(b.get(..4)?.try_into().ok()?) as usize;
    if n > 1024 {
        return None;
    }
    let mut at = 4;
    let read = |at: &mut usize| -> Option<String> {
        let len = u32::from_be_bytes(b.get(*at..*at + 4)?.try_into().ok()?) as usize;
        let s = b.get(*at + 4..*at + 4 + len)?;
        *at += 4 + len;
        Some(String::from_utf8_lossy(s).into_owned())
    };
    let mut out = Vec::new();
    for _ in 0..n {
        let k = read(&mut at)?;
        let v = read(&mut at)?;
        out.push((k.to_ascii_lowercase(), v));
    }
    Some(out)
}

/// A control frame of SPDY/3.
pub fn control(kind: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(8 + payload.len());
    f.extend_from_slice(&(0x8000 | VERSION).to_be_bytes());
    f.extend_from_slice(&kind.to_be_bytes());
    f.push(flags);
    f.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    f.extend_from_slice(payload);
    f
}

/// A data frame.
pub fn data_frame(id: u32, fin: bool, data: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(8 + data.len());
    f.extend_from_slice(&(id & 0x7fff_ffff).to_be_bytes());
    f.push(if fin { FLAG_FIN } else { 0 });
    f.extend_from_slice(&(data.len() as u32).to_be_bytes()[1..]);
    f.extend_from_slice(data);
    f
}

/// A client's `SYN_STREAM` as the Go library writes it (for tests).
pub fn syn_stream(enc: &mut Encoder, id: u32, headers: &[(String, String)], fin: bool) -> Vec<u8> {
    let mut p = id.to_be_bytes().to_vec();
    p.extend_from_slice(&0u32.to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(&enc.block(headers));
    control(SYN_STREAM, if fin { FLAG_FIN } else { 0 }, &p)
}

/// What the writer task is asked.
enum Out {
    Reply(u32, Headers),
    Data(u32, Vec<u8>, bool),
    Reset(u32, u32),
    Frame(Vec<u8>),
    Finish,
}

/// The side of the connection that sends: cloneable.
#[derive(Clone)]
pub struct Handle {
    tx: mpsc::Sender<Out>,
}

impl Handle {
    /// Accept the stream `id` with `headers`.
    pub async fn reply(&self, id: u32, headers: Headers) {
        let _ = self.tx.send(Out::Reply(id, headers)).await;
    }

    /// Send `data` on the stream (in frames of at most [`CHUNK`]), `fin`
    /// after the last.
    pub async fn data(&self, id: u32, data: &[u8], fin: bool) {
        let mut chunks = data.chunks(CHUNK).peekable();
        if chunks.peek().is_none() && fin {
            let _ = self.tx.send(Out::Data(id, Vec::new(), true)).await;
        }
        while let Some(c) = chunks.next() {
            let last = chunks.peek().is_none();
            if self
                .tx
                .send(Out::Data(id, c.to_vec(), fin && last))
                .await
                .is_err()
            {
                return;
            }
        }
    }

    /// Everything queued is sent, then the connection is shut down for writing.
    pub async fn finish(&self) {
        let _ = self.tx.send(Out::Finish).await;
    }

    /// Refuse or abort the stream (status 5: cancel).
    pub async fn reset(&self, id: u32) {
        let _ = self.tx.send(Out::Reset(id, 5)).await;
    }
}

async fn writer<W: AsyncWrite + Unpin>(mut wr: W, mut rx: mpsc::Receiver<Out>) {
    let mut enc = Encoder::new();
    while let Some(o) = rx.recv().await {
        let frame = match o {
            Out::Reply(id, headers) => {
                let mut p = (id & 0x7fff_ffff).to_be_bytes().to_vec();
                p.extend_from_slice(&enc.block(&headers));
                control(SYN_REPLY, 0, &p)
            }
            Out::Data(id, data, fin) => data_frame(id, fin, &data),
            Out::Reset(id, status) => {
                let mut p = (id & 0x7fff_ffff).to_be_bytes().to_vec();
                p.extend_from_slice(&status.to_be_bytes());
                control(RST_STREAM, 0, &p)
            }
            Out::Frame(f) => f,
            Out::Finish => break,
        };
        if wr.write_all(&frame).await.is_err() {
            return;
        }
    }
    let _ = wr.flush().await;
    let _ = wr.shutdown().await;
}

async fn reader<R: AsyncRead + Unpin>(mut rd: R, events: mpsc::Sender<Event>, h: Handle) {
    let mut dec = Decoder::new();
    // the streams of a client have odd ids, each higher than the one before
    let mut last_id = 0u32;
    loop {
        let mut head = [0u8; 8];
        if rd.read_exact(&mut head).await.is_err() {
            let _ = events.send(Event::Closed).await;
            return;
        }
        let flags = head[4];
        let len = u32::from_be_bytes([0, head[5], head[6], head[7]]) as usize;
        let is_control = head[0] & 0x80 != 0;
        if len > if is_control { MAX_CONTROL } else { MAX_DATA } {
            let _ = events.send(Event::Closed).await;
            return;
        }
        let mut payload = vec![0u8; len];
        if rd.read_exact(&mut payload).await.is_err() {
            let _ = events.send(Event::Closed).await;
            return;
        }
        let event = if !is_control {
            let id = u32::from_be_bytes([head[0] & 0x7f, head[1], head[2], head[3]]);
            Some(Event::Data {
                id,
                data: payload,
                fin: flags & FLAG_FIN != 0,
            })
        } else {
            let version = u16::from_be_bytes([head[0] & 0x7f, head[1]]);
            let kind = u16::from_be_bytes([head[2], head[3]]);
            if version != VERSION {
                let _ = events.send(Event::Closed).await;
                return;
            }
            match kind {
                SYN_STREAM if payload.len() >= 10 => {
                    let id = u32::from_be_bytes(payload[..4].try_into().unwrap()) & 0x7fff_ffff;
                    match dec.block(&payload[10..]) {
                        // (the block is decoded first: the zlib stream of the
                        // headers goes on whatever the id)
                        Ok(_) if id % 2 == 0 || id <= last_id => {
                            let _ = h.tx.send(Out::Reset(id, PROTOCOL_ERROR)).await;
                            None
                        }
                        Ok(headers) => {
                            last_id = id;
                            Some(Event::Stream {
                                id,
                                headers,
                                fin: flags & FLAG_FIN != 0,
                            })
                        }
                        Err(_) => {
                            let _ = events.send(Event::Closed).await;
                            return;
                        }
                    }
                }
                RST_STREAM if payload.len() >= 4 => Some(Event::Reset {
                    id: u32::from_be_bytes(payload[..4].try_into().unwrap()) & 0x7fff_ffff,
                }),
                PING => {
                    // answered as it came
                    let _ = h.tx.send(Out::Frame(control(PING, 0, &payload))).await;
                    None
                }
                GOAWAY => {
                    let _ = events.send(Event::Closed).await;
                    return;
                }
                // SETTINGS, HEADERS, WINDOW_UPDATE: nothing in these clients
                // needs an answer
                _ => None,
            }
        };
        if let Some(e) = event {
            if events.send(e).await.is_err() {
                return;
            }
        }
    }
}

/// Serve SPDY on `io`: the events of the client, and the handle to answer.
/// The connection ends when the events are dropped and the handles are.
pub fn serve<T>(io: T) -> (Handle, mpsc::Receiver<Event>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (rd, wr) = tokio::io::split(io);
    let (tx, rx) = mpsc::channel(64);
    let (etx, erx) = mpsc::channel(64);
    let handle = Handle { tx };
    tokio::spawn(writer(wr, rx));
    tokio::spawn(reader(rd, etx, handle.clone()));
    (handle, erx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dictionary_is_the_one_of_spdy3() {
        assert_eq!(DICTIONARY.len(), 1423);
        let mut a: u32 = 1;
        let mut b: u32 = 0;
        for byte in DICTIONARY {
            a = (a + *byte as u32) % 65521;
            b = (b + a) % 65521;
        }
        // the dictionary id of the zlib streams of SPDY/3
        assert_eq!((b << 16) | a, 0xe3c6_a7c2);
    }

    #[test]
    fn headers_go_through_one_zlib_stream_in_each_direction() {
        let mut enc = Encoder::new();
        let mut dec = Decoder::new();
        let h = vec![
            ("streamtype".to_string(), "data".to_string()),
            ("port".to_string(), "8080".to_string()),
            ("requestid".to_string(), "0".to_string()),
        ];
        for i in 0..5 {
            let mut h = h.clone();
            h[2].1 = i.to_string();
            let block = enc.block(&h);
            assert_eq!(dec.block(&block).unwrap(), h, "block {i}");
        }
        assert!(dec.block(b"garbage").is_err());
    }

    #[tokio::test]
    async fn a_session_opens_streams_replies_and_moves_data() {
        let (client, server) = tokio::io::duplex(1 << 16);
        let (handle, mut events) = serve(server);
        let (mut crd, mut cwr) = tokio::io::split(client);
        let mut enc = Encoder::new();
        let h = vec![("streamtype".to_string(), "error".to_string())];
        cwr.write_all(&syn_stream(&mut enc, 1, &h, false))
            .await
            .unwrap();
        cwr.write_all(&data_frame(1, true, b"hello")).await.unwrap();
        cwr.write_all(&control(PING, 0, &[0, 0, 0, 1]))
            .await
            .unwrap();
        assert_eq!(
            events.recv().await.unwrap(),
            Event::Stream {
                id: 1,
                headers: h.clone(),
                fin: false
            }
        );
        assert_eq!(
            events.recv().await.unwrap(),
            Event::Data {
                id: 1,
                data: b"hello".to_vec(),
                fin: true
            }
        );
        // the ping is answered and the reply to the stream is a SYN_REPLY
        handle.reply(1, vec![]).await;
        handle.data(1, b"status", true).await;
        let mut seen = Vec::new();
        let mut dec = Decoder::new();
        while seen.len() < 3 {
            let mut head = [0u8; 8];
            crd.read_exact(&mut head).await.unwrap();
            let len = u32::from_be_bytes([0, head[5], head[6], head[7]]) as usize;
            let mut payload = vec![0u8; len];
            crd.read_exact(&mut payload).await.unwrap();
            if head[0] & 0x80 != 0 {
                let kind = u16::from_be_bytes([head[2], head[3]]);
                if kind == SYN_REPLY {
                    assert_eq!(dec.block(&payload[4..]).unwrap(), Vec::new());
                }
                seen.push(format!("control {kind}"));
            } else {
                seen.push(format!(
                    "data {} {}",
                    head[4],
                    String::from_utf8_lossy(&payload)
                ));
            }
        }
        seen.sort();
        assert_eq!(seen, ["control 2", "control 6", "data 1 status"]);
        drop(handle);
        drop(cwr);
    }

    #[test]
    fn a_header_stream_that_ended_is_an_error_not_a_loop() {
        // a zlib stream finished by the client: the bytes after it are never
        // consumed
        let mut z = Compress::new(Compression::default(), true);
        z.set_dictionary(DICTIONARY).unwrap();
        let mut block = Vec::with_capacity(256);
        z.compress_vec(&[0, 0, 0, 0], &mut block, FlushCompress::Finish)
            .unwrap();
        block.extend_from_slice(b"trailing");
        let mut dec = Decoder::new();
        assert!(dec.block(&block).is_err());
        // and a block after the end of the stream
        let mut dec = Decoder::new();
        let n = block.len() - 8;
        let _ = dec.block(&block[..n]);
        assert!(dec.block(b"more").is_err());
    }

    #[test]
    fn a_header_bomb_is_refused() {
        // 64 MiB of one byte inflate from a few kilobytes
        let mut z = Compress::new(Compression::best(), true);
        z.set_dictionary(DICTIONARY).unwrap();
        let mut block = Vec::with_capacity(1 << 20);
        let zeros = vec![0u8; 64 << 20];
        z.compress_vec(&zeros, &mut block, FlushCompress::Sync)
            .unwrap();
        assert!(block.len() < MAX_CONTROL);
        assert!(Decoder::new().block(&block).is_err());
    }

    /// A tiny xorshift: the random frames are the same at each run.
    fn noise(seed: &mut u64, n: usize) -> Vec<u8> {
        (0..n)
            .map(|_| {
                *seed ^= *seed << 13;
                *seed ^= *seed >> 7;
                *seed ^= *seed << 17;
                *seed as u8
            })
            .collect()
    }

    #[tokio::test]
    async fn random_bytes_end_the_session_without_a_panic() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for round in 0..300 {
            let (client, server) = tokio::io::duplex(1 << 16);
            let (handle, mut events) = serve(server);
            let (_crd, mut cwr) = tokio::io::split(client);
            let mut input = Vec::new();
            // valid frame heads with random payloads, and pure noise
            if round % 2 == 0 {
                let mut enc = Encoder::new();
                let h = vec![("streamtype".to_string(), "data".to_string())];
                input.extend(syn_stream(&mut enc, 1, &h, false));
                let kind = [SYN_STREAM, SYN_REPLY, RST_STREAM, PING, 4, 9, 8][round % 7];
                let len = (round * 7) % 200;
                let mut p = noise(&mut seed, len);
                if kind == SYN_STREAM && len > 10 {
                    p[..4].copy_from_slice(&3u32.to_be_bytes());
                }
                input.extend(control(kind, 0, &p));
            }
            input.extend(noise(&mut seed, 64 + round * 13));
            let _ = cwr.write_all(&input).await;
            let _ = cwr.shutdown().await;
            let ended = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while let Some(e) = events.recv().await {
                    if e == Event::Closed {
                        break;
                    }
                }
            })
            .await;
            assert!(ended.is_ok(), "round {round}: the session did not end");
            drop(handle);
        }
    }

    #[tokio::test]
    async fn a_big_write_is_cut_in_frames_and_fin_follows_the_last() {
        let (client, server) = tokio::io::duplex(1 << 20);
        let (handle, _events) = serve(server);
        let (mut crd, _cwr) = tokio::io::split(client);
        handle.data(3, &vec![7u8; CHUNK * 2 + 5], true).await;
        let mut flags = Vec::new();
        for _ in 0..3 {
            let mut head = [0u8; 8];
            crd.read_exact(&mut head).await.unwrap();
            let len = u32::from_be_bytes([0, head[5], head[6], head[7]]) as usize;
            let mut payload = vec![0u8; len];
            crd.read_exact(&mut payload).await.unwrap();
            flags.push((head[4], len));
        }
        assert_eq!(flags, [(0, CHUNK), (0, CHUNK), (1, 5)]);
    }
}
