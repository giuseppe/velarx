// SPDX-License-Identifier: Apache-2.0
//! The DNS sockets of the overlay: for each container a UDP socket and a
//! listening TCP socket on port 53 of the node's address, bound to the host
//! side of the container's veth.  The overlay helper makes them (port 53 and
//! the binding to an interface are privileged) and passes them over; the
//! kernel does the rest of the network (TCP, the replies of UDP), as it
//! does for any server, and this module reads the queries and answers them
//! with the resolver of `dns_server`.
//!
//! What bounds a container's use of it:
//!
//! * only the container's own address may query (a datagram or a connection
//!   from any other is dropped; the socket sees that veth only);
//! * UDP: `UDP_IN_FLIGHT` queries being answered at a time, more are dropped
//!   (the client asks again); a datagram larger than `MAX_QUERY` is dropped;
//!   an answer is never larger than the client takes (`dns_server`), so
//!   nothing is amplified beyond that;
//! * TCP: `TCP_CONNECTIONS` connections at a time, more are closed at once;
//!   a message has `TCP_IDLE` to arrive whole (and to be answered); a length
//!   larger than `MAX_QUERY` or too small for a DNS header closes the
//!   connection; the connection serves one query at a time, so a client that
//!   sends faster than it reads is held by the socket buffers.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::OwnedFd;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinSet;
use tokio::time::{timeout_at, Duration, Instant};
use tracing::debug;

use crate::dns_server::{DnsHandler, Transport};

/// The largest query taken (UDP datagram, TCP message): far more than any
/// resolver sends (a header, one question, EDNS).
const MAX_QUERY: usize = 4096;

/// The smallest DNS message: its header.
const MIN_MESSAGE: usize = 12;

/// UDP queries of one container answered at the same time.
const UDP_IN_FLIGHT: usize = 32;

/// TCP connections of one container open at the same time.
const TCP_CONNECTIONS: usize = 16;

/// How long a TCP client has to send its next query whole, and to take the
/// answer.
const TCP_IDLE: Duration = Duration::from_secs(10);

/// Serve the container whose address is CLIENT on the sockets UDP and TCP
/// (the helper's, non blocking or not), until one fails or the future is
/// dropped (what it started goes with it).
pub async fn serve(
    udp: OwnedFd,
    tcp: OwnedFd,
    handler: Arc<DnsHandler>,
    client: Ipv4Addr,
) -> io::Result<()> {
    let udp = std::net::UdpSocket::from(udp);
    udp.set_nonblocking(true)?;
    let tcp = std::net::TcpListener::from(tcp);
    tcp.set_nonblocking(true)?;
    tokio::try_join!(
        serve_udp(UdpSocket::from_std(udp)?, handler.clone(), client),
        serve_tcp(TcpListener::from_std(tcp)?, handler, client),
    )
    .map(|_| ())
}

/// A transient failure of `recv_from` or `accept`: the next call is fine.
fn transient(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
    )
}

/// Whether ADDR is the address CLIENT.
fn is_client(addr: SocketAddr, client: Ipv4Addr) -> bool {
    addr.ip() == client
}

/// Answer the datagrams of SOCKET.
async fn serve_udp(
    socket: UdpSocket,
    handler: Arc<DnsHandler>,
    client: Ipv4Addr,
) -> io::Result<()> {
    let socket = Arc::new(socket);
    let mut answering = JoinSet::new();
    // (one byte more than a query: a larger datagram is seen)
    let mut buf = vec![0u8; MAX_QUERY + 1];
    loop {
        let (n, from) = tokio::select! {
            r = socket.recv_from(&mut buf) => match r {
                Ok(r) => r,
                Err(e) if transient(&e) => continue,
                Err(e) => return Err(e),
            },
            Some(_) = answering.join_next(), if !answering.is_empty() => continue,
        };
        if !is_client(from, client) || n > MAX_QUERY {
            debug!("DNS datagram of {} ({} bytes): dropped", from, n);
            continue;
        }
        if answering.len() >= UDP_IN_FLIGHT {
            debug!("Too many DNS queries of {} at once: dropped", client);
            continue;
        }
        let (query, socket, handler) = (buf[..n].to_vec(), socket.clone(), handler.clone());
        answering.spawn(async move {
            let Some(answer) = handler.answer(&query, Transport::Udp).await else {
                return;
            };
            if let Err(e) = socket.send_to(&answer, from).await {
                debug!("DNS answer to {}: {}", from, e);
            }
        });
    }
}

/// Accept the connections of LISTENER and serve each.
async fn serve_tcp(
    listener: TcpListener,
    handler: Arc<DnsHandler>,
    client: Ipv4Addr,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        let (stream, from) = tokio::select! {
            r = listener.accept() => match r {
                Ok(r) => r,
                Err(e) if transient(&e) => continue,
                Err(e) => return Err(e),
            },
            Some(_) = connections.join_next(), if !connections.is_empty() => continue,
        };
        if !is_client(from, client) {
            debug!("DNS connection of {}: dropped", from);
            continue;
        }
        if connections.len() >= TCP_CONNECTIONS {
            debug!("Too many DNS connections of {}: closed", client);
            continue;
        }
        let handler = handler.clone();
        connections.spawn(async move {
            connection(stream, &handler, TCP_IDLE).await;
            debug!("DNS connection of {} ended", from);
        });
    }
}

/// Serve the queries of one connection, one after the other, until the
/// client closes it, sends what is not a query, or leaves it IDLE without a
/// whole query.
async fn connection<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    handler: &DnsHandler,
    idle: Duration,
) {
    loop {
        let deadline = Instant::now() + idle;
        let query = match read_message(&mut stream, deadline).await {
            Ok(Some(query)) => query,
            Ok(None) => return,
            Err(e) => {
                debug!("DNS connection: {}", e);
                return;
            }
        };
        let Some(answer) = handler.answer(&query, Transport::Tcp).await else {
            return;
        };
        if let Err(e) = write_message(&mut stream, &answer, Instant::now() + idle).await {
            debug!("DNS connection: {}", e);
            return;
        }
    }
}

/// The next message of STREAM (two bytes of length, the message), which must
/// be whole by DEADLINE; None when the peer closed the stream before a
/// message.  A message shorter than a DNS header or longer than `MAX_QUERY`
/// is an error, as is a stream that ends within a message.
async fn read_message<R: AsyncRead + Unpin>(
    stream: &mut R,
    deadline: Instant,
) -> io::Result<Option<Vec<u8>>> {
    let read = async {
        let mut length = [0u8; 2];
        if stream.read(&mut length[..1]).await? == 0 {
            return Ok(None);
        }
        stream.read_exact(&mut length[1..]).await?;
        let length = usize::from(u16::from_be_bytes(length));
        if !(MIN_MESSAGE..=MAX_QUERY).contains(&length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("a message of {length} bytes"),
            ));
        }
        let mut message = vec![0u8; length];
        stream.read_exact(&mut message).await?;
        Ok(Some(message))
    };
    timeout_at(deadline, read)
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

/// Send MESSAGE to STREAM with its length, all by DEADLINE.
async fn write_message<W: AsyncWrite + Unpin>(
    stream: &mut W,
    message: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    let length = u16::try_from(message.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "an answer over 64 KiB"))?;
    let mut framed = length.to_be_bytes().to_vec();
    framed.extend_from_slice(message);
    timeout_at(deadline, async {
        stream.write_all(&framed).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DnsRecord, OverlayGossip};
    use tokio::io::duplex;
    use tokio::net::TcpStream;

    const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 200, 1, 2);

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    /// A query for NAME (`\x03web\x00` ...) of type A.
    fn query(id: u16, name: &[u8]) -> Vec<u8> {
        let mut q = id.to_be_bytes().to_vec();
        q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        q.extend_from_slice(name);
        q.extend_from_slice(&[0, 1, 0, 1]);
        q
    }

    fn framed(message: &[u8]) -> Vec<u8> {
        let mut f = (message.len() as u16).to_be_bytes().to_vec();
        f.extend_from_slice(message);
        f
    }

    async fn handler() -> Arc<DnsHandler> {
        let gossip = Arc::new(OverlayGossip::default());
        gossip
            .add_dns_record(DnsRecord {
                name: "web".into(),
                ipv4: "10.200.1.9".parse().unwrap(),
                container_id: "c1".into(),
            })
            .await;
        Arc::new(DnsHandler::new(
            gossip,
            Ipv4Addr::new(10, 200, 1, 1),
            Vec::new(),
        ))
    }

    /// A message arrives in pieces (a byte of the length, then the rest in
    /// two parts) and is read whole; two messages in one write are two reads;
    /// a close between messages is the end.
    #[tokio::test]
    async fn a_message_is_read_whole_however_it_arrives() {
        let (mut client, mut server) = duplex(64);
        let (one, two) = (query(1, b"\x03web\x00"), query(2, b"\x03web\x00"));
        let writer = tokio::spawn(async move {
            let bytes = framed(&one);
            client.write_all(&bytes[..1]).await.unwrap();
            tokio::task::yield_now().await;
            client.write_all(&bytes[1..5]).await.unwrap();
            tokio::task::yield_now().await;
            client.write_all(&bytes[5..]).await.unwrap();
            let mut both = framed(&two);
            both.extend_from_slice(&framed(&one));
            client.write_all(&both).await.unwrap();
            one
        });
        let first = read_message(&mut server, soon()).await.unwrap().unwrap();
        let one = writer.await.unwrap();
        assert_eq!(first, one);
        let second = read_message(&mut server, soon()).await.unwrap().unwrap();
        assert_eq!(second[..2], [0, 2]);
        let third = read_message(&mut server, soon()).await.unwrap().unwrap();
        assert_eq!(third, one);
        // (the writer is gone with its half: a clean end)
        assert_eq!(read_message(&mut server, soon()).await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_bad_length_or_a_cut_message_is_an_error() {
        for (bytes, kind) in [
            // larger than any query
            (vec![0x10, 0x01, 1, 2, 3], io::ErrorKind::InvalidData),
            (vec![0xff, 0xff], io::ErrorKind::InvalidData),
            // smaller than a header
            (vec![0, 5, 1, 2, 3, 4, 5], io::ErrorKind::InvalidData),
            (vec![0, 0], io::ErrorKind::InvalidData),
            // the stream ends within the length, or within the message
            (vec![0], io::ErrorKind::UnexpectedEof),
            (vec![0, 20, 1, 2, 3], io::ErrorKind::UnexpectedEof),
        ] {
            let (mut client, mut server) = duplex(8192);
            client.write_all(&bytes).await.unwrap();
            drop(client);
            let e = read_message(&mut server, soon()).await.unwrap_err();
            assert_eq!(e.kind(), kind, "{bytes:?}");
        }
        // the largest accepted
        let (mut client, mut server) = duplex(8192);
        client
            .write_all(&framed(&vec![7u8; MAX_QUERY]))
            .await
            .unwrap();
        let m = read_message(&mut server, soon()).await.unwrap().unwrap();
        assert_eq!(m.len(), MAX_QUERY);
    }

    /// A client that stops in the middle of a message, or sends none, is
    /// let go when the time is up (the time for the whole message, not for
    /// each piece).
    #[tokio::test]
    async fn a_client_that_is_silent_or_slow_is_given_up() {
        let (mut client, mut server) = duplex(64);
        let soon = Instant::now() + Duration::from_millis(100);
        let e = read_message(&mut server, soon).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        // a byte every 40 ms never completes a message within 150 ms
        let slow = tokio::spawn(async move {
            let bytes = framed(&query(1, b"\x03web\x00"));
            for b in bytes {
                if client.write_all(&[b]).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(40)).await;
            }
        });
        let deadline = Instant::now() + Duration::from_millis(150);
        let e = read_message(&mut server, deadline).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        drop(server);
        slow.await.unwrap();
    }

    /// A connection serves several queries and ends at the client's close;
    /// with no query within the idle time it ends; what is not a query ends
    /// it too.
    #[tokio::test]
    async fn a_connection_answers_query_after_query() {
        let handler = handler().await;
        let (mut client, server) = duplex(8192);
        let serving = tokio::spawn({
            let handler = handler.clone();
            async move { connection(server, &handler, Duration::from_millis(300)).await }
        });
        for id in [1u16, 2] {
            client
                .write_all(&framed(&query(id, b"\x03web\x06velarx\x00")))
                .await
                .unwrap();
            let answer = read_message_unchecked(&mut client).await;
            assert_eq!(answer[..2], id.to_be_bytes());
            assert_eq!(answer[answer.len() - 4..], [10, 200, 1, 9]);
        }
        // idle: closed by the server
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        serving.await.unwrap();

        // a message that is not a query (a header of zeros has no question)
        let (mut client, server) = duplex(8192);
        client.write_all(&framed(&[0u8; 12])).await.unwrap();
        connection(server, &handler, Duration::from_secs(5)).await;
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    }

    /// Whether the server closed STREAM (or reset it, as it does for a
    /// connection closed with a query it did not read) and said nothing.
    async fn closed_unanswered(stream: &mut TcpStream) -> bool {
        let mut rest = Vec::new();
        match stream.read_to_end(&mut rest).await {
            Ok(_) => rest.is_empty(),
            Err(e) => e.kind() == io::ErrorKind::ConnectionReset,
        }
    }

    /// The answer of a connection (its length, the message).
    async fn read_message_unchecked<R: AsyncRead + Unpin>(stream: &mut R) -> Vec<u8> {
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await.unwrap();
        let mut m = vec![0u8; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut m).await.unwrap();
        m
    }

    #[tokio::test]
    async fn an_answer_is_sent_with_its_length() {
        let (mut client, mut server) = duplex(8192);
        write_message(&mut server, &[1, 2, 3], soon())
            .await
            .unwrap();
        let mut got = [0u8; 5];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(got, [0, 3, 1, 2, 3]);
        let e = write_message(&mut server, &vec![0u8; 65536], soon())
            .await
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    }

    /// The listener: only the address of the container is served (here the
    /// loopback), no more than `TCP_CONNECTIONS` at a time.
    #[tokio::test]
    async fn the_listener_serves_the_container_and_a_few_connections() {
        let handler = handler().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // another container's address: nothing is served
        let stranger = tokio::spawn(serve_tcp(listener, handler.clone(), CLIENT));
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(&framed(&query(1, b"\x03web\x00")))
            .await
            .unwrap();
        assert!(closed_unanswered(&mut s).await, "dropped, not answered");
        stranger.abort();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serving = tokio::spawn(serve_tcp(listener, handler, Ipv4Addr::LOCALHOST));
        let ask = |mut s: TcpStream, id: u16| async move {
            s.write_all(&framed(&query(id, b"\x03web\x00")))
                .await
                .unwrap();
            let a = read_message_unchecked(&mut s).await;
            (s, a)
        };
        let mut open = Vec::new();
        for id in 0..TCP_CONNECTIONS as u16 {
            let (s, a) = ask(TcpStream::connect(addr).await.unwrap(), id).await;
            assert_eq!(a[..2], id.to_be_bytes());
            open.push(s);
        }
        // one more: closed
        let mut extra = TcpStream::connect(addr).await.unwrap();
        extra
            .write_all(&framed(&query(99, b"\x03web\x00")))
            .await
            .unwrap();
        assert!(closed_unanswered(&mut extra).await, "over the limit");
        serving.abort();
    }

    /// UDP: the container's datagram is answered at its source; another
    /// address's is not; a datagram over the limit is not.
    #[tokio::test]
    async fn udp_answers_the_container_only() {
        let handler = handler().await;
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let serving = tokio::spawn(serve_udp(server, handler.clone(), Ipv4Addr::LOCALHOST));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&vec![0u8; MAX_QUERY + 1], addr)
            .await
            .unwrap();
        client
            .send_to(&query(5, b"\x03web\x06velarx\x00"), addr)
            .await
            .unwrap();
        let mut buf = vec![0u8; 512];
        let n = client.recv(&mut buf).await.unwrap();
        assert_eq!(buf[..2], 5u16.to_be_bytes());
        assert_eq!(buf[n - 4..n], [10, 200, 1, 9]);
        serving.abort();

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = server.local_addr().unwrap();
        let serving = tokio::spawn(serve_udp(server, handler, CLIENT));
        client
            .send_to(&query(6, b"\x03web\x00"), addr)
            .await
            .unwrap();
        let none = tokio::time::timeout(Duration::from_millis(200), client.recv(&mut buf)).await;
        assert!(
            none.is_err(),
            "a datagram of another address is not answered"
        );
        serving.abort();
    }
}
