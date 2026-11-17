//! Contains connection related API.

use core::fmt::Debug;

#[cfg(all(feature = "std", target_os = "linux"))]
use crate::connection::PassedCredentials;
use crate::{Result, varlink_service};

use super::{
    BUFFER_SIZE, Call, MAX_BUFFER_SIZE,
    reply::{self, Reply},
    socket::ReadHalf,
};
#[cfg(feature = "std")]
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use serde::Deserialize;
use serde_json::Deserializer;

#[cfg(feature = "std")]
use std::os::fd::OwnedFd;

// Type alias for receive methods - std returns FDs, no_std doesn't
#[cfg(feature = "std")]
type RecvResult<T> = (T, Vec<OwnedFd>);
#[cfg(not(feature = "std"))]
type RecvResult<T> = T;
#[cfg(feature = "std")]
type Fds = Vec<OwnedFd>;
#[cfg(not(feature = "std"))]
type Fds = ();

/// A connection that can only be used for reading.
///
/// # Cancel safety
///
/// All async methods of this type are cancel safe unless explicitly stated otherwise in its
/// documentation.
#[derive(Debug)]
pub struct ReadConnection<Read: ReadHalf> {
    socket: Read,
    read_pos: usize,
    msg_pos: usize,
    buffer: Vec<u8>,
    id: usize,
    // The descriptors of each read that brought some, with the position in the stream of the
    // last byte of that read: they are the descriptors of the message that byte is in.
    #[cfg(feature = "std")]
    pending_fds: VecDeque<(u64, Vec<OwnedFd>)>,
    // The position in the stream of the first byte of `buffer`.
    #[cfg(feature = "std")]
    base: u64,
    // A call rewritten with the other form of "no parameters" (see `parameters_swapped`).
    #[cfg(feature = "std")]
    swapped: Vec<u8>,
    // Number of `recvmsg` calls that returned FDs. Used by `Connection` to drain
    // `WriteConnection::held_fds` on macOS. See that field's comment for details.
    #[cfg(all(feature = "std", target_os = "macos"))]
    pub(super) fd_recvs: usize,
    #[cfg(all(feature = "std", target_os = "linux"))]
    received_credentials: Option<std::sync::Arc<PassedCredentials>>,
}

impl<Read: ReadHalf> ReadConnection<Read> {
    /// Create a new connection.
    pub(super) fn new(socket: Read, id: usize) -> Self {
        Self {
            socket,
            read_pos: 0,
            msg_pos: 0,
            id,
            buffer: alloc::vec![0; BUFFER_SIZE],
            #[cfg(feature = "std")]
            pending_fds: VecDeque::new(),
            #[cfg(feature = "std")]
            base: 0,
            #[cfg(feature = "std")]
            swapped: Vec::new(),
            #[cfg(all(feature = "std", target_os = "macos"))]
            fd_recvs: 0,
            #[cfg(all(feature = "std", target_os = "linux"))]
            received_credentials: None,
        }
    }

    /// The unique identifier of the connection.
    #[inline]
    pub fn id(&self) -> usize {
        self.id
    }

    /// Receives a method call reply.
    ///
    /// The generic parameters needs some explanation:
    ///
    /// * `ReplyParams` is the type of the successful reply. This should be a type that can
    ///   deserialize itself from the `parameters` field of the reply.
    /// * `ReplyError` is the type of the error reply. This should be a type that can deserialize
    ///   itself from the whole reply object itself and must fail when there is no `error` field in
    ///   the object. This can be easily achieved using the `zlink::ReplyError` derive:
    ///
    /// ```rust
    /// use zlink_core::ReplyError;
    ///
    /// #[derive(Debug, ReplyError)]
    /// #[zlink(
    ///     interface = "org.example.ftl",
    ///     // Not needed in the real code because you'll use `ReplyError` through `zlink` crate.
    ///     crate = "zlink_core",
    /// )]
    /// enum MyError {
    ///     Alpha { param1: u32, param2: String },
    ///     Bravo,
    ///     Charlie { param1: String },
    /// }
    /// ```
    ///
    /// Returns the reply and any file descriptors received (std only).
    pub async fn receive_reply<'r, ReplyParams, ReplyError>(
        &'r mut self,
    ) -> Result<RecvResult<reply::Result<ReplyParams, ReplyError>>>
    where
        ReplyParams: Deserialize<'r> + Debug,
        ReplyError: Deserialize<'r> + Debug,
    {
        // The kind of the message is read once, by code that does not depend on the types; the
        // message is then read as that kind.  (An untagged enum buffers the message and tries
        // each variant, for every pair of types: a frontend has dozens of them.)
        let (start, end, fds) = self.take_message().await?;
        let text = &self.buffer[start..end];
        let result = match message_kind(text)? {
            // Varlink service interface error need to be returned as the top-level error.
            MessageKind::Varlink(e) => Err(crate::Error::VarlinkService(e.into())),
            MessageKind::Error => Ok(Err(serde_json::from_slice::<ReplyError>(text)?)),
            MessageKind::Reply(reply) => Ok(Ok(Reply {
                // (`null` is none, as for `Option` of a struct)
                parameters: match reply.parameters.map(|p| p.get()) {
                    None | Some("null") => None,
                    Some(parameters) => Some(serde_json::from_str::<ReplyParams>(parameters)?),
                },
                continues: reply.continues,
            })),
        };

        #[cfg(feature = "std")]
        return result.map(|r| (r, fds));
        #[cfg(not(feature = "std"))]
        {
            let _ = fds;
            return result;
        }
    }

    // The parameters of the reply at `start..end` of the buffer (`take_message`), as the type of
    // the method, or its error: only the reading of either depends on the types.
    #[cfg(feature = "std")]
    pub(super) fn parameters<'r, ReplyParams, ReplyError>(
        &'r self,
        start: usize,
        end: usize,
    ) -> Result<core::result::Result<ReplyParams, ReplyError>>
    where
        ReplyParams: Deserialize<'r>,
        ReplyError: Deserialize<'r>,
    {
        parameters_of(&self.buffer[start..end])
    }

    // The messages that follow a call with `more`, each copied out of the buffer with its
    // descriptors, to the last reply (one that does not continue, or an error): the same for
    // every type of reply, which `Replies` reads them as.
    #[cfg(feature = "std")]
    pub(super) fn messages<'c>(&'c mut self) -> Messages<'c>
    where
        Read: Send + 'c,
    {
        alloc::boxed::Box::pin(futures_util::stream::unfold(
            Some(self),
            |conn| async move {
                let conn = conn?;
                match conn.take_message().await {
                    Err(e) => Some((Err(e), None)),
                    Ok((start, end, fds)) => {
                        let text = conn.buffer[start..end].to_vec();
                        let more = matches!(
                            message_kind(&text),
                            Ok(MessageKind::Reply(ReplyMembers {
                                continues: Some(true),
                                ..
                            }))
                        );
                        Some((Ok((text, fds)), more.then_some(conn)))
                    }
                }
            },
        ))
    }

    /// Receive a method call over the socket.
    ///
    /// The generic `Method` is the type of the method name and its input parameters. This should be
    /// a type that can deserialize itself from a complete method call message, i-e an object
    /// containing `method` and `parameter` fields. This can be easily achieved using the
    /// `serde::Deserialize` derive (See the code snippet in [`super::WriteConnection::send_call`]
    /// documentation for an example).
    ///
    /// Returns the call and any file descriptors received (std only).
    pub async fn receive_call<'m, Method>(&'m mut self) -> Result<RecvResult<Call<Method>>>
    where
        Method: Deserialize<'m> + Debug,
    {
        self.read_message::<Call<Method>>(true).await
    }

    // Reads at least one full message from the socket and return a single message bytes.
    // `call`: the message is a call, taken with either form of "no parameters".
    async fn read_message<'m, M>(&'m mut self, #[allow(unused)] call: bool) -> Result<RecvResult<M>>
    where
        M: Deserialize<'m> + Debug,
    {
        // (all but the parsing is the same for every message type: out of the generic code, which
        // a frontend has once for each reply of the interface)
        let (start, end, fds) = self.take_message().await?;
        let buffer = &self.buffer[start..end];
        let msg = Deserializer::from_slice(buffer).into_iter::<M>().next();
        match msg {
            Some(Ok(msg)) => {
                trace!(
                    "connection {}: received a message of {} bytes",
                    self.id,
                    buffer.len()
                );

                #[cfg(feature = "std")]
                {
                    Ok((msg, fds))
                }
                #[cfg(not(feature = "std"))]
                {
                    let _ = fds;
                    Ok(msg)
                }
            }
            Some(Err(e)) => {
                // A call of a method without parameters sent with `"parameters": {}`, or of
                // one whose parameters are all optional sent without them: the method enums
                // take one form each.
                #[cfg(feature = "std")]
                if let Some(swapped) = call.then(|| parameters_swapped(buffer)).flatten() {
                    self.swapped = swapped;
                    if let Ok(msg) = serde_json::from_slice::<M>(&self.swapped) {
                        return Ok((msg, fds));
                    }
                }
                Err(e.into())
            }
            None => Err(crate::Error::UnexpectedEof),
        }
    }

    // The next message of the buffer, read from the socket if there is none: where it is in the
    // buffer, and its descriptors.
    #[inline(never)]
    pub(super) async fn take_message(&mut self) -> Result<(usize, usize, Fds)> {
        self.read_from_socket().await?;

        let start = self.msg_pos;
        // (every message ends with a null byte, which `read_from_socket` makes sure of)
        let null_index = start
            + self.buffer[start..]
                .iter()
                .position(|b| *b == b'\0')
                .unwrap_or(self.read_pos - start);
        // The descriptors of this message: Linux ends a read of a stream socket after the
        // bytes that came with descriptors, and those bytes start a message (zlink sends one
        // message with its descriptors per `sendmsg`), so the descriptors of a read belong to
        // the message its last byte is in.  Those of an earlier message that was not taken
        // are closed.
        #[cfg(feature = "std")]
        let fds = {
            let first = self.base + self.msg_pos as u64;
            let last = self.base + null_index as u64;
            let mut fds = Vec::new();
            while let Some((at, _)) = self.pending_fds.front() {
                if *at > last {
                    break;
                }
                let (at, got) = self.pending_fds.pop_front().unwrap();
                if at >= first {
                    fds.extend(got);
                }
            }
            fds
        };
        #[cfg(not(feature = "std"))]
        let fds = ();
        if self.buffer[null_index + 1] == b'\0' {
            // This means we're reading the last message and can now reset the indices.
            #[cfg(feature = "std")]
            {
                self.base += (null_index + 1) as u64;
            }
            self.read_pos = 0;
            self.msg_pos = 0;
        } else {
            self.msg_pos = null_index + 1;
        }
        Ok((start, null_index, fds))
    }

    // Reads at least one full message from the socket.
    async fn read_from_socket(&mut self) -> Result<()> {
        if self.msg_pos > 0 {
            // This means we already have at least one message in the buffer so no need to read.
            return Ok(());
        }

        loop {
            let result = self.socket.read(&mut self.buffer[self.read_pos..]).await?;
            #[cfg(all(feature = "std", target_os = "linux"))]
            let mut result = result;

            if result.bytes_read() == 0 {
                return Err(crate::Error::UnexpectedEof);
            }
            self.read_pos += result.bytes_read();
            #[cfg(all(feature = "std", target_os = "linux"))]
            if let Some(creds) = result.take_credentials() {
                self.received_credentials = Some(std::sync::Arc::new(creds));
            }
            #[cfg(feature = "std")]
            if !result.fds().is_empty() {
                let last = self.base + self.read_pos as u64 - 1;
                self.pending_fds.push_back((last, result.into_fds()));
                // Track receipt so `Connection` can drain `WriteConnection::held_fds`.
                #[cfg(target_os = "macos")]
                {
                    self.fd_recvs += 1;
                }
            }

            if self.read_pos == self.buffer.len() {
                if self.read_pos >= MAX_BUFFER_SIZE {
                    return Err(crate::Error::BufferOverflow);
                }

                // Doubled: a large message in a few reads, not one per
                // BUFFER_SIZE bytes.
                let len = (self.buffer.len() * 2).clamp(BUFFER_SIZE, MAX_BUFFER_SIZE);
                self.buffer.resize(len, 0);
            }

            // This marks end of all messages. After this loop is finished, we'll have 2 consecutive
            // null bytes at the end. This is then used by the callers to determine that they've
            // read all messages and can now reset the `read_pos`.
            self.buffer[self.read_pos] = b'\0';

            if self.buffer[self.read_pos - 1] == b'\0' {
                // One or more full messages were read.
                break;
            }
        }

        Ok(())
    }

    /// The underlying read half of the socket.
    pub fn read_half(&self) -> &Read {
        &self.socket
    }

    /// The credentials passed through over the socket with the latest message (if any).
    #[cfg(all(feature = "std", target_os = "linux"))]
    pub fn received_credentials(&self) -> Option<&std::sync::Arc<PassedCredentials>>
    where
        Read: super::socket::UnixSocket,
    {
        self.received_credentials.as_ref()
    }
}

// The call `message` with the other form of "no parameters": without `parameters` when they
// are `{}`, with `{}` when there are none; `None` for another call.
#[cfg(feature = "std")]
fn parameters_swapped(message: &[u8]) -> Option<Vec<u8>> {
    use serde_json::{Map, Value};
    let mut call: Map<String, Value> = serde_json::from_slice(message).ok()?;
    match call.get("parameters") {
        Some(Value::Object(p)) if p.is_empty() => {
            call.remove("parameters");
        }
        None => {
            call.insert("parameters".into(), Value::Object(Map::new()));
        }
        _ => return None,
    }
    serde_json::to_vec(&call).ok()
}

/// What a reply message is.
enum MessageKind<'m> {
    /// An error of the varlink service interface
    Varlink(varlink_service::Error<'m>),
    /// An error of the interface
    Error,
    /// A reply: its members, the parameters not read yet (they are, as the type of the reply
    /// says, by code of that type only)
    Reply(ReplyMembers<'m>),
}

/// The members of a reply.
struct ReplyMembers<'m> {
    parameters: Option<&'m serde_json::value::RawValue>,
    continues: Option<bool>,
}

// The messages of `ReadConnection::messages`.
#[cfg(feature = "std")]
pub(super) type Messages<'c> = core::pin::Pin<
    alloc::boxed::Box<dyn futures_util::Stream<Item = Result<(Vec<u8>, Vec<OwnedFd>)>> + Send + 'c>,
>;

/// The replies of a call with `more` of the proxy, as the type of the method
/// (`Connection::proxy_stream`): all but the reading of each is the same for every type.
#[cfg(feature = "std")]
pub(super) struct Replies<'c, ReplyParams, ReplyError> {
    pub(super) messages: Messages<'c>,
    pub(super) done: bool,
    pub(super) types: core::marker::PhantomData<fn() -> (ReplyParams, ReplyError)>,
}

#[cfg(feature = "std")]
impl<ReplyParams, ReplyError> futures_util::Stream for Replies<'_, ReplyParams, ReplyError>
where
    ReplyParams: serde::de::DeserializeOwned,
    ReplyError: serde::de::DeserializeOwned,
{
    type Item = Result<(core::result::Result<ReplyParams, ReplyError>, Vec<OwnedFd>)>;

    fn poll_next(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<Self::Item>> {
        if self.done {
            return core::task::Poll::Ready(None);
        }
        let next = match self.messages.as_mut().poll_next(cx) {
            core::task::Poll::Pending => return core::task::Poll::Pending,
            core::task::Poll::Ready(next) => next,
        };
        // (an error ends the stream, as a reply that cannot be read does)
        let reply = next.map(|message| {
            let (text, fds) = message?;
            Ok((parameters_of(&text)?, fds))
        });
        self.done = !matches!(reply, Some(Ok(_)));
        core::task::Poll::Ready(reply)
    }
}

// The parameters of the reply `text` as the type of the method, or its error: only the reading
// of either depends on the types.
#[cfg(feature = "std")]
fn parameters_of<'r, ReplyParams, ReplyError>(
    text: &'r [u8],
) -> Result<core::result::Result<ReplyParams, ReplyError>>
where
    ReplyParams: Deserialize<'r>,
    ReplyError: Deserialize<'r>,
{
    Ok(match reply_parameters(text)? {
        Some(parameters) => Ok(serde_json::from_str::<ReplyParams>(parameters)?),
        None => Err(serde_json::from_slice::<ReplyError>(text)?),
    })
}

// The parameters of a reply (none: it is an error of the interface), as `receive_reply` and the
// proxy's `into_parameters` take them: an error of the varlink service interface, or a reply
// without parameters, is an error of the call.
#[cfg(feature = "std")]
#[inline(never)]
fn reply_parameters(text: &[u8]) -> Result<Option<&str>> {
    match message_kind(text)? {
        MessageKind::Varlink(e) => Err(crate::Error::VarlinkService(e.into())),
        MessageKind::Error => Ok(None),
        MessageKind::Reply(reply) => match reply.parameters.map(|p| p.get()) {
            // (`null` is none, as for `Option` of a struct)
            None | Some("null") => Err(crate::Error::MissingParameters),
            Some(parameters) => Ok(Some(parameters)),
        },
    }
}

#[inline(never)]
fn message_kind(text: &[u8]) -> Result<MessageKind<'_>> {
    // The members of any message, read once: the error (a name with an escape is not borrowed:
    // `Cow`), and those of a reply.
    #[derive(Deserialize)]
    struct Probe<'m> {
        #[serde(borrow, default)]
        error: Option<alloc::borrow::Cow<'m, str>>,
        #[serde(borrow, default)]
        parameters: Option<&'m serde_json::value::RawValue>,
        #[serde(default)]
        continues: Option<bool>,
    }

    let probe: Probe<'_> = serde_json::from_slice(text)?;
    Ok(match probe.error {
        None => MessageKind::Reply(ReplyMembers {
            parameters: probe.parameters,
            continues: probe.continues,
        }),
        Some(name) if name.starts_with("org.varlink.service.") => {
            match serde_json::from_slice::<varlink_service::Error<'_>>(text) {
                Ok(e) => MessageKind::Varlink(e),
                Err(_) => MessageKind::Error,
            }
        }
        Some(_) => MessageKind::Error,
    })
}
