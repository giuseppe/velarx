// SPDX-License-Identifier: Apache-2.0
//! Who may use the CRI socket: root and the user of this process, whatever the
//! permissions of the socket and of its directory say (the socket is made
//! `0600`; a path that is changed or a socket passed on is not a way in).

use futures::Stream;
use tokio::net::{UnixListener, UnixStream};
use tokio_stream::{wrappers::UnixListenerStream, StreamExt};
use tracing::warn;

/// The connections of `listener` from root or this user; the others are
/// closed at once.
pub fn trusted_incoming(listener: UnixListener) -> impl Stream<Item = std::io::Result<UnixStream>> {
    accept_if(listener, velarx_proto::trusted_uid)
}

/// The connections of `listener` whose peer's uid `allowed` accepts.
pub fn accept_if(
    listener: UnixListener,
    allowed: impl Fn(u32) -> bool + Send + 'static,
) -> impl Stream<Item = std::io::Result<UnixStream>> {
    UnixListenerStream::new(listener).filter(move |accepted| match accepted {
        Ok(stream) => match stream.peer_cred() {
            Ok(cred) if allowed(cred.uid()) => true,
            Ok(cred) => {
                warn!(
                    "a connection from uid {} to the CRI socket is refused",
                    cred.uid()
                );
                false
            }
            Err(e) => {
                warn!("the user of a connection to the CRI socket is unknown: {e}");
                false
            }
        },
        Err(_) => true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn this_user_is_served_and_another_is_closed_at_once() {
        let dir = std::env::temp_dir().join(format!("velarx-cri-peer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s");
        let mine = rustix::process::geteuid().as_raw();
        let listener = UnixListener::bind(&path).unwrap();
        let mut incoming = Box::pin(accept_if(listener, move |uid| uid == mine));
        let first = UnixStream::connect(&path).await.unwrap();
        assert!(incoming.next().await.unwrap().is_ok());
        drop(first);
        // a user that is not allowed: the connection is closed, nothing is served
        let listener = UnixListener::bind(dir.join("t")).unwrap();
        let mut incoming = Box::pin(accept_if(listener, move |uid| uid != mine));
        let mut refused = UnixStream::connect(dir.join("t")).await.unwrap();
        let next = tokio::time::timeout(std::time::Duration::from_millis(300), incoming.next());
        assert!(next.await.is_err(), "no connection is handed to the server");
        let mut buf = [0u8; 1];
        assert_eq!(refused.read(&mut buf).await.unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn root_and_the_own_user_are_trusted() {
        let mine = rustix::process::geteuid().as_raw();
        assert!(velarx_proto::trusted_uid(mine));
        assert!(velarx_proto::trusted_uid(0));
        assert!(!velarx_proto::trusted_uid(mine.wrapping_add(12345).max(1)) || mine == 0);
    }
}
