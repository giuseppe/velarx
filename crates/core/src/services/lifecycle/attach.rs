// SPDX-License-Identifier: Apache-2.0
use super::conn::Input;
use super::*;

/// What the monitor sends to a client attached to a container.
#[derive(Debug)]
pub enum AttachEvent {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(i32),
}

/// A session attached to the monitor of a container.
pub struct AttachStream {
    pub(super) session: conn::Session,
    /// The directory of the monitor, to tell whose output was dropped.
    pub(super) dir: PathBuf,
}

impl AttachStream {
    /// The session of an attach connection the blocking client opened;
    /// `dir` is the directory of the monitor.
    pub fn new(opened: client::AttachSession, dir: PathBuf) -> io::Result<Self> {
        Ok(Self {
            session: conn::Session::new(opened.conn, opened.streams, false, opened.exit)?,
            dir,
        })
    }

    /// The next event; `None` when the monitor went away without a status.
    pub async fn next(&mut self) -> io::Result<Option<AttachEvent>> {
        loop {
            return Ok(Some(match self.session.next().await? {
                None => return Ok(None),
                Some(conn::Told::Stdout(d)) => AttachEvent::Stdout(d),
                Some(conn::Told::Stderr(d)) => AttachEvent::Stderr(d),
                Some(conn::Told::End {
                    code,
                    output_dropped,
                    ..
                }) => {
                    if output_dropped {
                        tracing::warn!(
                            "the output of {} was dropped: its reader did not read it fast enough",
                            self.dir.display()
                        );
                    }
                    AttachEvent::Exit(code)
                }
                Some(conn::Told::Started) => continue,
            }));
        }
    }

    /// The input of the session (written while its output is read, see
    /// [`Input`]); `eof` ends it once that is written.
    pub fn input(&self) -> Input {
        self.session.input()
    }

    pub async fn eof(&self) -> io::Result<()> {
        self.session.eof().await
    }

    /// The input of a session whose streams were handed on ends.
    pub async fn close_stdin(&self) -> io::Result<()> {
        self.session.close_stdin().await
    }

    pub async fn resize(&self, rows: u16, cols: u16) -> io::Result<()> {
        self.session.resize(rows, cols).await
    }
}

impl ContainerService {
    /// Attach to the monitor in `dir`; with `start` it starts the container
    /// once attached.
    pub async fn attach_stream(
        &self,
        dir: &Path,
        attach: &proto::Attach,
    ) -> io::Result<AttachStream> {
        let dir = dir.to_path_buf();
        let attach = attach.clone();
        let open = dir.clone();
        let opened = tokio::task::spawn_blocking(move || client::open_attach(&open, &attach))
            .await
            .map_err(io::Error::other)??;
        AttachStream::new(opened, dir)
    }

    /// [`attach_stream`](Self::attach_stream), the pipes of the session given
    /// to the caller to pass on: the stream carries the end of the session
    /// only.
    pub async fn attach_handed(
        &self,
        dir: &Path,
        attach: &proto::Attach,
    ) -> io::Result<(AttachStream, client::Streams)> {
        let dir = dir.to_path_buf();
        let attach = attach.clone();
        let open = dir.clone();
        let mut opened = tokio::task::spawn_blocking(move || client::open_attach(&open, &attach))
            .await
            .map_err(io::Error::other)??;
        let streams = std::mem::take(&mut opened.streams);
        Ok((AttachStream::new(opened, dir)?, streams))
    }
}
