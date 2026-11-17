// SPDX-License-Identifier: Apache-2.0
//! The engine, as the handlers of the API see it: the methods that do more
//! than forward a call (the pipes and the descriptors, the lists with their
//! filters, the waits), and `engine_call!` for the calls that only forward,
//! with the errors as podman's.
//!
//! A call has a connection of its own (made and checked: the user of the
//! engine, its version), because a connection that passes descriptors
//! carries one call at a time; the engine starts when the first connect
//! reaches its socket.  The engine refuses the connections of a process above
//! a limit of its own, so two budgets keep the requests apart: at most
//! [`MAX_CALLS`] short calls are in progress at once (a request over it waits
//! at most [`ACQUIRE_DEADLINE`] for one to end, then is answered 503), and at
//! most [`MAX_WAITS`] waits, which hold their connection for as long as the
//! container takes (a wait over it is answered 429 at once).  Waits never
//! take what the short calls need.

use crate::podman::call::Filters;
use crate::podman::error::{ApiError, ApiResult};
use axum::body::Body;
use futures::StreamExt;
use std::collections::{BTreeMap, HashMap};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::Arc;
use velarx_proto::buildspec::BuildSpec;
use velarx_proto::connect::{self, filled_pipe, ConnectError};
use velarx_proto::engine::{
    ArtifactAddSpec, AttachOptions, CheckpointFlags, Checkpointed, CommitSpec, ContainerCreated,
    ContainersPruned, EngineError, EngineProxy, Filter, ImportSpec, InstanceSpec, LayerCompression,
    LogOptions, LoginReply, ManifestArtifactSpec, PathStat, PlatformSpec, PullSpec, PushSpec,
    RemovedContainer, RestoreFlags, Restored, SearchHit, Stream, UpdateSpec, Waited,
};
use velarx_proto::pod::PodAction;
use velarx_proto::retry::Retry;
use velarx_proto::system::{PrunedVolume, SystemPruneReport};
use velarx_proto::wait::WaitCondition;
use velarx_proto::workload::{
    ArtifactListed, ArtifactRecord, Committed, ContainerListed, ContainerRecord, EventListed,
    ImageHistoryEntry, ImageHistoryListed, ImageListed, ImagePruneListed, ImageRecord,
    ImageRemoved, ManifestListRecord, MetricDescriptorListed, NetworkListed, NetworkRecord,
    PodListed, PodMetricsListed, PodRecord, PrunedImage, Pulled, PulledImage, Pushed, SecretListed,
    SecretRecord, StatsListed, StatsRecord, VolumeListed, VolumeRecord,
};
use velarx_registry::auth::RegistryAccess;

/// The most short calls in progress at once.  With [`MAX_WAITS`] they stay
/// below the engine's limit of connections of one client
/// (`[services] max_per_client`, 192 by default), with room for the connection
/// that holds the engine.
pub const MAX_CALLS: usize = 48;

/// The most waits in progress at once: each is a connection of its own for
/// as long as the container takes, from a budget the short calls do not use.
pub const MAX_WAITS: usize = 128;

/// How long a short call waits for a connection when [`MAX_CALLS`] are in
/// progress, before it is answered 503.
pub const ACQUIRE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// A secret to create.
pub struct NewSecret<'a> {
    pub name: &'a str,
    pub data: bytes::Bytes,
    pub driver: Option<&'a str>,
    pub driver_opts: BTreeMap<String, String>,
    pub labels: BTreeMap<String, String>,
    pub replace: bool,
    pub ignore: bool,
}

/// How `image_remove` removes.
#[derive(Debug, Clone, Copy)]
pub struct ImageRemoveOptions {
    pub force: bool,
    pub spare_running: bool,
    pub noprune: bool,
    pub ignore: bool,
    pub manifest_list: bool,
}

/// How `container_remove` removes.
#[derive(Debug, Clone, Copy)]
pub struct RemoveOptions {
    pub force: bool,
    /// Its anonymous volumes too
    pub volumes: bool,
    /// One that is not there is no error
    pub ignore: bool,
    /// The containers that depend on it go first
    pub depend: bool,
    /// The seconds a running container has to stop
    pub timeout: Option<u64>,
}

/// A call of the engine on a connection of its own: its answer, or the error
/// a podman client sees.
macro_rules! raw_call {
    ($engine:expr, $method:ident ( $($arg:expr),* $(,)? )) => {
        async {
            use ::velarx_proto::engine::EngineProxy as _;
            let mut conn = $engine.conn().await?;
            let reply = conn
                .$method($($arg),*)
                .await
                .map_err($crate::engine::protocol)?;
            conn.answered();
            reply.map_err($crate::engine::failed)
        }
        .await
    };
}
pub(crate) use raw_call;

/// [`raw_call`] with the size of the arguments checked: a call is a message
/// zlink builds in memory, and a large one costs much more than its bytes
/// (`MAX_ARG_BYTES`).
macro_rules! engine_call {
    ($engine:expr, $method:ident ( $($arg:expr),* $(,)? )) => {
        async {
            $crate::engine::check_args(stringify!($method), &($(&$arg,)*))?;
            $crate::engine::raw_call!($engine, $method($($arg),*))
        }
        .await
    };
}
pub(crate) use engine_call;

/// A call whose reply carries descriptors: the answer and its descriptors,
/// the size of the arguments checked.
macro_rules! fds_call {
    ($engine:expr, $method:ident ( $($arg:expr),* $(,)? )) => {{
        check_args(stringify!($method), &($(&$arg,)*))?;
        let mut conn = $engine.conn().await?;
        conn.$method($($arg),*).await.map_err(protocol)?
    }};
}

/// A list, a call with more: its records.  `take` gets one out of a reply
/// (none in the one reply of an empty list), `refused` is the error of a
/// call the engine refuses; the size of the arguments is checked.
macro_rules! list_call {
    ($engine:expr, $method:ident ( $($arg:expr),* $(,)? ), $take:expr, $refused:expr) => {{
        check_args(stringify!($method), &($(&$arg,)*))?;
        let mut conn = $engine.conn().await?;
        let replies = conn.$method($($arg),*).await.map_err(protocol)?;
        let listed = connect::records(replies, $take).await.map_err(protocol)?;
        conn.answered();
        listed.map_err($refused)
    }};
}

/// A call with more that lasts (a pull, a push, the events), on a connection
/// of the budget of the waits: the replies to the receiver as they come, the
/// last one or an error the end.  Dropping the receiver closes the
/// connection, which ends the call.  The arguments are owned (a task makes
/// the call); `$checked` are those that are not descriptors, whose size is
/// checked.
macro_rules! replies_call {
    ($engine:expr, $method:ident ( $($arg:expr),* $(,)? ), $checked:expr) => {{
        check_args(stringify!($method), $checked)?;
        let mut conn = $engine.wait_conn().await?;
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let (sent_tx, sent_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            match conn.$method($($arg),*).await {
                Ok(replies) => {
                    let _ = sent_tx.send(Ok(()));
                    pass_on(replies, tx).await;
                }
                Err(e) => {
                    let _ = sent_tx.send(Err(protocol(e)));
                }
            }
        });
        sent_rx
            .await
            .map_err(|_| ApiError::internal("the engine call ended before it was sent"))??;
        ApiResult::Ok(rx)
    }};
}

/// The replies of a call with more, to `tx` until the last or an error, or
/// until the receiver is dropped.
async fn pass_on<T>(
    replies: impl futures::Stream<Item = zlink::Result<Result<T, EngineError>>>,
    tx: tokio::sync::mpsc::Sender<ApiResult<T>>,
) {
    let mut replies = std::pin::pin!(replies);
    loop {
        let received = tokio::select! {
            r = replies.next() => r,
            () = tx.closed() => return,
        };
        let item = match received {
            None => return,
            Some(Ok(Ok(reply))) => Ok(reply),
            Some(Ok(Err(e))) => Err(failed(e)),
            Some(Err(e)) => Err(protocol(e)),
        };
        let last = item.is_err();
        if tx.send(item).await.is_err() || last {
            return;
        }
    }
}

/// The arguments of a call are at most `MAX_ARG_BYTES` of JSON: what is
/// larger crosses as a descriptor.
pub(crate) fn check_args<T: serde::Serialize + ?Sized>(method: &str, args: &T) -> ApiResult<()> {
    match connect::args_too_large(method, args) {
        Some(message) => Err(ApiError::new(413, message)),
        None => Ok(()),
    }
}

/// The samples of the stats of containers that [`Engine::container_stats`]
/// receives.
pub struct Samples(tokio::sync::mpsc::Receiver<ApiResult<StatsListed>>);

impl Samples {
    /// The next sample (none: the samples ended).
    pub async fn next(&mut self) -> Option<ApiResult<Vec<StatsRecord>>> {
        let mut sample = Vec::new();
        loop {
            match self.0.recv().await {
                None if sample.is_empty() => return None,
                None => return Some(Ok(sample)),
                Some(Err(e)) => return Some(Err(e)),
                Some(Ok(StatsListed { stats: Some(s) })) => sample.push(s),
                Some(Ok(StatsListed { stats: None })) => return Some(Ok(sample)),
            }
        }
    }
}

/// A wait the engine armed ([`Engine::container_wait`]).
pub struct ArmedWait {
    /// The end of the wait, when the engine armed it already over
    first: Option<ApiResult<Waited>>,
    replies: tokio::sync::mpsc::Receiver<ApiResult<Waited>>,
}

impl ArmedWait {
    /// The end of the wait: the exit code and the condition met.
    pub async fn outcome(mut self) -> ApiResult<Waited> {
        if let Some(over) = self.first.take() {
            return over;
        }
        self.replies
            .recv()
            .await
            .unwrap_or_else(|| Err(ApiError::internal("the engine ended the wait")))
    }
}

#[derive(Clone, Debug)]
pub struct Engine {
    dial: Arc<connect::Dial>,
    calls: Arc<tokio::sync::Semaphore>,
    waits: Arc<tokio::sync::Semaphore>,
    /// The connections checked and not in use: a call takes one, and gives
    /// it back when the engine has answered it in full.
    idle: connect::Idle,
    deadline: std::time::Duration,
}

/// A connection to the engine, counted in [`MAX_CALLS`] or [`MAX_WAITS`]
/// while it lives.
type EngineCall = connect::Held;

/// The error a client sees when the engine cannot be used.
fn unavailable(e: ConnectError) -> ApiError {
    ApiError::new(503, format!("the engine is not available: {e}"))
}

/// The engine tried the call and it failed: not an object that is not
/// there, a request it refused before it started, a format it does not do,
/// nor an engine that cannot answer.
fn tried(e: &EngineError) -> bool {
    use EngineError as E;
    let (cause, _) = e.parts();
    !(cause.is_empty()
        || matches!(
            e,
            E::NoSuchContainer { .. }
                | E::NoSuchImage { .. }
                | E::NoSuchObject { .. }
                | E::InvalidReference { .. }
                | E::NotSupported { .. }
                | E::TooLarge { .. }
                | E::Unavailable { .. }
        ))
}

/// The error of a list or a prune whose filters podman reads: podman's
/// handlers answer a filter they do not take with a 500, where the engine
/// says `InvalidArgument`.
fn filter_failed(e: EngineError) -> ApiError {
    let invalid = matches!(e, EngineError::InvalidArgument { .. });
    let e = failed(e);
    if invalid {
        e.with_status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
    } else {
        e
    }
}

/// The error of a call, as podman's: the status of its condition, and the
/// cause and the message of the engine (which has podman's words); one the
/// engine refused before any operation has no cause.
pub(crate) fn failed(e: EngineError) -> ApiError {
    let condition = e.condition();
    unnamed(&e).with_condition(condition)
}

fn unnamed(e: &EngineError) -> ApiError {
    let status = e.status();
    let (cause, message) = e.parts();
    match (e, cause) {
        (EngineError::Unavailable { .. }, "") => {
            ApiError::new(status, format!("the engine is not available: {message}"))
        }
        (_, "") => ApiError::new(status, message),
        _ => ApiError::from_engine(status, cause.to_string(), message.to_string()),
    }
}

pub(crate) fn protocol(e: zlink::Error) -> ApiError {
    ApiError::internal(format!("the engine: {e}"))
}

fn filters_of(filters: &Filters) -> Vec<Filter> {
    filters
        .0
        .iter()
        .map(|(key, values)| Filter {
            key: key.clone(),
            values: values.clone(),
        })
        .collect()
}

impl Engine {
    pub fn new(socket: &Path) -> Self {
        Self::reached(connect::Dial::Path(socket.to_path_buf()))
    }

    /// An engine reached the way `dial` says (a confined frontend has the
    /// connections of a connector, and looks up no socket).
    pub fn reached(dial: connect::Dial) -> Self {
        Self::with_dial(dial, MAX_CALLS, MAX_WAITS, ACQUIRE_DEADLINE)
    }

    /// An engine with the budgets of short calls and of waits given, and the
    /// time a short call waits for its connection.
    pub fn with_limits(
        socket: &Path,
        calls: usize,
        waits: usize,
        deadline: std::time::Duration,
    ) -> Self {
        Self::with_dial(
            connect::Dial::Path(socket.to_path_buf()),
            calls,
            waits,
            deadline,
        )
    }

    fn with_dial(
        dial: connect::Dial,
        calls: usize,
        waits: usize,
        deadline: std::time::Duration,
    ) -> Self {
        Self {
            dial: Arc::new(dial),
            calls: Arc::new(tokio::sync::Semaphore::new(calls)),
            waits: Arc::new(tokio::sync::Semaphore::new(waits)),
            idle: connect::Idle::default(),
            deadline,
        }
    }

    pub fn socket(&self) -> &Path {
        self.dial.socket()
    }

    /// A connection to the engine, checked, once fewer than [`MAX_CALLS`]
    /// are open: the call waits for one at most [`ACQUIRE_DEADLINE`].
    pub(crate) async fn conn(&self) -> ApiResult<EngineCall> {
        let permit = tokio::time::timeout(self.deadline, self.calls.clone().acquire_owned())
            .await
            .map_err(|_| {
                ApiError::new(
                    503,
                    format!(
                        "the engine is busy: every connection for requests is in use, \
                         none was free in {}s",
                        self.deadline.as_secs_f32()
                    ),
                )
            })?
            .map_err(|e| ApiError::internal(format!("the engine: {e}")))?;
        self.connect(permit).await
    }

    /// A connection for a wait, from the budget of the waits: none free is
    /// 429 at once, a wait that cannot start is better told than queued.
    async fn wait_conn(&self) -> ApiResult<EngineCall> {
        let permit = self
            .waits
            .clone()
            .try_acquire_owned()
            .map_err(|e| match e {
                tokio::sync::TryAcquireError::NoPermits => ApiError::new(
                    429,
                    "too many waits in progress for the engine: wait for one to end",
                ),
                tokio::sync::TryAcquireError::Closed => ApiError::internal("the engine: closed"),
            })?;
        self.connect(permit).await
    }

    async fn connect(&self, permit: tokio::sync::OwnedSemaphorePermit) -> ApiResult<EngineCall> {
        self.idle
            .hold(&self.dial, permit)
            .await
            .map_err(unavailable)
    }

    /// The engine answers.
    pub async fn ping(&self) -> ApiResult<()> {
        let mut conn = self.conn().await?;
        conn.ping()
            .await
            .map_err(protocol)?
            .map(|_| ())
            .map_err(failed)
    }

    /// Start the container: whether it was started (it was not running).
    pub async fn container_start(&self, name: &str, verify_image: &[String]) -> ApiResult<bool> {
        Ok(engine_call!(
            self,
            container_start(name, verify_image.to_vec(), None::<bool>, None::<bool>)
        )?
        .changed)
    }

    /// Remove the container: the IDs removed, each with what named it.
    pub async fn container_remove(
        &self,
        name: &str,
        opts: RemoveOptions,
    ) -> ApiResult<Vec<RemovedContainer>> {
        let RemoveOptions {
            force,
            volumes,
            ignore,
            depend,
            timeout,
        } = opts;
        engine_call!(
            self,
            container_remove(name, force, volumes, ignore, depend, timeout)
        )
        .map(|r| r.removed)
    }

    /// Arm a wait of the engine until the container meets one of
    /// `conditions` (none: its exit), `interval_ns` podman's interval: this
    /// returns once the engine follows the container (what it refuses, it
    /// refuses here), and [`ArmedWait::outcome`] is the end of the wait.
    /// The wait ends when the outcome is dropped: its connection closes.
    pub async fn container_wait(
        &self,
        name: &str,
        conditions: Vec<WaitCondition>,
        interval_ns: i64,
    ) -> ApiResult<ArmedWait> {
        let name = name.to_string();
        let mut replies = replies_call!(
            self,
            container_wait(&name, conditions, interval_ns),
            &(&name, &conditions)
        )?;
        // (the first reply says the wait is armed; one with the status is
        // the end of a wait that was over already)
        let first = match replies.recv().await {
            Some(Ok(w)) if w.status_code.is_none() => None,
            Some(Ok(w)) => Some(Ok(w)),
            Some(Err(e)) => return Err(e),
            None => {
                return Err(ApiError::internal(
                    "the engine ended the wait without arming it",
                ))
            }
        };
        Ok(ArmedWait { first, replies })
    }

    /// The steps of the history of the image, the newest first.
    pub async fn image_history(&self, name: &str) -> ApiResult<Vec<ImageHistoryEntry>> {
        list_call!(
            self,
            image_history(name),
            |r: ImageHistoryListed| r.entry,
            failed
        )
    }

    /// Remove the image: the names untagged and the ids removed.
    pub async fn image_remove(
        &self,
        name: &str,
        opts: ImageRemoveOptions,
    ) -> ApiResult<ImageRemoved> {
        let ImageRemoveOptions {
            force,
            spare_running,
            noprune,
            ignore,
            manifest_list,
        } = opts;
        engine_call!(
            self,
            image_remove(name, force, spare_running, noprune, ignore, manifest_list)
        )
    }

    /// Remove the unused images the filters select: what was removed.
    pub async fn image_prune(&self, all: bool, filters: &Filters) -> ApiResult<Vec<PrunedImage>> {
        let filters = filters_of(filters);
        list_call!(
            self,
            image_prune(all, filters),
            |r: ImagePruneListed| r.image,
            filter_failed
        )
    }

    pub async fn network_list(&self, filters: &Filters) -> ApiResult<Vec<NetworkRecord>> {
        let filters = filters_of(filters);
        list_call!(
            self,
            network_list(filters),
            |r: NetworkListed| r.network,
            filter_failed
        )
    }

    pub async fn network_prune(&self, filters: &Filters) -> ApiResult<Vec<String>> {
        let filters = filters_of(filters);
        check_args("network_prune", &filters)?;
        let mut conn = self.conn().await?;
        Ok(conn
            .network_prune(filters)
            .await
            .map_err(protocol)?
            .map_err(filter_failed)?
            .removed)
    }

    /// The logs of a container: Docker's multiplexed frames.
    pub async fn container_logs(&self, name: &str, opts: LogOptions) -> ApiResult<Streamed> {
        let (reply, fds) = fds_call!(self, container_logs(name, opts));
        streamed(reply.map_err(failed)?, fds)
    }

    /// A TCP connection to `port` on the loopback of a container (a pod:
    /// its infra container), made in its network namespace.
    pub async fn connect_port(&self, pod: bool, name: &str, port: u16) -> ApiResult<OwnedFd> {
        let (reply, fds) = fds_call!(self, port_connect(pod, name, port));
        reply.map_err(failed)?;
        connect::take_fd(fds, 0)
            .ok_or_else(|| ApiError::internal("the engine connected a port with no socket"))
    }

    /// podman's `system prune`: what it removed (podman's 500 for a filter
    /// it does not take).
    pub async fn system_prune(
        &self,
        all: bool,
        volumes: bool,
        build: bool,
        filters: &Filters,
    ) -> ApiResult<SystemPruneReport> {
        let filters = filters_of(filters);
        check_args("system_prune", &(&all, &volumes, &build, &filters))?;
        let mut conn = self.conn().await?;
        conn.system_prune(all, volumes, build, filters)
            .await
            .map_err(protocol)?
            .map_err(filter_failed)
            .map(|r| r.report)
    }

    /// Log in to the registry at `host`: what it said when it refused, and
    /// whether it refused the credentials.
    pub async fn registry_login(
        &self,
        host: &str,
        username: &str,
        password: &str,
    ) -> ApiResult<LoginReply> {
        // (the password goes in a sealed memory file, never in the message)
        let access = RegistryAccess {
            creds: Some(velarx_registry::Credentials::basic(username, password)),
            ..Default::default()
        };
        let (at, fds) = access_memfd(&access)?;
        check_args("registry_login", &(host,))?;
        raw_call!(self, registry_login(host, at, fds))
    }

    /// The descriptors of the metrics of pods.
    pub async fn metrics_descriptors(&self) -> ApiResult<(Body, Option<u64>)> {
        let list = list_call!(
            self,
            metric_descriptor_list(),
            |r: MetricDescriptorListed| r.descriptor,
            failed
        )?;
        json_body(&list)
    }

    /// The metrics of the pods that run, or of the pod `name`.
    pub async fn pods_metrics(&self, name: Option<&str>) -> ApiResult<(Body, Option<u64>)> {
        let list = list_call!(
            self,
            pod_metrics_list(name),
            |r: PodMetricsListed| r.pod,
            failed
        )?;
        json_body(&list)
    }

    /// The events of `filters` from `since_ns` to `until_ns`, those that
    /// happen too with `follow`: the replies of the engine as they come
    /// (the first one of a follow without an event: it was taken), until
    /// the last or an error.  It stops when the receiver is dropped.
    pub async fn event_list(
        &self,
        filters: &Filters,
        since_ns: Option<i64>,
        until_ns: Option<i64>,
        follow: bool,
    ) -> ApiResult<tokio::sync::mpsc::Receiver<ApiResult<EventListed>>> {
        let filters = filters_of(filters);
        replies_call!(
            self,
            event_list(filters, since_ns, until_ns, follow),
            &(&filters, since_ns, until_ns, follow)
        )
    }

    /// Samples of the stats of the containers `names` (none: those that
    /// run; with `all` all of them, those that do not run with zeros),
    /// `size`: with what they wrote; with `stream` again every
    /// `interval_ms`.  The replies as they come: a record each, none at
    /// the end of a sample, until the last or an error.  It stops when the
    /// receiver is dropped.
    pub async fn container_stats(
        &self,
        names: &[String],
        all: bool,
        size: bool,
        stream: bool,
        interval_ms: Option<u64>,
    ) -> ApiResult<Samples> {
        let names = names.to_vec();
        replies_call!(
            self,
            container_stats(names, all, size, stream, interval_ms),
            &(&names, all, size, stream, interval_ms)
        )
        .map(Samples)
    }

    /// Start an exec session.  `upgraded`: the client sends input.  None
    /// when the command runs on its own (`detach`).
    pub async fn exec_start(
        &self,
        id: &str,
        upgraded: bool,
        detach: bool,
        height: i64,
        width: i64,
    ) -> ApiResult<Option<Hijacked>> {
        let id = id.to_string();
        check_args("exec_start", &(&id, upgraded, detach, height, width))?;
        let conn = self.wait_conn().await?;
        let opened = velarx_proto::session_call!(
            conn,
            exec_start(&id, upgraded, detach, height, width, Vec::new(), Vec::new())
        )
        .await;
        self.session(opened)
    }

    /// Attach to a container.
    pub async fn container_attach(&self, name: &str, opts: AttachOptions) -> ApiResult<Hijacked> {
        let name = name.to_string();
        check_args("container_attach", &(&name, &opts))?;
        let conn = self.wait_conn().await?;
        let opened = velarx_proto::session_call!(conn, container_attach(&name, opts)).await;
        self.session(opened)?
            .ok_or_else(|| ApiError::internal("the engine attached to nothing"))
    }

    /// The session of a call that opened one: none when the command runs on
    /// its own.
    fn session(
        &self,
        opened: Result<
            (velarx_proto::stream::Item, velarx_proto::stream::Replies),
            velarx_proto::stream::OpenError,
        >,
    ) -> ApiResult<Option<Hijacked>> {
        use velarx_proto::stream::OpenError;
        let (first, replies) = opened.map_err(|e| match e {
            OpenError::Engine(e) => failed(e),
            OpenError::Protocol(e) => protocol(e),
        })?;
        let engine = self.clone();
        velarx_proto::stream::Session::of_first(first, replies, move |name, what| {
            let engine = engine.clone();
            async move {
                engine
                    .session_control(&name, what)
                    .await
                    .map_err(|e| std::io::Error::other(e.message))
            }
        })
        .map(|s| s.map(Hijacked))
        .map_err(|e| ApiError::internal(format!("the streams of the engine: {e}")))
    }

    /// What the client of a session tells the engine, on a connection of
    /// its own.
    async fn session_control(
        &self,
        session: &str,
        what: velarx_proto::stream::Control,
    ) -> ApiResult<()> {
        use velarx_proto::stream::Control;
        let mut conn = self.conn().await?;
        let answered = match what {
            Control::CloseStdin => {
                check_args("session_close_stdin", &session)?;
                conn.session_close_stdin(session).await
            }
            Control::Detach => {
                check_args("session_detach", &session)?;
                conn.session_detach(session).await
            }
        };
        // (the connection is not kept for another call: the engine holds a
        // descriptor for each one that is)
        answered.map_err(protocol)?.map_err(failed)?;
        Ok(())
    }

    /// Build an image from `spec` and the context (the body of the request,
    /// streamed through a pipe as it arrives, never held; none when the spec
    /// names a remote one, or a directory of the host).  The answer is the
    /// progress as a stream; the errors of the request and of the context
    /// come before it.
    pub async fn image_build(
        &self,
        spec: &BuildSpec,
        access: &RegistryAccess,
        context: Option<Context>,
    ) -> ApiResult<Streamed> {
        // (the spec is the first descriptor, the credentials the second)
        let mut pipes = spec_pipe(spec)?;
        let (access, credentials) = access_memfd(access)?;
        let access = access.map(|_| 1);
        pipes.extend(credentials);
        let mut upload = None;
        let mut context_at = None;
        let mut sections = false;
        match context {
            Some(Context::Body(body)) => {
                let (read, pump) = body_pump(body)?;
                context_at = Some(pipes.len() as u32);
                pipes.push(read);
                upload = Some(pump);
            }
            Some(Context::Sections(body, boundary)) => {
                let (read, pump) = sections_pump(body, boundary)?;
                context_at = Some(pipes.len() as u32);
                pipes.push(read);
                upload = Some(pump);
                sections = true;
            }
            None => {}
        }
        let mut conn = self.conn().await?;
        let reply = conn
            .image_build(0, context_at, sections, access, pipes)
            .await;
        if !matches!(reply, Ok((Ok(_), _))) {
            // (its connection to the engine is one of a bounded pool: free
            // for other requests while this one waits for its client)
            drop(conn);
            // A refusal that does not read the context: the client that is
            // still uploading it gets the answer once the upload is over (up
            // to a bound of time, and the drain of 64 MiB at most), not a
            // connection closed under it.
            if let Some(pump) = upload {
                let _ = tokio::time::timeout(std::time::Duration::from_secs(30), pump).await;
            }
        }
        let (stream, fds) = reply.map_err(protocol)?;
        streamed(stream.map_err(failed)?, fds)
    }

    pub async fn volume_list(&self, filters: &Filters) -> ApiResult<Vec<VolumeRecord>> {
        let filters = filters_of(filters);
        list_call!(
            self,
            volume_list(filters),
            |r: VolumeListed| r.volume,
            filter_failed
        )
    }

    pub async fn volume_prune(
        &self,
        filters: &Filters,
        dry_run: bool,
    ) -> ApiResult<Vec<PrunedVolume>> {
        let filters = filters_of(filters);
        check_args("volume_prune", &(&filters, &dry_run))?;
        let mut conn = self.conn().await?;
        Ok(conn
            .volume_prune(filters, dry_run)
            .await
            .map_err(protocol)?
            .map_err(filter_failed)?
            .removed)
    }

    /// The content of a volume: a tar archive, as it comes.
    pub async fn volume_export(&self, name: &str) -> ApiResult<Body> {
        let (reply, fds) = fds_call!(self, volume_export(name));
        reply.map_err(failed)?;
        downloaded(fds)
    }

    /// Extract the tar archive `body` into a volume.
    pub async fn volume_import(&self, name: &str, body: Body) -> ApiResult<()> {
        check_args("volume_import", &(name,))?;
        let archive = vec![body_pipe(body)?];
        raw_call!(self, volume_import(name, archive)).map(|_| ())
    }

    /// Create a container from the document of the client (libpod's
    /// SpecGenerator, Docker's configuration with `docker`).
    pub async fn container_create_document(
        &self,
        docker: bool,
        name: Option<&str>,
        platform: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> ApiResult<ContainerCreated> {
        check_args("podman_container_create", &(name, platform))?;
        // (a request without a body is an empty document)
        let pipe = vec![match body {
            Some(v) => filled_pipe(bytes::Bytes::from(serde_json::to_vec(&v)?))?,
            None => filled_pipe(bytes::Bytes::new())?,
        }];
        raw_call!(
            self,
            podman_container_create(docker, name, platform, 0, pipe)
        )
    }

    /// Remove the containers that do not run and the filters select.
    pub async fn container_prune(&self, filters: &Filters) -> ApiResult<ContainersPruned> {
        let filters = filters_of(filters);
        check_args("container_prune", &(&filters,))?;
        let mut conn = self.conn().await?;
        conn.container_prune(filters)
            .await
            .map_err(protocol)?
            .map_err(filter_failed)
    }

    /// Change a container as `spec` says: its id.
    pub async fn container_amend(&self, name: &str, spec: UpdateSpec) -> ApiResult<String> {
        check_args("container_amend", &(name, &spec))?;
        raw_call!(self, container_amend(name, spec)).map(|r| r.id)
    }

    /// Checkpoint a container, the checkpoint kept with it for a restore in
    /// place.
    pub async fn container_checkpoint_kept(
        &self,
        name: &str,
        flags: CheckpointFlags,
    ) -> ApiResult<Checkpointed> {
        raw_call!(self, container_checkpoint(name, flags, None, Vec::new()))
    }

    /// Checkpoint a container into an archive, as it comes: the engine
    /// writes the frames to a pipe the call carries, and the body is read
    /// from it.  An error of the checkpoint (it comes before the first
    /// frame) is the answer, not a body that ends early.
    pub async fn container_checkpoint_export(
        &self,
        name: &str,
        flags: CheckpointFlags,
    ) -> ApiResult<Body> {
        use velarx_proto::engine::EngineProxy as _;
        check_args("container_checkpoint", &(name, &flags))?;
        let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)
            .map_err(|e| ApiError::internal(format!("cannot make a pipe: {e}")))?;
        let reader = tokio::net::unix::pipe::Receiver::from_owned_fd(read)
            .map_err(|e| ApiError::internal(format!("the download of the engine: {e}")))?;
        let mut conn = self.conn().await?;
        let name = name.to_string();
        let (done_tx, mut done) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let reply = conn
                .container_checkpoint(&name, flags, Some(0), vec![write])
                .await
                .map_err(protocol);
            if reply.is_ok() {
                conn.answered();
            }
            let _ = done_tx.send(reply.and_then(|r| r.map_err(failed)).map(|_| ()));
        });
        // (what comes first: the call fails, or the archive starts)
        tokio::select! {
            answer = &mut done => match answer {
                Ok(Err(e)) => return Err(e),
                Ok(Ok(())) => {}
                Err(_) => return Err(ApiError::internal("the engine call ended early")),
            },
            ready = reader.readable() => {
                ready.map_err(|e| ApiError::internal(e.to_string()))?;
                // (a pipe the engine closed has no bytes: its answer is next)
                if rustix::io::ioctl_fionread(&reader).unwrap_or(0) == 0 {
                    if let Ok(Err(e)) = (&mut done).await {
                        return Err(e);
                    }
                }
            }
        }
        Ok(framed(reader))
    }

    /// Make a container of the checkpoint archive `body` (or the shared one
    /// `reference`) and restore it: its id and what was measured.
    pub async fn container_restore_import(
        &self,
        flags: RestoreFlags,
        reference: Option<&str>,
        body: Body,
    ) -> ApiResult<Restored> {
        check_args("container_restore", &(&flags, reference))?;
        let archive = vec![body_pipe(body)?];
        raw_call!(
            self,
            container_restore(None, flags, Some(0), reference, false, archive)
        )
    }

    /// Restore a container from the checkpoint kept with it.
    pub async fn container_restore_kept(
        &self,
        name: &str,
        flags: RestoreFlags,
    ) -> ApiResult<Restored> {
        check_args("container_restore", &(name, &flags))?;
        raw_call!(
            self,
            container_restore(Some(name), flags, None, None, false, Vec::new())
        )
    }

    /// What is at `path` in a container and, with `content`, its tar.
    pub async fn container_archive_get(
        &self,
        name: &str,
        path: &str,
        content: bool,
    ) -> ApiResult<(PathStat, Option<Body>)> {
        let (reply, fds) = fds_call!(self, container_archive_get(name, path, content));
        let stat = reply.map_err(failed)?;
        let body = if content {
            Some(downloaded(fds)?)
        } else {
            None
        };
        Ok((stat, body))
    }

    /// Extract the tar `body` into the directory `path` of a container.
    pub async fn container_archive_put(
        &self,
        name: &str,
        path: &str,
        rename: HashMap<String, String>,
        chown: bool,
        overwrite_dir_non_dir: bool,
        body: Body,
    ) -> ApiResult<()> {
        let rename: BTreeMap<String, String> = rename.into_iter().collect();
        check_args("container_archive_put", &(name, path, &rename))?;
        let archive = vec![body_pipe(body)?];
        raw_call!(
            self,
            container_archive_put(name, path, rename, chown, overwrite_dir_non_dir, archive)
        )
        .map(|_| ())
    }

    /// The root file system of a container as a tar, as it comes.
    pub async fn container_export(&self, name: &str) -> ApiResult<Body> {
        let (reply, fds) = fds_call!(self, container_export(name));
        reply.map_err(failed)?;
        downloaded(fds)
    }

    /// Search registries for `term`.
    #[allow(
        clippy::too_many_arguments,
        reason = "one argument for each parameter of the search"
    )]
    pub async fn image_search(
        &self,
        term: &str,
        limit: u32,
        filters: Vec<String>,
        list_tags: bool,
        tls_verify: Option<bool>,
        access: &RegistryAccess,
    ) -> ApiResult<Vec<SearchHit>> {
        check_args("image_search", &(term, &filters))?;
        let (at, fds) = access_memfd(access)?;
        raw_call!(
            self,
            image_search(term, limit, filters, list_tags, tls_verify, at, fds)
        )
        .map(|r| r.hits)
    }

    /// The archive of images, as it comes.
    pub async fn image_save(&self, names: Vec<String>) -> ApiResult<Body> {
        use tokio::io::AsyncReadExt;
        let spec = PushSpec {
            images: names,
            destination: Some("oci-archive:save".into()),
            destination_fd: Some(0),
            ..Default::default()
        };
        check_args("image_push", &(&spec,))?;
        let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)
            .map_err(|e| ApiError::internal(format!("cannot make a pipe: {e}")))?;
        let _ = rustix::pipe::fcntl_setpipe_size(&write, 1 << 20);
        let mut reader = tokio::net::unix::pipe::Receiver::from_owned_fd(read)
            .map_err(|e| ApiError::internal(format!("the archive: {e}")))?;
        let mut conn = self.conn().await?;
        let mut saved = tokio::spawn(async move {
            use ::velarx_proto::engine::EngineProxy as _;
            let reply = conn
                .image_push(spec, None, vec![write])
                .await
                .map_err(protocol)?;
            conn.answered();
            reply.map(|_| ()).map_err(failed)
        });
        // An answer before the first byte is the call's: an image that is not
        // there is a 404, not a body that ends in an error.
        let mut first = vec![0u8; 1 << 16];
        let n = tokio::select! {
            done = &mut saved => {
                done.map_err(|e| ApiError::internal(format!("the save: {e}")))??;
                saved = tokio::spawn(async { Ok(()) });
                0
            }
            n = reader.read(&mut first) => {
                let n = n.map_err(|e| ApiError::internal(format!("the archive: {e}")))?;
                if n == 0 {
                    // (the engine closed its end: it has answered)
                    (&mut saved)
                        .await
                        .map_err(|e| ApiError::internal(format!("the save: {e}")))??;
                    saved = tokio::spawn(async { Ok(()) });
                }
                n
            }
        };
        first.truncate(n);
        // (an error in the middle of the archive is a read error of the body)
        Ok(Body::from_stream(futures::stream::unfold(
            Some((reader, saved, bytes::Bytes::from(first))),
            |state| async move {
                let (mut r, saved, first) = state?;
                if !first.is_empty() {
                    return Some((Ok(first), Some((r, saved, bytes::Bytes::new()))));
                }
                let mut buf = vec![0u8; 1 << 16];
                match r.read(&mut buf).await {
                    Ok(0) => match saved.await {
                        Ok(Ok(())) => None,
                        Ok(Err(e)) => Some((Err(std::io::Error::other(e.to_string())), None)),
                        Err(e) => Some((Err(std::io::Error::other(e.to_string())), None)),
                    },
                    Ok(n) => {
                        buf.truncate(n);
                        Some((
                            Ok(bytes::Bytes::from(buf)),
                            Some((r, saved, bytes::Bytes::new())),
                        ))
                    }
                    Err(e) => Some((Err(e), None)),
                }
            },
        )))
    }

    /// Load the images of the archive `body`: their names.
    pub async fn image_load(&self, platform: Option<&str>, body: Body) -> ApiResult<Vec<String>> {
        let spec = PullSpec {
            source: "archive:".into(),
            source_fd: Some(0),
            platform: PlatformSpec {
                platform: platform.map(str::to_string),
                ..Default::default()
            },
            tls_verify: true,
            ..Default::default()
        };
        check_args("image_load", &(&spec,))?;
        let archive = vec![body_pipe(body)?];
        raw_call!(self, image_pull(spec, None, archive))
            .map(|r| loaded_names(r.images.unwrap_or_default()))
    }

    /// Load the images of the archive at `path` of the host of the engine
    /// (podman's local API): their names.
    pub async fn image_load_local(&self, path: &str) -> ApiResult<Vec<String>> {
        let spec = PullSpec {
            source: format!("archive:{path}"),
            tls_verify: true,
            ..Default::default()
        };
        check_args("image_load_local", &(&spec,))?;
        raw_call!(self, image_pull(spec, None, Vec::new()))
            .map(|r| loaded_names(r.images.unwrap_or_default()))
    }

    /// Create an image from a tar: `body`, or what `spec.url` has.
    pub async fn image_import(&self, spec: ImportSpec, body: Option<Body>) -> ApiResult<String> {
        check_args("image_import", &(&spec,))?;
        let archive = body.map(body_pipe).transpose()?.into_iter().collect();
        raw_call!(self, image_import(spec, archive)).map(|r| r.id)
    }

    /// The changes of a container as a new image: its id.  With `in_band`
    /// a commit the engine tried and that failed is its message (libpod's
    /// stream says it in its body); a container that is not there, a
    /// format the engine does not take and an engine that does not answer
    /// stay errors of the answer.
    pub async fn container_commit(
        &self,
        spec: CommitSpec,
        config: Option<serde_json::Value>,
        in_band: bool,
    ) -> ApiResult<Result<String, String>> {
        check_args("container_commit", &(&spec,))?;
        let (length, pipe) = json_pipe(config)?;
        let mut conn = self.conn().await?;
        match conn
            .container_commit(spec, length, pipe)
            .await
            .map_err(protocol)?
        {
            Ok(Committed { id: Some(id), .. }) => Ok(Ok(id)),
            Ok(_) => Err(ApiError::internal("the engine committed no image")),
            Err(e) if in_band && tried(&e) => Ok(Err(e.message().to_string())),
            Err(e) => Err(failed(e)),
        }
    }

    /// Pull an image: the replies of the engine as they come (the progress,
    /// then what was pulled), until the last or an error.  The pull stops
    /// when the receiver is dropped.
    pub async fn image_pull(
        &self,
        spec: PullSpec,
        access: &RegistryAccess,
    ) -> ApiResult<tokio::sync::mpsc::Receiver<ApiResult<Pulled>>> {
        let (at, fds) = access_memfd(access)?;
        replies_call!(self, image_pull_progress(spec, at, fds), &(&spec, at))
    }

    /// Push an image: the replies of the engine as they come (where it
    /// goes, the progress, then what was pushed), until the last or an
    /// error.  The push stops when the receiver is dropped.
    pub async fn image_push(
        &self,
        spec: PushSpec,
        access: &RegistryAccess,
    ) -> ApiResult<tokio::sync::mpsc::Receiver<ApiResult<Pushed>>> {
        let (at, fds) = access_memfd(access)?;
        replies_call!(self, image_push_progress(spec, at, fds), &(&spec, at))
    }

    /// Add the file `body` to an artifact: the digest of the artifact.
    pub async fn artifact_add(&self, spec: ArtifactAddSpec, body: Body) -> ApiResult<String> {
        check_args("artifact_add", &(&spec,))?;
        let file = vec![body_pipe(body)?];
        raw_call!(self, artifact_add(spec, Some(0), None, file)).map(|r| r.id)
    }

    /// Add the file at `path` of the host of the engine to an artifact (podman's
    /// local API): the digest of the artifact.
    pub async fn artifact_add_local(&self, spec: ArtifactAddSpec, path: &str) -> ApiResult<String> {
        check_args("artifact_add_local", &(&spec, path))?;
        raw_call!(self, artifact_add(spec, None, Some(path), Vec::new())).map(|r| r.id)
    }

    /// Pull (`push`: push) an artifact: its digest.
    pub async fn artifact_transfer(
        &self,
        push: bool,
        name: &str,
        tls_verify: bool,
        retry: Retry,
        access: &RegistryAccess,
    ) -> ApiResult<String> {
        if push {
            let spec = PushSpec {
                images: vec![name.to_string()],
                artifact: true,
                tls_verify,
                retry,
                ..Default::default()
            };
            self.image_push_done(spec, access).await
        } else {
            let (at, fds) = access_memfd(access)?;
            let spec = PullSpec {
                source: name.to_string(),
                artifact: true,
                tls_verify,
                retry,
                ..Default::default()
            };
            check_args("artifact_pull", &(&spec,))?;
            raw_call!(self, image_pull(spec, at, fds)).map(|r| r.id.unwrap_or_default())
        }
    }

    /// A tar of the blobs of an artifact, as it comes.
    pub async fn artifact_extract(
        &self,
        name: &str,
        digest: Option<&str>,
        title: Option<&str>,
        by_digest: bool,
    ) -> ApiResult<Body> {
        let (reply, fds) = fds_call!(self, artifact_extract(name, digest, title, by_digest));
        reply.map_err(failed)?;
        downloaded(fds)
    }

    /// Make a manifest list.
    #[allow(
        clippy::too_many_arguments,
        reason = "one argument for each parameter of the call"
    )]
    pub async fn manifest_create(
        &self,
        name: &str,
        images: Vec<String>,
        amend: bool,
        all: bool,
        tls_verify: bool,
        annotations: BTreeMap<String, String>,
        instance: InstanceSpec,
        subject: Option<String>,
        access: &RegistryAccess,
    ) -> ApiResult<String> {
        let (at, fds) = access_memfd(access)?;
        check_args(
            "manifest_create",
            &(name, &images, &annotations, &instance, &subject),
        )?;
        raw_call!(
            self,
            manifest_create(
                name,
                images,
                amend,
                all,
                tls_verify,
                annotations,
                instance,
                subject,
                None,
                at,
                fds
            )
        )
        .map(|r| r.id)
    }

    /// A manifest list as OCI's index.
    pub async fn manifest_inspect(
        &self,
        name: &str,
        tls_verify: bool,
        access: &RegistryAccess,
    ) -> ApiResult<ManifestListRecord> {
        let (at, fds) = access_memfd(access)?;
        check_args("manifest_inspect", &(name,))?;
        raw_call!(self, manifest_inspect(name, tls_verify, at, fds))
    }

    /// Add images to a list: its id.
    pub async fn manifest_add_images(
        &self,
        name: &str,
        images: Vec<String>,
        all: bool,
        instance: InstanceSpec,
        tls_verify: bool,
        access: &RegistryAccess,
    ) -> ApiResult<String> {
        let (at, fds) = access_memfd(access)?;
        check_args("manifest_add_images", &(name, &images, &instance))?;
        raw_call!(
            self,
            manifest_add_images(name, images, all, instance, tls_verify, at, fds)
        )
        .map(|r| r.id)
    }

    /// Annotate an instance of a list, or the list: its id.
    pub async fn manifest_annotate(
        &self,
        name: &str,
        instance: Option<String>,
        spec: InstanceSpec,
        index_annotations: BTreeMap<String, String>,
        subject: Option<String>,
    ) -> ApiResult<String> {
        engine_call!(
            self,
            manifest_annotate(name, instance, spec, index_annotations, subject)
        )
        .map(|r| r.id)
    }

    /// Add an artifact of `files` (one descriptor for each title of the
    /// spec) to a list: its digest.
    pub async fn manifest_add_artifact(
        &self,
        name: &str,
        spec: ManifestArtifactSpec,
        tls_verify: bool,
        access: &RegistryAccess,
        files: Vec<OwnedFd>,
    ) -> ApiResult<String> {
        let (length, mut pipes) = access_memfd(access)?;
        pipes.extend(files);
        check_args("manifest_add_artifact", &(name, &spec))?;
        raw_call!(
            self,
            manifest_add_artifact(name, spec, tls_verify, length, pipes)
        )
        .map(|r| r.id)
    }

    /// Push a manifest list: the digest.
    pub async fn manifest_push(
        &self,
        name: &str,
        destination: &str,
        all: bool,
        tls_verify: bool,
        compression: Option<LayerCompression>,
        access: &RegistryAccess,
    ) -> ApiResult<String> {
        let spec = PushSpec {
            images: vec![name.to_string()],
            destination: Some(destination.to_string()),
            all,
            tls_verify,
            compression,
            ..Default::default()
        };
        self.image_push_done(spec, access).await
    }

    /// An `ImagePush` made to its end: the digest of what was pushed.
    async fn image_push_done(&self, spec: PushSpec, access: &RegistryAccess) -> ApiResult<String> {
        let mut replies = self.image_push(spec, access).await?;
        let mut digest = None;
        while let Some(reply) = replies.recv().await {
            if let Some(pushed) = reply?.pushed {
                digest = Some(pushed.digest);
            }
        }
        digest.ok_or_else(|| ApiError::internal("the engine ended the push"))
    }

    /// Create a secret from its data: its id.  The data goes through a pipe
    /// (no base64, and a message of that size would cost much more than its
    /// bytes).
    pub async fn secret_create(&self, secret: NewSecret<'_>) -> ApiResult<String> {
        let NewSecret {
            name,
            data,
            driver,
            driver_opts,
            labels,
            replace,
            ignore,
        } = secret;
        check_args(
            "secret_create",
            &(name, driver, &driver_opts, &labels, replace, ignore),
        )?;
        let data = velarx_base::sealed::sealed_memory(&data)
            .map_err(|e| ApiError::internal(format!("the secret data: {e}")))?;
        raw_call!(
            self,
            secret_create(
                name,
                driver,
                driver_opts,
                labels,
                replace,
                ignore,
                0,
                vec![data]
            )
        )
        .map(|r| r.id)
    }

    pub async fn secret_list(&self, filters: &Filters) -> ApiResult<Vec<SecretRecord>> {
        let filters = filters_of(filters);
        list_call!(
            self,
            secret_list(filters),
            |r: SecretListed| r.secret,
            filter_failed
        )
    }

    /// A secret; with `show_data`, with its data (read from the pipe of
    /// the reply: it never crosses in the JSON, which the protocol logs at
    /// trace level).
    pub async fn secret_inspect(&self, name: &str, show_data: bool) -> ApiResult<SecretRecord> {
        let (reply, fds) = fds_call!(self, secret_inspect(name, show_data));
        let reply = reply.map_err(failed)?;
        let mut secret = reply.secret;
        if let Some(i) = reply.data {
            let fd = connect::take_fd(fds, i)
                .ok_or_else(|| ApiError::internal("the engine named a file it did not send"))?;
            let max = crate::podman::secrets::SECRET_MAX_SIZE as u64;
            let data = velarx_base::sealed::read_sealed_whole(&std::fs::File::from(fd), max)
                .map_err(|why| ApiError::internal(format!("the data of the secret {why}")))?;
            secret.data = Some(data);
        }
        Ok(secret)
    }

    /// Create a pod from the body of the request: its id.  The body goes
    /// through a pipe (a varlink message of that size would cost much more
    /// than its bytes, as [`velarx_proto::INLINE_MAX`] says).
    pub async fn pod_create(&self, spec: bytes::Bytes) -> ApiResult<String> {
        let read = filled_pipe(spec)?;
        raw_call!(self, pod_create(0, vec![read])).map(|r| r.id)
    }

    /// The pods `filters` select.
    pub async fn pod_list(&self, filters: &Filters) -> ApiResult<Vec<PodRecord>> {
        let filters = filters_of(filters);
        // (podman's pod list says 400 for a filter it does not take)
        list_call!(self, pod_list(filters), |r: PodListed| r.pod, failed)
    }

    /// Apply the operation to the pod: its id and the errors of its
    /// containers, none when the pod is already as asked.  `verify_image`:
    /// the digests typed on a start or a restart.
    pub async fn pod_run(
        &self,
        name: &str,
        op: &str,
        timeout: Option<u64>,
        signal: Option<&str>,
        verify_image: &[String],
    ) -> ApiResult<Option<(String, Vec<String>)>> {
        let op = PodAction::of_word(op)
            .ok_or_else(|| ApiError::bad_request(format!("{op:?} is not an action of a pod")))?;
        engine_call!(
            self,
            pod_run(
                name,
                op,
                timeout,
                signal,
                verify_image.to_vec(),
                None::<bool>
            )
        )
        .map(|r| r.changed.then_some((r.id, r.errors)))
    }

    pub async fn artifact_list(&self) -> ApiResult<Vec<ArtifactRecord>> {
        list_call!(
            self,
            artifact_list(),
            |r: ArtifactListed| r.artifact,
            failed
        )
    }

    /// The containers the filters select (see `ContainerList`).
    pub async fn container_list(
        &self,
        filters: &Filters,
        all: bool,
        size: bool,
        namespace: bool,
        limit: i64,
    ) -> ApiResult<Vec<ContainerRecord>> {
        let filters = filters_of(filters);
        list_call!(
            self,
            container_list(filters, all, size, namespace, limit),
            |r: ContainerListed| r.container,
            filter_failed
        )
    }

    /// The images the filters select, the oldest first: with `all` the
    /// intermediate images too, with `manifest_lists` the manifest lists.
    pub async fn image_list(
        &self,
        filters: &Filters,
        all: bool,
        manifest_lists: bool,
    ) -> ApiResult<Vec<ImageRecord>> {
        let filters = filters_of(filters);
        list_call!(
            self,
            image_list(filters, all, manifest_lists),
            |r: ImageListed| r.image,
            filter_failed
        )
    }
}

/// The names of the images an archive loaded, their ids when they have
/// none (podman's answer).
pub(crate) fn loaded_names(images: Vec<PulledImage>) -> Vec<String> {
    images
        .into_iter()
        .flat_map(|i| {
            if i.names.is_empty() {
                vec![i.id]
            } else {
                i.names
            }
        })
        .collect()
}

/// A stream the engine opened: the read end of its pipe.  Nothing times it
/// out (a follow may be idle for hours, unlike the document of a call): it
/// ends when the engine closes its end, and the engine stops when this one
/// is dropped, as it is when the client of the response goes away.
pub struct Streamed {
    reader: tokio::net::unix::pipe::Receiver,
    /// The frames of the stream are not wanted (Docker's logs of a
    /// container with a terminal)
    pub tty: bool,
}

fn streamed(stream: Stream, fds: Vec<OwnedFd>) -> ApiResult<Streamed> {
    let fd = connect::take_fd(fds, 0)
        .ok_or_else(|| ApiError::internal("the engine opened a stream with no pipe"))?;
    let reader = tokio::net::unix::pipe::Receiver::from_owned_fd(fd)
        .map_err(|e| ApiError::internal(format!("the stream of the engine: {e}")))?;
    Ok(Streamed {
        reader,
        tty: stream.tty,
    })
}

impl Streamed {
    /// What the engine writes, as the body of the answer.
    pub fn body(self) -> Body {
        self.shaped(Shape::Raw)
    }

    /// The events of a build the engine writes (a `BuildEvent` each line),
    /// as the lines of podman's or Docker's answer.
    pub fn build_body(self, lines: velarx_shape::build::BuildLines) -> Body {
        self.shaped(Shape::Build(lines, Vec::new()))
    }

    /// The data of the frames of Docker's multiplexed stream the engine
    /// writes, as the body of the answer.
    pub fn unframed_body(self) -> Body {
        self.shaped(Shape::Unframed(Unframe::default()))
    }

    fn shaped(self, shape: Shape) -> Body {
        use tokio::io::AsyncReadExt;
        let state = (self.reader, shape);
        Body::from_stream(futures::stream::unfold(
            state,
            |(mut r, mut shape)| async move {
                loop {
                    let mut buf = bytes::BytesMut::with_capacity(32 * 1024);
                    match r.read_buf(&mut buf).await {
                        Ok(n) if n > 0 => {
                            let data = shape.push(buf);
                            if !data.is_empty() {
                                return Some((Ok::<_, std::io::Error>(data), (r, shape)));
                            }
                        }
                        _ => return None,
                    }
                }
            },
        ))
    }
}

/// What a stream of the engine is in the body of the answer.
enum Shape {
    /// The bytes as they are
    Raw,
    /// The data of Docker's frames
    Unframed(Unframe),
    /// The lines of a build's answer, and what came of a line that is not
    /// whole yet
    Build(velarx_shape::build::BuildLines, Vec<u8>),
}

impl Shape {
    /// What the body gets of `buf`, the next bytes of the stream.
    fn push(&mut self, buf: bytes::BytesMut) -> bytes::Bytes {
        match self {
            Shape::Raw => buf.freeze(),
            Shape::Unframed(unframe) => unframe.push(&buf),
            Shape::Build(lines, held) => {
                held.extend_from_slice(&buf);
                let Some(end) = held.iter().rposition(|&b| b == b'\n') else {
                    return bytes::Bytes::new();
                };
                let mut out = Vec::new();
                for line in held[..end].split(|&b| b == b'\n') {
                    lines.lay(line, &mut out);
                }
                held.drain(..=end);
                out.into()
            }
        }
    }
}

/// The data of the frames of Docker's multiplexed stream (a stream byte,
/// three zero bytes, the length big endian and the data), whatever the
/// pieces they arrive in.
#[derive(Default)]
struct Unframe {
    head: Vec<u8>,
    left: usize,
}

impl Unframe {
    fn push(&mut self, mut bytes: &[u8]) -> bytes::Bytes {
        let mut out = bytes::BytesMut::new();
        while !bytes.is_empty() {
            if self.left > 0 {
                let n = self.left.min(bytes.len());
                out.extend_from_slice(&bytes[..n]);
                self.left -= n;
                bytes = &bytes[n..];
                continue;
            }
            let want = 8 - self.head.len();
            let n = want.min(bytes.len());
            self.head.extend_from_slice(&bytes[..n]);
            bytes = &bytes[n..];
            if self.head.len() == 8 {
                self.left =
                    u32::from_be_bytes([self.head[4], self.head[5], self.head[6], self.head[7]])
                        as usize;
                self.head.clear();
            }
        }
        out.freeze()
    }
}

#[cfg(test)]
mod unframe_tests {
    use super::*;

    /// The events of a build are laid out by whole lines, whatever the
    /// pieces the pipe gives them in.
    #[test]
    fn the_lines_of_a_build_are_laid_out_whole() {
        let lines = velarx_shape::build::BuildLines {
            quiet: false,
            docker: false,
        };
        let events = b"{\"kind\":\"step\",\"text\":\"STEP 1/1: FROM x\"}\n{\"kind\":\"complete\",\"text\":\"ab\"}\n";
        let mut shape = Shape::Build(lines, Vec::new());
        let mut out = Vec::new();
        for piece in events.chunks(7) {
            out.extend_from_slice(&shape.push(bytes::BytesMut::from(piece)));
        }
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "{\"stream\":\"STEP 1/1: FROM x\\n\"}\n{\"stream\":\"ab\\n\"}\n"
        );
        assert!(matches!(shape, Shape::Build(_, held) if held.is_empty()));
    }

    fn frame(stream: u8, data: &[u8]) -> Vec<u8> {
        let mut v = vec![stream, 0, 0, 0];
        v.extend_from_slice(&(data.len() as u32).to_be_bytes());
        v.extend_from_slice(data);
        v
    }

    /// The engine refused the body (closed its end): the rest the client
    /// sends is read anyway, so that the client is not cut off half way.
    #[tokio::test]
    async fn the_body_the_engine_does_not_read_is_read_to_its_end() {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(1);
        let stream =
            futures::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|c| (c, rx)) });
        let read = body_pipe(Body::from_stream(stream)).unwrap();
        drop(read);
        for _ in 0..16 {
            tx.send(Ok(bytes::Bytes::from(vec![7u8; 64 << 10])))
                .await
                .expect("the body is still read");
        }
        drop(tx);
    }

    #[test]
    fn the_data_of_frames_in_any_pieces() {
        let mut all = frame(1, b"hello ");
        all.extend(frame(2, b""));
        all.extend(frame(2, b"world\n"));
        for size in [1, 2, 3, 7, 8, 9, 100] {
            let mut u = Unframe::default();
            let mut got = Vec::new();
            for piece in all.chunks(size) {
                got.extend_from_slice(&u.push(piece));
            }
            assert_eq!(got, b"hello world\n", "pieces of {size}");
        }
    }
}

/// The session of a process the engine opened (its streams come once the
/// process is there).
pub struct Hijacked(pub velarx_proto::stream::Session);

/// The spec of a build as the pipe of a call.
fn spec_pipe(spec: &BuildSpec) -> ApiResult<Vec<OwnedFd>> {
    let bytes = bytes::Bytes::from(serde_json::to_vec(spec)?);
    if bytes.len() > velarx_proto::build::MAX_BUILD_SPEC {
        return Err(ApiError::new(413, "the build request is too large"));
    }
    Ok(vec![filled_pipe(bytes)?])
}

/// The credentials of a call: [`RegistryAccess::sealed`].
fn access_memfd(access: &RegistryAccess) -> ApiResult<(Option<u32>, Vec<OwnedFd>)> {
    access
        .sealed()
        .map_err(|e| ApiError::new(500, format!("the credentials: {e}")))
}

/// The JSON document of a request (none: no pipe) as the pipe of a call, and
/// its position among the descriptors.
fn json_pipe(body: Option<serde_json::Value>) -> ApiResult<(Option<u32>, Vec<OwnedFd>)> {
    let Some(v) = body else {
        return Ok((None, Vec::new()));
    };
    let bytes = bytes::Bytes::from(serde_json::to_vec(&v)?);
    Ok((Some(0), vec![filled_pipe(bytes)?]))
}

/// The bytes of a download (the frames of the pipe of the reply), as the
/// body of the answer: a pipe that ends before the empty frame ends the body
/// with an error, so that the client does not take a part for the whole.
fn downloaded(fds: Vec<OwnedFd>) -> ApiResult<Body> {
    let fd = connect::take_fd(fds, 0)
        .ok_or_else(|| ApiError::internal("the engine sent a download with no pipe"))?;
    let reader = tokio::net::unix::pipe::Receiver::from_owned_fd(fd)
        .map_err(|e| ApiError::internal(format!("the download of the engine: {e}")))?;
    Ok(framed(reader))
}

/// The frames of the pipe `reader` as the body of an answer (see
/// [`downloaded`]).
fn framed(reader: tokio::net::unix::pipe::Receiver) -> Body {
    use tokio::io::AsyncReadExt;
    let cut = || {
        std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "the engine ended the download early",
        )
    };
    Body::from_stream(futures::stream::unfold(
        Some(reader),
        move |reader| async move {
            let mut r = reader?;
            let mut head = [0u8; 4];
            if r.read_exact(&mut head).await.is_err() {
                return Some((Err(cut()), None));
            }
            let n = u32::from_be_bytes(head) as usize;
            if n == 0 {
                return None;
            }
            if n > velarx_proto::build::MAX_CONTEXT_FRAME {
                let e = std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("the engine sent a frame of {n} bytes"),
                );
                return Some((Err(e), None));
            }
            let mut buf = vec![0u8; n];
            match r.read_exact(&mut buf).await {
                Ok(_) => Some((Ok(bytes::Bytes::from(buf)), Some(r))),
                Err(_) => Some((Err(cut()), None)),
            }
        },
    ))
}

/// A record or a list of records as the JSON body of an answer.
fn json_body<T: serde::Serialize>(value: &T) -> ApiResult<(Body, Option<u64>)> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    Ok((Body::from(bytes), None))
}

/// The body of a request as a pipe, filled as it arrives: nothing is held
/// but what the pipe has.  The body crosses in frames
/// ([`velarx_proto::build::MAX_CONTEXT_FRAME`]); its end is an empty
/// frame, which a client that goes away half way never sends.
fn body_pipe(body: Body) -> ApiResult<OwnedFd> {
    body_pump(body).map(|(read, _)| read)
}

/// The body of a build request.
pub enum Context {
    /// The tar of the context
    Body(Body),
    /// A multipart body (with its boundary): the main context and the named
    /// ones
    Sections(Body, String),
}

/// A multipart body as the sections of a pipe (see
/// [`velarx_proto::build::SECTION_MAIN`]), split as it arrives: no part is
/// held but the pipe's content.  The task ends when the body is over or the
/// engine closed its end.
fn sections_pump(
    body: Body,
    boundary: String,
) -> ApiResult<(OwnedFd, tokio::task::JoinHandle<()>)> {
    let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)
        .map_err(|e| ApiError::internal(format!("cannot make a pipe: {e}")))?;
    let _ = rustix::pipe::fcntl_setpipe_size(&write, 1 << 20);
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    // (it blocks on the pipe for as long as the engine reads slowly, and
    // ends when the body or the pipe does)
    tokio::task::spawn_blocking(move || {
        crate::podman::build::write_sections(
            crate::podman::multipart::Chunks::new(rx),
            &boundary,
            std::fs::File::from(write),
        )
    });
    let pump = tokio::spawn(async move {
        let mut chunks = body.into_data_stream();
        while let Some(Ok(chunk)) = chunks.next().await {
            if tx.send(chunk).await.is_err() {
                // (the engine stopped reading)
                drain(chunks).await;
                break;
            }
        }
        drop(tx);
    });
    Ok((read, pump))
}

/// [`body_pipe`] and the task that moves the body: it ends when the body is
/// over, or when the engine closed its end and the rest was drained.
fn body_pump(body: Body) -> ApiResult<(OwnedFd, tokio::task::JoinHandle<()>)> {
    let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)
        .map_err(|e| ApiError::internal(format!("cannot make a pipe: {e}")))?;
    let _ = rustix::pipe::fcntl_setpipe_size(&write, 1 << 20);
    let mut sender = tokio::net::unix::pipe::Sender::from_owned_fd(write)
        .map_err(|e| ApiError::internal(format!("cannot make a pipe: {e}")))?;
    let pump = tokio::spawn(async move {
        let mut chunks = body.into_data_stream();
        loop {
            // (the engine closed its end, 408 after ten minutes of nothing
            // or an error: no reason to wait for a client that has nothing
            // more to send)
            let next = tokio::select! {
                next = chunks.next() => next,
                _ = sender.ready(tokio::io::Interest::ERROR) => {
                    drain(chunks).await;
                    return;
                }
            };
            let chunk = match next {
                Some(Ok(chunk)) => chunk,
                // (the end: the empty frame)
                None => {
                    let _ = write_frame(&mut sender, &[]).await;
                    return;
                }
                // (the client went away: no end frame)
                Some(Err(_)) => return,
            };
            for part in chunk.chunks(velarx_proto::build::MAX_CONTEXT_FRAME) {
                if write_frame(&mut sender, part).await.is_err() {
                    // (the engine stopped reading)
                    drain(chunks).await;
                    return;
                }
            }
        }
    });
    Ok((read, pump))
}

/// The rest of a body the engine will not read (it refused the request):
/// read and dropped, up to a bound, so that the client that still sends it
/// reads the answer instead of a connection closed under its upload.  A
/// client that sends nothing for [`DRAIN_IDLE`] is not waited for: the task
/// ends (it would hold the body for ever).
async fn drain(mut chunks: axum::body::BodyDataStream) {
    const MAX_DRAINED: usize = 64 << 20;
    let mut drained = 0;
    while let Ok(Some(Ok(chunk))) = tokio::time::timeout(DRAIN_IDLE, chunks.next()).await {
        drained += chunk.len();
        if drained > MAX_DRAINED {
            return;
        }
    }
}

/// How long the rest of a refused body is read while its client sends
/// nothing.
const DRAIN_IDLE: std::time::Duration = std::time::Duration::from_secs(5);

async fn write_frame(
    sender: &mut tokio::net::unix::pipe::Sender,
    data: &[u8],
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    sender.write_all(&(data.len() as u32).to_be_bytes()).await?;
    sender.write_all(data).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The engine gave the upload up (its end of the pipe is closed): the
    /// task that pumps the body ends once its client sent nothing for
    /// `DRAIN_IDLE`, not on the next chunk of a client that sends nothing.
    #[tokio::test(start_paused = true)]
    async fn the_pump_of_a_body_ends_when_the_engine_closes_its_end() {
        // (dropped with the body, when the pump ends)
        let (guard, dropped) = tokio::sync::oneshot::channel::<()>();
        let body = Body::from_stream(
            futures::stream::pending::<std::io::Result<bytes::Bytes>>().map(move |chunk| {
                let _ = &guard;
                chunk
            }),
        );
        let read = body_pipe(body).unwrap();
        drop(read);
        let ended = tokio::time::timeout(std::time::Duration::from_secs(30), dropped).await;
        assert!(matches!(ended, Ok(Err(_))), "the pump is still waiting");
    }
}
