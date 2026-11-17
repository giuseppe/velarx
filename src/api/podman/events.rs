// SPDX-License-Identifier: Apache-2.0
//! The events: kept in memory (the last [`HISTORY`]) and in the backend of
//! the configuration, and sent to the clients of `EventList` as records
//! (velarx-shape lays out podman's and Docker's documents of them).

use super::call::Filters;
use super::error::{ApiError, ApiResult};
use crate::api::AppState;
use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use velarx_proto::workload::EventKind;
pub use velarx_wire::events::{now_nanos, Event};

/// Events kept for the clients that ask for the history.
const HISTORY: usize = 4096;

pub struct EventHub {
    inner: Mutex<Inner>,
    tx: broadcast::Sender<Arc<Event>>,
    /// Where the events are kept beyond the memory of this process.
    log: std::sync::OnceLock<velarx_wire::events::log::EventLog>,
}

struct Inner {
    next: u64,
    history: VecDeque<Arc<Event>>,
}

impl Default for EventHub {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner {
                next: 1,
                history: VecDeque::new(),
            }),
            tx: broadcast::channel(1024).0,
            log: std::sync::OnceLock::new(),
        }
    }
}

impl EventHub {
    /// Keep the events in `log` too (the first call decides).
    /// The name of the backend that keeps the events (`memory` when none
    /// does: they are in the memory of the server only).
    pub fn logger_name(&self) -> &'static str {
        self.log.get().map_or("memory", |l| l.name())
    }

    /// Whether a backend keeps the events beyond the memory of this process.
    fn keeps(&self) -> bool {
        self.log
            .get()
            .is_some_and(|l| !matches!(l, velarx_wire::events::log::EventLog::None))
    }

    /// A watch of the places where the events are kept.
    pub fn watch(&self) -> std::io::Result<super::eventlog::ChangeWatch> {
        let dirs = self.log.get().map(|l| l.watch_dirs()).unwrap_or_default();
        super::eventlog::ChangeWatch::new(&dirs)
    }

    pub fn set_log(&self, log: velarx_wire::events::log::EventLog) {
        let _ = self.log.set(log);
    }

    pub fn emit(&self, ev: Event) {
        if let Some(log) = self.log.get() {
            crate::api::blocking(|| {
                if let Err(e) = log.write(&ev) {
                    tracing::debug!(
                        "Cannot keep the event {} {}: {e}",
                        ev.kind.word(),
                        ev.action
                    );
                }
            });
        }
        self.emit_live(ev);
    }

    /// Tell the clients of this process an event that the backend has: the
    /// monitor of its container wrote it.
    pub fn emit_live(&self, mut ev: Event) {
        let ev = {
            let mut g = match self.inner.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            ev.seq = g.next;
            g.next += 1;
            let ev = Arc::new(ev);
            if g.history.len() == HISTORY {
                g.history.pop_front();
            }
            g.history.push_back(ev.clone());
            // sent under the lock: subscribers see the events in order
            let _ = self.tx.send(ev.clone());
            ev
        };
        drop(ev);
    }

    /// The history and a receiver of what follows it.
    fn subscribe(&self) -> (Vec<Arc<Event>>, broadcast::Receiver<Arc<Event>>) {
        let g = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        (g.history.iter().cloned().collect(), self.tx.subscribe())
    }

    /// The events kept by the backend between `since` and `until`, those of
    /// other processes and earlier servers too; `None` without a backend.
    async fn kept(&self, since: Option<i64>, until: Option<i64>) -> Option<Vec<Arc<Event>>> {
        let log = self.log.get()?;
        match super::eventlog::read(log, since, until).await {
            Ok(Some(stored)) => Some(
                stored
                    .into_iter()
                    .map(|s| Arc::new(from_stored(s)))
                    .collect(),
            ),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!("Cannot read the events kept: {e}");
                None
            }
        }
    }
}

/// An event read back from its backend.
fn from_stored(s: velarx_wire::events::log::Stored) -> Event {
    let kind = EventKind::of_word(&s.kind).unwrap_or(EventKind::System);
    Event {
        seq: 0,
        kind,
        action: s.action,
        id: s.id,
        name: s.name,
        image: s.image,
        attributes: s.attributes,
        time_nano: s.time_nano,
    }
}

/// The `until` of a filter (containers, pods, volumes, networks, prune), as
/// Docker's `GetTimestamp` that podman uses for them reads it: a time (RFC
/// 3339, a date, unix seconds with a fraction) or a Go duration before now;
/// empty is the epoch.  Unlike the times of the events, seconds have no sign
/// and no exponent (`-5`, `1e3`: podman refuses them here).
pub fn parse_since(s: &str) -> Option<i64> {
    if s.is_empty() {
        return Some(0);
    }
    if s.parse::<f64>().is_ok() && !s.bytes().all(|c| c.is_ascii_digit() || c == b'.') {
        return None;
    }
    velarx_proto::time::parse_input_time(s, now_nanos(), velarx_proto::time::Toward::Past, false)
}

fn name_or_id_matches(value: &str, name: &str, id: &str) -> bool {
    value == name || (!value.is_empty() && id.starts_with(value))
}

fn filter_value_matches(key: &str, value: &str, ev: &Event) -> bool {
    match key {
        "type" => ev.kind.word() == value,
        // Docker's status is podman's event
        "event" | "status" => {
            ev.action == value
                || (value == "die" && ev.action == "died")
                || (value == "died" && ev.action == "die")
                || (value == "delete" && ev.kind == EventKind::Image && ev.action == "remove")
        }
        "container" | "volume" | "network" | "pod" | "artifact" => {
            if key == "pod" && ev.kind != EventKind::Pod {
                return ev
                    .attributes
                    .get("podId")
                    .is_some_and(|p| name_or_id_matches(value, "", p));
            }
            // a volume by a prefix of its name, as podman
            if key == "volume" {
                return ev.kind == EventKind::Volume
                    && (ev.name.starts_with(value) || ev.id.starts_with(value));
            }
            ev.kind.word() == key && name_or_id_matches(value, &ev.name, &ev.id)
        }
        "image" => {
            if ev.kind == EventKind::Image {
                name_or_id_matches(value, &ev.name, &ev.id)
            } else {
                !ev.image.is_empty() && ev.image.starts_with(value)
            }
        }
        "label" => {
            let (k, v) = value
                .split_once('=')
                .map_or((value, None), |(k, v)| (k, Some(v)));
            ev.attributes
                .get(k)
                .is_some_and(|a| v.is_none_or(|v| v == a))
        }
        _ => true,
    }
}

pub fn filters_match(filters: &Filters, ev: &Event) -> bool {
    for (key, values) in &filters.0 {
        if key == "since" || key == "until" || values.is_empty() {
            continue;
        }
        if !values.iter().any(|v| filter_value_matches(key, v, ev)) {
            return false;
        }
    }
    true
}

/// What a request for events asked.
pub struct EventsQuery {
    pub filters: Filters,
    /// The events that happen are sent too, until `until`
    pub stream: bool,
    /// A follow reads what the backend keeps, where every engine of the
    /// store writes, not the memory of this process: for an engine that is
    /// not the one every command goes through (the engine of a command).  A
    /// daemon, which sees what the commands do, follows its memory.
    pub follow_kept: bool,
}

/// The events of a request, ready to be sent.
pub struct EventsRun {
    q: EventsQuery,
    since: Option<i64>,
    until: Option<i64>,
    history: Vec<Arc<Event>>,
    rx: broadcast::Receiver<Arc<Event>>,
    kept_until: Option<i64>,
    /// A follow of the events a backend keeps reads them there (see
    /// [`EventsRun::deliver`]): the state that has the backend.
    follows_kept: Option<Arc<AppState>>,
}

/// Check the query and take the history (the errors before the stream),
/// from `since` to `until` (nanoseconds since the epoch).
pub async fn events_of(
    state: &Arc<AppState>,
    q: EventsQuery,
    since: Option<i64>,
    until: Option<i64>,
) -> ApiResult<EventsRun> {
    check_filters(&q.filters)?;
    // A follow of the engine of a command reads what the backend keeps,
    // where every engine of the store writes (this one, the other commands',
    // the monitors'): the memory of this process has this engine's events
    // only.
    if q.stream && q.follow_kept && state.podman.events.keeps() {
        let (_, rx) = state.podman.events.subscribe();
        return Ok(EventsRun {
            q,
            // (without `since`: what happens from the call on)
            since: Some(since.unwrap_or_else(now_nanos)),
            until,
            history: Vec::new(),
            rx,
            kept_until: None,
            follows_kept: Some(state.clone()),
        });
    }
    let (mut history, rx) = state.podman.events.subscribe();
    // What the backend keeps outlives this server: the history comes from
    // it.  A live event already in it is not sent twice.
    let mut kept_until = None;
    if since.is_some() || !q.stream {
        if let Some(kept) = state.podman.events.kept(since, until).await {
            kept_until = kept.last().map(|e| e.time_nano);
            history = kept;
        }
    }
    Ok(EventsRun {
        q,
        since,
        until,
        history,
        rx,
        kept_until,
        follows_kept: None,
    })
}

/// The filters of a request for events are those of the API.
fn check_filters(filters: &Filters) -> ApiResult<()> {
    if let Some(k) = filters.keys().find(|k| {
        !matches!(
            *k,
            "container"
                | "event"
                | "status"
                | "image"
                | "artifact"
                | "pod"
                | "network"
                | "volume"
                | "type"
                | "label"
                | "since"
                | "until"
        )
    }) {
        return Err(ApiError::bad_request(format!(
            "failed to parse event filters: {k} is an invalid filter"
        )));
    }
    Ok(())
}

/// Where the events of a request go.
#[allow(async_fn_in_trait, reason = "its implementations are of this crate")]
pub trait EventOut {
    /// Send `ev`: false once the reader went away.
    async fn send(&mut self, ev: &Event) -> bool;
    /// `f`, unless the reader goes away first.
    async fn while_there<T>(&self, f: impl Future<Output = T>) -> Option<T>;
}

/// The events kept after `pos` (see [`velarx_wire::events::log::EventLog::read_after`])
/// that `filters` select, up to `until`, and where the next read starts;
/// `None` when no backend keeps them.
async fn read_kept_after(
    state: &Arc<AppState>,
    filters: &Filters,
    since: Option<i64>,
    until: Option<i64>,
    mut pos: velarx_wire::events::log::Position,
) -> ApiResult<Option<(Vec<Event>, velarx_wire::events::log::Position)>> {
    let Some(log) = state.podman.events.log.get() else {
        return Ok(None);
    };
    let Some(kept) = super::eventlog::read_after(log, since, &mut pos)
        .await
        .map_err(|e| ApiError::internal(format!("cannot read the events kept: {e}")))?
    else {
        return Ok(None);
    };
    let events = kept
        .into_iter()
        .map(from_stored)
        .filter(|ev| until.is_none_or(|u| ev.time_nano <= u) && filters_match(filters, ev))
        .collect();
    Ok(Some((events, pos)))
}

impl EventsRun {
    /// Send the events to `out` until the end of the query or the client's;
    /// the error of a follow that cannot read the events kept any more.
    pub async fn deliver(self, mut out: impl EventOut) -> ApiResult<()> {
        let Self {
            q,
            since,
            until,
            history,
            mut rx,
            kept_until,
            follows_kept,
        } = self;
        let stream = q.stream;
        let filters = q.filters;
        if let Some(state) = follows_kept {
            return deliver_kept(&state, &filters, since, until, out).await;
        }
        let mut last_seq = 0;
        let want = |ev: &Event| {
            since.is_none_or(|s| ev.time_nano >= s)
                && until.is_none_or(|u| ev.time_nano <= u)
                && filters_match(&filters, ev)
        };
        // Without `since` a streaming client gets what happens from now on.
        if since.is_some() || !stream {
            for ev in &history {
                last_seq = ev.seq;
                if want(ev) && !out.send(ev).await {
                    return Ok(());
                }
            }
        } else if let Some(last) = history.last() {
            last_seq = last.seq;
        }
        if !stream {
            return Ok(());
        }
        let deadline = until.map(|u| {
            let ahead = (u - now_nanos()).max(0) as u64;
            tokio::time::Instant::now() + std::time::Duration::from_nanos(ahead)
        });
        loop {
            let next = async {
                match rx.recv().await {
                    Ok(ev) => Some(ev),
                    Err(broadcast::error::RecvError::Lagged(_)) => Some(Arc::new(lagged())),
                    Err(broadcast::error::RecvError::Closed) => None,
                }
            };
            // (idle for as long as nothing happens: only the end of the
            // reader or the time limit stops it)
            let waited = out.while_there(async {
                match deadline {
                    Some(d) => tokio::time::timeout_at(d, next).await.ok().flatten(),
                    None => next.await,
                }
            });
            let Some(Some(ev)) = waited.await else {
                return Ok(());
            };
            if ev.seq <= last_seq || kept_until.is_some_and(|t| ev.time_nano <= t) {
                continue;
            }
            last_seq = ev.seq;
            if want(&ev) && !out.send(&ev).await {
                return Ok(());
            }
        }
    }
}

/// The events a backend keeps that `filters` select, from `since` to
/// `until`, then those kept as they come, until `until` or the reader goes: a
/// read of what was kept after the last, when something is written where
/// they are kept (the journal's cursor, the offset in the file).  An event of
/// another process kept after a later one (its time is taken before it is
/// written) is sent by the read after its write, and none twice.
async fn deliver_kept(
    state: &Arc<AppState>,
    filters: &Filters,
    since: Option<i64>,
    until: Option<i64>,
    mut out: impl EventOut,
) -> ApiResult<()> {
    let mut pos = velarx_wire::events::log::Position::default();
    let mut warned = false;
    loop {
        // (armed before the read: what is kept after it wakes the wait)
        let watch = state.podman.events.watch();
        let Some((events, next)) = read_kept_after(state, filters, since, until, pos).await? else {
            return Ok(());
        };
        pos = next;
        for ev in &events {
            if !out.send(ev).await {
                return Ok(());
            }
        }
        let left = until
            .map(|u| std::time::Duration::from_nanos(u.saturating_sub(now_nanos()).max(0) as u64));
        if left.is_some_and(|l| l.is_zero()) {
            return Ok(());
        }
        // (a watch that cannot be made or kept, say the inotify instances of
        // the user are all taken, is no end of the follow: it reads again
        // after a pause)
        let pause = left.map_or(POLL, |l| l.min(POLL));
        let waited = out
            .while_there(async {
                match watch {
                    Ok(watch) => watch.changed(left).await.err(),
                    Err(e) => Some(e),
                }
            })
            .await;
        match waited {
            None => return Ok(()),
            Some(None) => {}
            Some(Some(e)) => {
                if !std::mem::replace(&mut warned, true) {
                    tracing::warn!(
                        "Cannot watch the events kept, reading them every {POLL:?}: {e}"
                    );
                }
                if out.while_there(tokio::time::sleep(pause)).await.is_none() {
                    return Ok(());
                }
            }
        }
    }
}

/// How often a follow of the events kept reads them when it cannot watch
/// where they are kept.
const POLL: std::time::Duration = std::time::Duration::from_millis(500);

/// Marker for events a slow client missed: it has seq 0 and no filter
/// matches it, so it is skipped.
fn lagged() -> Event {
    Event::new(EventKind::System, "lagged", "", "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters() {
        let ev = Event::new(EventKind::Container, "died", "abcdef", "c1");
        let f = Filters::parse(r#"{"event":["die"],"container":["c1"]}"#).unwrap();
        assert!(filters_match(&f, &ev));
        let f = Filters::parse(r#"{"container":["abc"]}"#).unwrap();
        assert!(filters_match(&f, &ev));
        let f = Filters::parse(r#"{"type":["volume"]}"#).unwrap();
        assert!(!filters_match(&f, &ev));
        // Docker's status is podman's event
        let f = Filters::parse(r#"{"status":["die"]}"#).unwrap();
        assert!(filters_match(&f, &ev));
        // a volume by a prefix of its name
        let vol = Event::new(EventKind::Volume, "create", "", "v-t14-abcdef");
        let f = Filters::parse(r#"{"volume":["v-t14-ab"]}"#).unwrap();
        assert!(filters_match(&f, &vol));
        let f = Filters::parse(r#"{"volume":["t14"]}"#).unwrap();
        assert!(!filters_match(&f, &vol));
    }

    #[test]
    fn the_until_of_a_filter_is_docker_s_get_timestamp() {
        assert_eq!(parse_since(""), Some(0));
        assert_eq!(parse_since("1700000000.5"), Some(1_700_000_000_500_000_000));
        assert_eq!(parse_since("2023-11-14"), Some(1_699_920_000_000_000_000));
        let ago = parse_since("5m").unwrap();
        assert!(ago < now_nanos() && ago > now_nanos() - 400_000_000_000);
        assert!(parse_since("-5m").unwrap() > now_nanos());
        // (a sign or an exponent: the events take them, GetTimestamp not)
        for bad in ["-5", "+5", "1e3", "garbage", "2d"] {
            assert_eq!(parse_since(bad), None, "{bad}");
        }
    }

    #[test]
    fn history_is_replayed_in_order() {
        let hub = EventHub::default();
        hub.emit(Event::new(EventKind::Container, "create", "a", "a"));
        hub.emit(Event::new(EventKind::Container, "start", "a", "a"));
        let (h, _rx) = hub.subscribe();
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].action, "create");
        assert!(h[0].seq < h[1].seq);
    }
}
