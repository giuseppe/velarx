// SPDX-License-Identifier: Apache-2.0
//! The events of the containers and images: what they are, the ones the
//! engine's operations and the monitors write, and where they are kept
//! ([`log`]).  The engine and the monitor of a container write them with
//! the same code.

pub mod log;

use std::collections::BTreeMap;
use velarx_proto::workload::EventKind;

#[derive(Debug, Clone)]
pub struct Event {
    /// The order the hub of a process gave it (0: not given)
    pub seq: u64,
    pub kind: EventKind,
    pub action: String,
    pub id: String,
    pub name: String,
    pub image: String,
    pub attributes: BTreeMap<String, String>,
    pub time_nano: i64,
}

impl Event {
    pub fn new(kind: EventKind, action: &str, id: &str, name: &str) -> Self {
        Self {
            seq: 0,
            kind,
            action: action.to_string(),
            id: id.to_string(),
            name: name.to_string(),
            image: String::new(),
            attributes: BTreeMap::new(),
            time_nano: now_nanos(),
        }
    }

    pub fn image(mut self, image: &str) -> Self {
        self.image = image.to_string();
        self
    }

    pub fn attr(mut self, k: &str, v: impl Into<String>) -> Self {
        self.attributes.insert(k.to_string(), v.into());
        self
    }

    /// The event as the interface has it.
    pub fn record(&self) -> velarx_proto::workload::Event {
        velarx_proto::workload::Event {
            time_ns: self.time_nano,
            kind: self.kind,
            action: self.action.clone(),
            id: self.id.clone(),
            name: self.name.clone(),
            image: self.image.clone(),
            attributes: self.attributes.clone(),
        }
    }
}

/// Nanoseconds since the epoch.
pub fn now_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
}

/// The event of a container.
pub fn container_event(id: &str, name: &str, action: &str) -> Event {
    Event::new(EventKind::Container, action, id, name)
}

/// The event of an exit.
pub fn died_event(
    id: &str,
    name: &str,
    image: &str,
    labels: Vec<(String, String)>,
    code: i32,
    timed_out: bool,
) -> Event {
    let mut event = container_event(id, name, "died").image(image);
    for (k, v) in labels {
        event = event.attr(&k, v);
    }
    let mut event = event.attr("containerExitCode", code.to_string());
    if timed_out {
        event = event.attr("timedOut", "true");
    }
    event
}

/// A stored repository (`library/alpine`, `localhost:5000/alpine`) with the
/// registry podman shows for it.
pub fn display_repository(repo: &str) -> String {
    let first = repo.split('/').next().unwrap_or("");
    let has_registry = repo.contains('/') && velarx_base::reference::is_registry_domain(first);
    if has_registry {
        repo.to_string()
    } else {
        format!("docker.io/{repo}")
    }
}

/// The name of an image as podman shows it; a name `repository@digest` of
/// the history has the tag `@digest`.
pub fn display_name(repository: &str, tag: &str) -> String {
    match tag.starts_with('@') {
        true => format!("{}{tag}", display_repository(repository)),
        false => format!("{}:{tag}", display_repository(repository)),
    }
}

/// The events of an image `--rmi` removed or untagged: those `image rm`
/// writes (an `untag` for each name, and the `remove` of the image when it
/// went).
pub fn image_events(change: &crate::monitor::iface::ImageChange) -> Vec<Event> {
    let id = change.id.as_str();
    let shown: Vec<String> = change
        .names
        .iter()
        .map(|n| display_name(&n.repository, &n.tag))
        .collect();
    let mut out: Vec<Event> = shown
        .iter()
        .map(|n| Event::new(EventKind::Image, "untag", id, n))
        .collect();
    if change.removed {
        out.push(Event::new(
            EventKind::Image,
            "remove",
            id,
            shown.first().map_or("", String::as_str),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::iface::{ImageChange, ImageName};

    fn change(names: &[(&str, &str)], removed: bool) -> ImageChange {
        ImageChange {
            id: "abc".into(),
            names: names
                .iter()
                .map(|(repository, tag)| ImageName {
                    repository: (*repository).into(),
                    tag: (*tag).into(),
                })
                .collect(),
            removed,
        }
    }

    /// The name `--rmi` takes from an image with others: one `untag`.
    #[test]
    fn a_name_that_goes_is_one_untag() {
        let ev = image_events(&change(&[("localhost/x", "2")], false));
        assert_eq!(ev.len(), 1);
        assert_eq!(
            (ev[0].action.as_str(), ev[0].name.as_str()),
            ("untag", "localhost/x:2")
        );
    }

    /// The image that goes: an `untag` for each name, then its `remove`.
    #[test]
    fn an_image_that_goes_is_untags_and_a_remove() {
        let ev = image_events(&change(
            &[("localhost/x", "1"), ("localhost/x", "@sha256:9")],
            true,
        ));
        let actions: Vec<_> = ev.iter().map(|e| e.action.as_str()).collect();
        assert_eq!(actions, ["untag", "untag", "remove"]);
        assert_eq!(ev[1].name, "localhost/x@sha256:9");
        assert!(ev.iter().all(|e| e.id == "abc"));
    }
}
