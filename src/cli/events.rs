// SPDX-License-Identifier: Apache-2.0
//! The output of `velarx events`, as podman's: a line per event (the
//! local time as Go prints it, the type, the status, the short ID and the
//! attributes), `--format json` with podman's fields, or a template of
//! them.

use serde_json::{json, Value};
use velarx_proto::workload::{Event, EventKind};
use velarx_shape::event::{other_attributes, podman_cli};

/// How `velarx events` prints an event.
pub enum Format {
    Human { truncate: bool },
    Json,
    Template(String),
}

impl Format {
    pub fn new(format: Option<&str>, no_trunc: bool) -> Self {
        match format {
            None | Some("") => Format::Human {
                truncate: !no_trunc,
            },
            Some(f) if f == "json" || f == "{{json .}}" => Format::Json,
            Some(f) => Format::Template(f.to_string()),
        }
    }

    pub fn render(&self, e: &Event) -> String {
        match self {
            Format::Human { truncate } => human(e, *truncate),
            Format::Json => podman_cli(e).to_string(),
            Format::Template(t) => template(t, &podman_cli(e)),
        }
    }
}

fn attr<'a>(e: &'a Event, k: &str) -> &'a str {
    e.attributes.get(k).map(String::as_str).unwrap_or("")
}

/// podman's line (libpod/events `toHumanReadable`).
fn human(e: &Event, truncate: bool) -> String {
    let id = if truncate && e.id.len() > 12 {
        &e.id[..12]
    } else {
        e.id.as_str()
    };
    let prefix = format!("{} {} {}", go_time(e), e.kind.word(), e.action);
    match e.kind {
        EventKind::Container | EventKind::Pod => {
            let mut s = format!("{prefix} {id} (image={}, name={}", e.image, e.name);
            for (k, v) in other_attributes(e) {
                s.push_str(&format!(", {k}={v}"));
            }
            s + ")"
        }
        EventKind::Network => match attr(e, "driver") {
            d if !d.is_empty() => format!("{prefix} {} (name={}, type={d})", e.id, e.name),
            _ => format!("{prefix} {id} (name={})", e.name),
        },
        EventKind::Image | EventKind::Artifact => format!("{prefix} {id} {}", e.name),
        EventKind::Volume | EventKind::Machine => format!("{prefix} {}", e.name),
        EventKind::System if !e.name.is_empty() => format!("{prefix} {}", e.name),
        EventKind::System => prefix,
        EventKind::Secret => format!("{prefix} {id}"),
    }
}

/// The time of the event as Go's `time.Time.String()` prints it.
fn go_time(e: &Event) -> String {
    go_time_ns(e.time_ns)
}

/// A time in nanoseconds since the epoch as Go's `time.Time.String()`
/// prints it, in the local zone: `2006-01-02 15:04:05.999999999 -0700 MST`.
pub fn go_time_ns(nanos: i64) -> String {
    let secs = nanos.div_euclid(1_000_000_000);
    let frac = nanos.rem_euclid(1_000_000_000);
    let Some(tm) = velarx_sys::time::local_time(secs) else {
        return secs.to_string();
    };
    let zone = tm.zone.clone();
    let mut s = format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.year, tm.month, tm.day, tm.hour, tm.minute, tm.second
    );
    if frac != 0 {
        let f = format!("{frac:09}");
        s.push('.');
        s.push_str(f.trim_end_matches('0'));
    }
    let off = tm.utc_offset;
    let sign = if off < 0 { '-' } else { '+' };
    let off = off.abs();
    let offset = format!("{sign}{:02}{:02}", off / 3600, off % 3600 / 60);
    let zone = if zone.is_empty() {
        offset.clone()
    } else {
        zone
    };
    format!("{s} {offset} {zone}")
}

/// The template `t` applied to podman's event `v`: the fields of podman's
/// event (its JSON leaves out those that are empty), named as Go names
/// them (`.Time`, `.TimeNano`, `.Network`).  A template that does not apply,
/// a field the event does not have too, is podman's error.
fn template(t: &str, v: &Value) -> String {
    use super::template::{GO_TYPE, NIL};
    let mut doc = serde_json::Map::new();
    doc.insert(GO_TYPE.into(), json!("system.Event"));
    for (field, key, zero) in [
        // (a pointer: nil unless the container exited)
        ("ContainerExitCode", "ContainerExitCode", json!(NIL)),
        ("ID", "ID", json!("")),
        ("Image", "Image", json!("")),
        ("Name", "Name", json!("")),
        ("Network", "network", json!("")),
        ("Status", "Status", json!("")),
        ("Time", "time", json!(0)),
        ("TimeNano", "timeNano", json!(0)),
        ("Type", "Type", json!("")),
        ("HealthStatus", "health_status", json!("")),
        ("Error", "Error", json!("")),
        ("ContainerInspectData", "ContainerInspectData", json!("")),
        ("PodID", "PodID", json!("")),
        ("Attributes", "Attributes", json!({})),
    ] {
        doc.insert(field.into(), v.get(key).cloned().unwrap_or(zero));
    }
    let rendered = super::template::Template::parse(t).and_then(|p| p.render(&Value::Object(doc)));
    match rendered {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {}", go_error(t, &e));
            std::process::exit(125);
        }
    }
}

/// The error `e` of the template `t` as Go's: where it failed, at the line
/// and column of the field it names (`template: events:1:2: executing
/// "events" at <.Nope>: ...`).
fn go_error(t: &str, e: &str) -> String {
    let Some(field) = e
        .strip_prefix("at <")
        .and_then(|rest| rest.split_once(">:"))
        .map(|(f, _)| f)
    else {
        return format!("template: events: {e}");
    };
    let Some(at) = t.find(field) else {
        return format!("template: events: executing \"events\" {e}");
    };
    let line = t[..at].matches('\n').count() + 1;
    let column = at - t[..at].rfind('\n').map_or(0, |n| n + 1);
    format!("template: events:{line}:{column}: executing \"events\" {e}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn died() -> Event {
        Event {
            time_ns: 1_700_000_000_120_000_000,
            kind: EventKind::Container,
            action: "died".into(),
            id: "0123456789abcdef0123".into(),
            name: "evc".into(),
            image: "alpine".into(),
            attributes: [("containerExitCode", "3")]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn human_is_podmans_line() {
        let s = Format::new(None, false).render(&died());
        let fields: Vec<&str> = s.split(' ').collect();
        // date, time, offset, zone, type, status, short id
        assert_eq!(fields[4..7], ["container", "died", "0123456789ab"]);
        assert!(fields[1].ends_with(".12"), "{s}");
        assert!(
            s.ends_with("(image=alpine, name=evc, containerExitCode=3)"),
            "{s}"
        );
        let s = Format::new(None, true).render(&died());
        assert!(s.contains(" 0123456789abcdef0123 "), "{s}");
    }

    #[test]
    fn json_has_podmans_fields() {
        let v: Value =
            serde_json::from_str(&Format::new(Some("json"), false).render(&died())).unwrap();
        assert_eq!(v["Type"], "container");
        assert_eq!(v["Status"], "died");
        assert_eq!(v["Name"], "evc");
        assert_eq!(v["ContainerExitCode"], 3);
        assert_eq!(v["timeNano"], 1_700_000_000_120_000_000i64);
        assert_eq!(v["Attributes"], json!({"containerExitCode": "3"}));
    }

    #[test]
    fn templates() {
        let f = Format::new(
            Some("{{.Type}} {{.Status}} {{ .Name }} {{.ContainerExitCode}}"),
            false,
        );
        assert_eq!(f.render(&died()), "container died evc 3");
        let f = Format::new(
            Some("{{.Attributes}}|{{.Attributes.nope}}|{{.PodID}}"),
            false,
        );
        assert_eq!(f.render(&died()), "map[containerExitCode:3]|<no value>|");
        let mut created = died();
        created.action = "create".into();
        created.attributes.clear();
        let f = Format::new(Some("{{.ContainerExitCode}}"), false);
        assert_eq!(f.render(&created), "<nil>");
    }

    /// A field that podman's event does not have fails as Go's.
    #[test]
    fn a_field_the_event_has_not_is_an_error() {
        let e = super::super::template::Template::parse("x\n {{.Nope}}")
            .unwrap()
            .render(&json!({ super::super::template::GO_TYPE: "system.Event" }))
            .unwrap_err();
        assert_eq!(
            go_error("x\n {{.Nope}}", &e),
            "template: events:2:3: executing \"events\" at <.Nope>: can't evaluate field Nope in type system.Event"
        );
    }
}
