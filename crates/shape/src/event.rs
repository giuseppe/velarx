// SPDX-License-Identifier: Apache-2.0
//! Events: Docker's `events.Message` (which podman's `entities.Event`
//! embeds), a line of `GET /events`, and the event of podman's `events
//! --format json`.

use serde_json::{json, Map, Value};
use velarx_proto::workload::{Event, EventKind};

/// Docker's word for an action (`die` where podman says `died`, `delete`
/// for the removal of an image).
fn docker_action(ev: &Event) -> &str {
    match (ev.kind, ev.action.as_str()) {
        (_, "died") => "die",
        (EventKind::Image, "remove") => "delete",
        (_, a) => a,
    }
}

/// The JSON of an event for the API flavour of the client (`libpod`:
/// podman's); Docker's API 1.52 (`modern`) dropped `status`, `id` and
/// `from`.
pub fn document(ev: &Event, libpod: bool, modern: bool) -> Value {
    let action = if libpod {
        ev.action.as_str()
    } else {
        docker_action(ev)
    };
    let id = if ev.id.is_empty() { &ev.name } else { &ev.id };
    let mut attrs = Map::new();
    // as podman: the clients parse containerExitCode unconditionally
    if libpod {
        attrs.insert("containerExitCode".into(), json!("0"));
        attrs.insert("podId".into(), json!(""));
    }
    if !ev.name.is_empty() || libpod {
        attrs.insert("name".into(), json!(ev.name));
    }
    if !ev.image.is_empty() || libpod {
        attrs.insert("image".into(), json!(ev.image));
    }
    for (k, v) in &ev.attributes {
        attrs.insert(k.clone(), json!(v));
    }
    if !libpod && action == "die" {
        if let Some(code) = ev.attributes.get("containerExitCode") {
            attrs.insert("exitCode".into(), json!(code));
        }
    }
    let kind = ev.kind.word();
    let mut m = Map::new();
    if libpod || !modern {
        m.insert("status".into(), json!(action));
        m.insert("id".into(), json!(id));
        if ev.kind == EventKind::Container && !ev.image.is_empty() {
            m.insert("from".into(), json!(ev.image));
        }
    }
    m.insert("Type".into(), json!(kind));
    m.insert("Action".into(), json!(action));
    m.insert("Actor".into(), json!({"ID": id, "Attributes": attrs}));
    m.insert("scope".into(), json!("local"));
    m.insert("time".into(), json!(ev.time_ns.div_euclid(1_000_000_000)));
    m.insert("timeNano".into(), json!(ev.time_ns));
    if libpod && action == "health_status" {
        if let Some(h) = ev.attributes.get("health_status") {
            m.insert("HealthStatus".into(), json!(h));
        }
    }
    Value::Object(m)
}

/// Whether podman's API shows the event: the end of a lazy pull has no
/// podman status.
pub fn libpod_shows(ev: &Event) -> bool {
    ev.action != "complete"
}

/// The attributes of an event that are not fields of podman's event of the
/// command line, in order.
pub fn other_attributes(ev: &Event) -> impl Iterator<Item = (&String, &String)> {
    ev.attributes
        .iter()
        .filter(|(k, _)| !matches!(k.as_str(), "name" | "image"))
}

/// The event of podman's `events --format json` (cmd/podman/system/events.go
/// `Event`).
pub fn podman_cli(ev: &Event) -> Value {
    let attr = |k: &str| ev.attributes.get(k).map_or("", String::as_str);
    let mut o = Map::new();
    if let Ok(code) = attr("containerExitCode").parse::<i64>() {
        o.insert("ContainerExitCode".into(), json!(code));
    }
    if !ev.id.is_empty() {
        o.insert("ID".into(), json!(ev.id));
    }
    for (field, value) in [("Image", &ev.image), ("Name", &ev.name)] {
        if !value.is_empty() {
            o.insert(field.into(), json!(value));
        }
    }
    if ev.kind == EventKind::Network && !ev.name.is_empty() {
        o.insert("network".into(), json!(ev.name));
    }
    o.insert("Status".into(), json!(ev.action));
    o.insert("time".into(), json!(ev.time_ns.div_euclid(1_000_000_000)));
    if ev.time_ns != 0 {
        o.insert("timeNano".into(), json!(ev.time_ns));
    }
    o.insert("Type".into(), json!(ev.kind.word()));
    if !attr("podId").is_empty() {
        o.insert("PodID".into(), json!(attr("podId")));
    }
    // (the health status is a field of podman's event, not an attribute)
    if let Some(h) = ev.attributes.get("health_status") {
        o.insert("health_status".into(), json!(h));
    }
    let attributes: Map<String, Value> = other_attributes(ev)
        .filter(|(k, _)| k.as_str() != "health_status")
        .map(|(k, v)| (k.clone(), json!(v)))
        .collect();
    o.insert("Attributes".into(), Value::Object(attributes));
    Value::Object(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_health_status_is_a_field_of_podman_s_event() {
        let mut ev = Event {
            kind: EventKind::Container,
            action: "health_status".into(),
            id: "abc".into(),
            ..Default::default()
        };
        ev.attributes
            .insert("health_status".into(), "healthy".into());
        let v = podman_cli(&ev);
        assert_eq!(v["health_status"], "healthy");
        assert_eq!(v["Attributes"], json!({}));
    }

    fn event(kind: EventKind, action: &str, id: &str, name: &str) -> Event {
        Event {
            time_ns: 1_500_000_000,
            kind,
            action: action.into(),
            id: id.into(),
            name: name.into(),
            ..Default::default()
        }
    }

    #[test]
    fn docker_names_die() {
        let mut ev = event(EventKind::Container, "died", "abc", "c1");
        ev.image = "img".into();
        ev.attributes.insert("containerExitCode".into(), "3".into());
        let d = document(&ev, false, false);
        assert_eq!(d["Action"], "die");
        assert_eq!(d["status"], "die");
        assert_eq!(d["Actor"]["Attributes"]["exitCode"], "3");
        assert_eq!(
            (d["time"].clone(), d["timeNano"].clone()),
            (json!(1), json!(1_500_000_000))
        );
        assert!(document(&ev, false, true).get("status").is_none());
        let p = document(&ev, true, false);
        assert_eq!(p["Action"], "died");
        assert_eq!(p["Actor"]["Attributes"]["containerExitCode"], "3");
        assert_eq!(p["Actor"]["Attributes"]["podId"], "");
        assert_eq!(p["from"], "img");
        let image = event(EventKind::Image, "remove", "sha", "");
        assert_eq!(document(&image, false, false)["Action"], "delete");
        assert_eq!(document(&image, true, false)["Action"], "remove");
        // (an object without an id is named by its name)
        let volume = event(EventKind::Volume, "create", "", "v1");
        assert_eq!(document(&volume, false, false)["Actor"]["ID"], "v1");
    }

    #[test]
    fn the_command_line_s_event_is_podman_s() {
        let mut ev = event(EventKind::Container, "died", "abc", "c1");
        ev.image = "img".into();
        ev.attributes.insert("containerExitCode".into(), "3".into());
        ev.attributes.insert("podId".into(), "p1".into());
        let v = podman_cli(&ev);
        assert_eq!(v["ContainerExitCode"], 3);
        assert_eq!(
            (v["Name"].clone(), v["Image"].clone()),
            (json!("c1"), json!("img"))
        );
        assert_eq!(
            (v["Status"].clone(), v["Type"].clone()),
            (json!("died"), json!("container"))
        );
        assert_eq!(v["PodID"], "p1");
        assert_eq!(v["Attributes"]["containerExitCode"], "3");
        let net = podman_cli(&event(EventKind::Network, "create", "n1", "net"));
        assert_eq!(net["network"], "net");
        assert!(net.get("ContainerExitCode").is_none());
    }
}
