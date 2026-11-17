// SPDX-License-Identifier: Apache-2.0
//! No query parameter is accepted and ignored.  `parameters.txt` lists every
//! query parameter that podman's handlers decode, per route, and what velarx
//! does with it: `implemented`, `refused` (501 naming it) or `noop` with the
//! reason it changes nothing here (tools/parity-report/params.py writes it
//! from podman's sources and keeps the decisions).  This test keeps the table
//! and the handlers together:
//!
//! * a parameter the table says is implemented or refused is named in the
//!   code of the handler of its route (the function of the route tables
//!   of crates/api/src/podman and the functions it calls there), so it is
//!   not dropped when a handler changes, and a name read on one route does
//!   not stand for another;
//! * every parameter the handlers read or refuse is in the table (a new one
//!   is a decision: implement it, refuse it, or say why it changes nothing);
//! * a `noop` has its reason.

mod common;

use common::*;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// Parameters the handlers read that podman's decoders do not have (velarx's
/// own, or read for a client of another version).
const OTHER: &[&str] = &["version", "format"];

/// The text of the handlers, without their unit tests.
fn handler_code() -> String {
    let mut files = Vec::new();
    sources(&root().join("crates/api/src/podman"), &mut files);
    sources(&root().join("src/api/podman"), &mut files);
    files.push(root().join("crates/proto/src/build.rs"));
    let mut code = String::new();
    for f in files {
        let text = fs::read_to_string(&f).unwrap();
        let end = text.find("#[cfg(test)]").unwrap_or(text.len());
        code.push_str(&text[..end]);
        code.push('\n');
    }
    code
}

struct Row {
    route: String,
    name: String,
    what: String,
    reason: String,
}

fn table() -> Vec<Row> {
    let text =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/parameters.txt"))
            .unwrap();
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let w: Vec<&str> = l.splitn(6, ' ').collect();
            assert!(w.len() >= 5, "bad row: {l}");
            Row {
                route: format!("{} {} {}", w[0], w[1], w[2]),
                name: w[3].to_string(),
                what: w[4].to_string(),
                reason: w.get(5).unwrap_or(&"").to_string(),
            }
        })
        .collect()
}

#[test]
fn the_table_has_a_decision_for_every_parameter() {
    for r in table() {
        match r.what.as_str() {
            "implemented" | "refused" => {}
            "noop" => assert!(
                !r.reason.is_empty(),
                "{} {}: a noop says why",
                r.route,
                r.name
            ),
            w => panic!(
                "{} {}: `{w}` is not implemented, refused or noop",
                r.route, r.name
            ),
        }
    }
}

/// The routes of the handlers: ("compat"|"libpod" METHOD PATH) -> the
/// text of its handler and what it calls.
fn routes() -> std::collections::BTreeMap<String, String> {
    let dir = root().join("crates/api/src/podman");
    let mut files = Vec::new();
    for e in fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "rs") {
            let text = fs::read_to_string(&p).unwrap();
            let end = text.find("#[cfg(test)]").unwrap_or(text.len());
            let stem = p.file_stem().unwrap().to_string_lossy().to_string();
            files.push((stem, strip_comments(&text[..end])));
        }
    }
    let fns = functions(&files);
    let mut out = std::collections::BTreeMap::new();
    for (stem, code) in &files {
        for (at, _) in code.match_indices("route!(") {
            let open = at + "route!".len();
            let args = &code[open + 1..matching(code, open) - 1];
            let w: Vec<&str> = args
                .split(',')
                .map(str::trim)
                .filter(|w| !w.is_empty())
                .collect();
            if w.len() != 5 || !w[0].starts_with('"') {
                continue; // the macro itself
            }
            let method = w[0].trim_matches('"');
            let path = w[1].trim_matches('"').replace("{*}", "{}");
            let handler = w[4];
            let (module, name) = match handler.rsplit_once("::") {
                Some((m, n)) => (m.rsplit("::").next().unwrap().to_string(), n),
                None => (stem.clone(), handler),
            };
            let module = if module == "super" {
                stem.clone()
            } else {
                module
            };
            let mut text = closure(&fns, &module, name, 4, &mut BTreeSet::new());
            if module == "build" {
                // the build reads its parameters in the engine, by these lists
                text.push_str(
                    &fs::read_to_string(root().join("crates/proto/src/build.rs")).unwrap(),
                );
            }
            let apis: &[&str] = match w[2] {
                "LIBPOD" => &["libpod"],
                "COMPAT" => &["compat"],
                _ => &["compat", "libpod"],
            };
            for api in apis {
                out.entry(format!("{api} {method} {path}"))
                    .or_insert_with(String::new)
                    .push_str(&text);
            }
        }
    }
    out
}

#[test]
fn a_parameter_of_the_table_is_named_in_the_handler_of_its_route() {
    let routes = routes();
    let mut missing = Vec::new();
    for r in table() {
        if r.what == "noop" || r.route.starts_with("any ") {
            continue;
        }
        let Some(code) = routes.get(&r.route) else {
            missing.push(format!(
                "{} {} ({}): no such route",
                r.route, r.name, r.what
            ));
            continue;
        };
        if !literals(code).contains(&r.name.to_ascii_lowercase()) {
            missing.push(format!("{} {} ({})", r.route, r.name, r.what));
        }
    }
    assert!(
        missing.is_empty(),
        "named in the table, not in the handler of the route (ignored?):\n{}",
        missing.join("\n")
    );
}

#[test]
fn a_route_less_parameter_of_the_table_is_named_in_the_handlers() {
    let lit = literals(&handler_code());
    let missing: Vec<String> = table()
        .into_iter()
        .filter(|r| r.what != "noop" && r.route.starts_with("any "))
        .filter(|r| !lit.contains(&r.name.to_ascii_lowercase()))
        .map(|r| format!("{} {} ({})", r.route, r.name, r.what))
        .collect();
    assert!(
        missing.is_empty(),
        "named in the table, not in the handlers (ignored?):\n{}",
        missing.join("\n")
    );
}

#[test]
fn a_parameter_the_handlers_read_is_in_the_table() {
    let known: BTreeSet<String> = table()
        .into_iter()
        .map(|r| r.name.to_ascii_lowercase())
        .chain(OTHER.iter().map(|s| s.to_string()))
        .collect();
    let code = handler_code();
    let mut unknown = BTreeSet::new();
    for (i, _) in code.match_indices(".q") {
        // call.q("x"), q_bool("x", ..), q_i64, q_set, q_all
        let rest = &code[i + 2..];
        let name_end = rest.find('(').unwrap_or(0);
        let fname = &rest[..name_end];
        if !(fname.is_empty() || matches!(fname, "_bool" | "_i64" | "_set" | "_all")) {
            continue;
        }
        let args = rest[name_end + 1..].trim_start();
        if let Some(r) = args.strip_prefix('"') {
            if let Some(e) = r.find('"') {
                let n = r[..e].to_ascii_lowercase();
                if !known.contains(&n) {
                    unknown.insert(n);
                }
            }
        }
    }
    for k in ["refuse_params", "refuse_set"] {
        for (i, _) in code.match_indices(k) {
            let rest = &code[i..];
            let (Some(a), Some(b)) = (rest.find('['), rest.find(']')) else {
                continue;
            };
            if a > 40 {
                continue;
            }
            for n in literals(&rest[a..b]) {
                if !known.contains(&n) {
                    unknown.insert(n);
                }
            }
        }
    }
    assert!(
        unknown.is_empty(),
        "read or refused by a handler, not in tests/parameters.txt \
         (run tools/parity-report/params.py, then decide: implemented, refused, or noop with a reason): {unknown:?}"
    );
}
