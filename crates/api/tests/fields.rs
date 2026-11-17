// SPDX-License-Identifier: Apache-2.0
//! No field of a request body is accepted and ignored.  `fields.txt` lists
//! every field of the bodies podman's handlers decode (the JSON fields of
//! SpecGenerator, CreateContainerConfig, PodSpecGenerator, Network...), per
//! route, and what velarx does with it: `implemented`, `refused` (naming it)
//! or `noop` with the reason it changes nothing here
//! (tools/parity-report/fields.py writes it from podman's Go types and keeps
//! the decisions).  Its `scope` lines say which code reads the body of a
//! route.  This test keeps the table and that code together:
//!
//! * a field the table says is implemented or refused is named in the code
//!   of its route (a refusal of a whole object says which member it looks
//!   at: `via`), so it is not dropped when the handler changes;
//! * the status is what the code does: a refused field is named where the
//!   code refuses, an implemented one is not only there;
//! * every field the code of a route reads is in the table (a new one is a
//!   decision: implement it, refuse it, or say why it changes nothing);
//! * a `noop` has its reason.

mod common;

use common::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

/// Fields the handlers read that podman's types do not have: velarx's own,
/// or of another version of the API.
const OTHER: &[&str] = &[
    "cap_ambient",
    "groups_strict",
    "gpus",
    "pidfile",
    "r_o_paths",
    "domainname",
    "autoremoveimage",
    "umask",
    "cni_annotations",
    "cni_ip_ranges",
    "cpu_period",
    "cpu_quota",
    "infra_oom_score_adj",
    "infra_privileged",
    "infra_read_only",
    "infra_run_as_group",
    "infra_run_as_user",
    "infra_supplemental_groups",
    "oci_runtime",
    "static_ip",
    "username",
    "password",
    "skiptlsverify",
    "ignoreifexists",
    "lower",
    "force",
    "h",
    "w",
    "detach",
    // (a key of the options of a log driver, a map)
    "max-size",
];

/// Fields read on a route that its type in podman lacks, because the body is
/// decoded for both APIs by one struct (the other API's fields are taken
/// too: a superset, nothing is ignored).
const SHARED: &[(&str, &[&str])] = &[
    (
        "compat POST /volumes/create",
        &["gid", "label", "options", "uid", "ignoreifexists"],
    ),
    (
        "libpod POST /volumes/create",
        &["clustervolumespec", "driveropts"],
    ),
    // (the device rules of Docker's DeviceCgroupRules are built as the OCI ones)
    ("compat POST /containers/{}/update", &["type"]),
    (
        "compat POST /networks/{}/connect",
        &[
            "interface_name",
            "options",
            "static_ips",
            "static_mac",
            "aliases",
            "container",
        ],
    ),
    (
        "libpod POST /networks/{}/connect",
        &["endpointconfig", "docker_container"],
    ),
];

/// The directories whose files hold the code of the scopes.
const DIRS: &[&str] = &[
    "crates/api/src/podman",
    "src/api/podman",
    "crates/proto/src",
    "crates/core/src/services/container",
];

struct Row {
    route: String,
    field: String,
    what: String,
    reason: String,
}

fn table() -> (Vec<Row>, BTreeMap<String, Vec<String>>) {
    let text =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fields.txt")).unwrap();
    let mut rows = Vec::new();
    let mut scopes = BTreeMap::new();
    for l in text.lines().filter(|l| !l.is_empty()) {
        if let Some(s) = l.strip_prefix("# scope ") {
            let w: Vec<&str> = s.split(' ').collect();
            scopes.insert(
                format!("{} {} {}", w[0], w[1], w[2]),
                w[3..].iter().map(|i| i.to_string()).collect(),
            );
        } else if !l.starts_with('#') {
            let w: Vec<&str> = l.splitn(6, ' ').collect();
            assert!(w.len() >= 5, "bad row: {l}");
            rows.push(Row {
                route: format!("{} {} {}", w[0], w[1], w[2]),
                field: w[3].to_string(),
                what: w[4].to_string(),
                reason: w.get(5).unwrap_or(&"").to_string(),
            });
        }
    }
    (rows, scopes)
}

/// The code of the scopes of the table: the files without their comments
/// and unit tests, and the functions in them.
struct Code {
    files: Vec<(String, String)>,
    fns: Functions,
}

fn code() -> Code {
    let mut paths = Vec::new();
    for d in DIRS {
        sources(&root().join(d), &mut paths);
    }
    let files: Vec<(String, String)> = paths
        .iter()
        .map(|p| {
            let text = fs::read_to_string(p).unwrap();
            let end = text.find("#[cfg(test)]").unwrap_or(text.len());
            let rel = p.strip_prefix(root()).unwrap();
            (
                rel.to_string_lossy().to_string(),
                strip_comments(&text[..end]),
            )
        })
        .collect();
    let fns = functions(&files);
    Code { files, fns }
}

/// The body of `struct name { .. }` in a file.
fn struct_of<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let at = text
        .match_indices(&format!("struct {name}"))
        .map(|(i, _)| i)
        .find(|i| text[i + "struct ".len() + name.len()..].starts_with([' ', '{', '<', '\n']))?;
    let open = at + text[at..].find('{')?;
    Some(&text[open..matching(text, open)])
}

/// The bodies of the structs of a file.
fn all_structs(text: &str) -> Vec<String> {
    text.match_indices("struct ")
        .filter(|(i, _)| *i == 0 || !text.as_bytes()[i - 1].is_ascii_alphanumeric())
        .filter_map(|(i, _)| {
            let rest = &text[i..];
            let open = rest.find(['{', ';'])?;
            (rest.as_bytes()[open] == b'{').then(|| {
                let at = i + open;
                text[at..matching(text, at)].to_string()
            })
        })
        .collect()
}

/// The fields of a struct body with the name they have on the wire (the
/// rename of serde, else the member).
fn members(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rename = None;
    for line in body.lines().skip(1) {
        let l = line.trim();
        if let Some(at) = l.find("rename = \"") {
            let r = &l[at + "rename = \"".len()..];
            rename = r.find('"').map(|e| r[..e].to_string());
        }
        if let Some(at) = l.find("alias = \"") {
            let r = &l[at + "alias = \"".len()..];
            if let Some(e) = r.find('"') {
                out.push((String::new(), r[..e].to_string()));
            }
        }
        let l = l.strip_prefix("pub ").unwrap_or(l);
        if let Some((ident, _)) = l.split_once(':') {
            if !ident.is_empty()
                && ident.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !l.starts_with("#")
            {
                out.push((
                    ident.to_string(),
                    rename.take().unwrap_or_else(|| ident.to_string()),
                ));
            }
        }
    }
    out
}

/// The names a scope reads: the string literals of its functions, and the
/// members of its structs that its functions read (`.member`).
fn names(code: &Code, items: &[String]) -> BTreeSet<String> {
    let mut text = String::new();
    let mut structs = Vec::new();
    for item in items {
        let (file, name) = item.split_once("::").unwrap();
        let src = &code
            .files
            .iter()
            .find(|(f, _)| f == file)
            .unwrap_or_else(|| panic!("no file {file}"))
            .1;
        if name == "*" {
            text.push_str(src);
            structs.extend(all_structs(src));
        } else if let Some(s) = struct_of(src, name) {
            structs.push(s.to_string());
        } else {
            let found = closure(&code.fns, file, name, 6, &mut BTreeSet::new());
            assert!(
                !found.is_empty(),
                "scope item without a function or struct: {item}"
            );
            text.push_str(&found);
        }
    }
    let mut out = literals(&text);
    for s in &structs {
        let mut pending = Vec::new();
        for (ident, wire) in members(s) {
            if ident.is_empty() {
                // an alias belongs to the member that follows
                pending.push(wire);
            } else if text.contains(&format!(".{ident}")) {
                out.extend(pending.drain(..).map(|a| a.to_ascii_lowercase()));
                out.insert(wire.to_ascii_lowercase());
                out.insert(ident.to_ascii_lowercase());
            } else {
                pending.clear();
            }
        }
    }
    out
}

fn last(field: &str) -> String {
    field.rsplit('.').next().unwrap().to_ascii_lowercase()
}

#[test]
fn the_table_has_a_decision_for_every_field() {
    let (rows, _) = table();
    assert!(!rows.is_empty());
    for r in rows {
        match r.what.as_str() {
            "implemented" | "refused" => {}
            "noop" => assert!(
                !r.reason.is_empty(),
                "{} {}: a noop says why",
                r.route,
                r.field
            ),
            w => panic!(
                "{} {}: `{w}` is not implemented, refused or noop",
                r.route, r.field
            ),
        }
    }
}

#[test]
fn a_field_of_the_table_is_named_in_the_code_of_its_route() {
    let (rows, scopes) = table();
    let code = code();
    let mut known: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for (route, items) in &scopes {
        known.insert(route, names(&code, items));
    }
    let mut missing = Vec::new();
    for r in &rows {
        if r.what == "noop" {
            continue;
        }
        let Some(read) = known.get(r.route.as_str()) else {
            missing.push(format!("{} {}: no scope for the route", r.route, r.field));
            continue;
        };
        // `via x`: the code looks at the member x of the object
        let name = r
            .reason
            .strip_prefix("via ")
            .map_or_else(|| last(&r.field), |v| v.to_ascii_lowercase());
        if !read.contains(&name) {
            missing.push(format!("{} {} ({})", r.route, r.field, r.what));
        }
    }
    assert!(
        missing.is_empty(),
        "named in the table, not in the code of the route (dropped?):\n{}",
        missing.join("\n")
    );
}

/// The text of the functions of a scope, and the names of the members of
/// its structs (on the wire, in lower case).
fn scope_text(code: &Code, items: &[String]) -> (String, BTreeSet<String>) {
    let mut text = String::new();
    let mut members_of = BTreeSet::new();
    for item in items {
        let (file, name) = item.split_once("::").unwrap();
        let src = &code.files.iter().find(|(f, _)| f == file).unwrap().1;
        let structs = if name == "*" {
            text.push_str(src);
            all_structs(src)
        } else if let Some(s) = struct_of(src, name) {
            vec![s.to_string()]
        } else {
            text.push_str(&closure(&code.fns, file, name, 6, &mut BTreeSet::new()));
            Vec::new()
        };
        for s in structs {
            members_of.extend(members(&s).into_iter().map(|(_, w)| w.to_ascii_lowercase()));
        }
    }
    (text, members_of)
}

/// The statements of `text` that name `name` as a word, in lower case: from
/// the `;`, `{` or `}` before the name to the `;` after it (what an `if`
/// does with it, the call it is an argument of).  `strict`: to the end of
/// the arm of a `match` or of the line of a list too, and of a `for`, a
/// `match` or an `if let` to the start of its body (the body is about all
/// the elements, or the members of the value).
fn statements_naming(text: &str, name: &str, strict: bool) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let b = lower.as_bytes();
    lower
        .match_indices(name)
        .filter(|(at, _)| {
            (*at == 0 || !word(b[at - 1])) && b.get(at + name.len()).is_none_or(|c| !word(*c))
        })
        .map(|(at, _)| {
            let start = lower[..at].rfind([';', '{', '}']).map_or(0, |i| i + 1);
            let rest = &lower[at..];
            let mut end = rest.find(';').unwrap_or(rest.len());
            if strict {
                for arm_end in [",\n", "}\n"] {
                    end = end.min(rest.find(arm_end).unwrap_or(end));
                }
                let head = lower[start..at].trim_start();
                if ["for ", "match ", "if let "]
                    .iter()
                    .any(|k| head.starts_with(k))
                {
                    end = end.min(rest.find('{').unwrap_or(end));
                }
            }
            lower[start..at + end].to_string()
        })
        .collect()
}

/// What a refusal says, or calls.
const REFUSAL: &[&str] = &[
    "refuse",
    "not_implemented",
    "not supported",
    "unsupported",
    "cannot set",
];

/// The status of a row is what the code does: a refused field is named
/// where the code refuses (a refusal says its name, or the statement that
/// looks at it refuses), an implemented one that the code takes by its name
/// is named elsewhere too, unless its reason says which of its values are
/// refused.  (A member of a struct is taken by the decoding
/// of the body; the generic names that the code of a route has in other
/// places pass: the test above sees those.)
#[test]
fn the_status_of_a_field_is_what_the_code_does_with_it() {
    let (rows, scopes) = table();
    let code = code();
    let texts: BTreeMap<&str, (String, BTreeSet<String>)> = scopes
        .iter()
        .map(|(route, items)| (route.as_str(), scope_text(&code, items)))
        .collect();
    let mut wrong = Vec::new();
    for r in rows
        .iter()
        .filter(|r| r.what != "noop" && !r.reason.starts_with("via "))
    {
        let Some((text, members_of)) = texts.get(r.route.as_str()) else {
            continue;
        };
        let name = last(&r.field);
        let refusing = |strict| {
            let stmts = statements_naming(text, &name, strict);
            let n = stmts
                .iter()
                .filter(|s| REFUSAL.iter().any(|m| s.contains(m)))
                .count();
            (n, stmts.len())
        };
        match r.what.as_str() {
            "refused" if matches!(refusing(false), (0, 1..)) => wrong.push(format!(
                "{} {}: refused, but no refusal names it",
                r.route, r.field
            )),
            "implemented"
                if r.reason.is_empty()
                    && matches!(refusing(true), (n, all) if all > 0 && n == all)
                    && !members_of.contains(&name) =>
            {
                wrong.push(format!(
                    "{} {}: implemented, but the code only refuses it",
                    r.route, r.field
                ))
            }
            _ => {}
        }
    }
    assert!(
        wrong.is_empty(),
        "the status of the table is not what the code does:\n{}",
        wrong.join("\n")
    );
}

/// The names the code of a scope takes from a body with the helpers of the
/// handlers (`s(spec, "name")`, `strs(host, "Name")`...), and the members of
/// its structs that are read.
fn read_names(code: &Code, items: &[String]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut text = String::new();
    let mut structs = Vec::new();
    for item in items {
        let (file, name) = item.split_once("::").unwrap();
        let src = &code.files.iter().find(|(f, _)| f == file).unwrap().1;
        if name == "*" {
            text.push_str(src);
            structs.extend(all_structs(src));
        } else if let Some(s) = struct_of(src, name) {
            structs.push(s.to_string());
        } else {
            text.push_str(&closure(&code.fns, file, name, 6, &mut BTreeSet::new()));
        }
    }
    for helper in [
        "s(", "b(", "i(", "strs(", "arr(", "get(", "field(", "text(", "flag(", "strings(",
    ] {
        for (at, _) in text.match_indices(helper) {
            // not the tail of another name
            if at > 0 {
                let p = text.as_bytes()[at - 1];
                if p.is_ascii_alphanumeric() || p == b'_' {
                    continue;
                }
            }
            let rest = &text[at + helper.len()..];
            let Some(end) = rest.find(')') else { continue };
            let args = &rest[..end];
            if let Some((_, lit)) = args.split_once(", \"") {
                if let Some(n) = lit.strip_suffix('"') {
                    out.insert(n.to_ascii_lowercase());
                }
            }
        }
    }
    // (and the members of an object read with `.get("name")`)
    for (at, _) in text.match_indices(".get(\"") {
        let rest = &text[at + ".get(\"".len()..];
        if let Some(end) = rest.find("\")") {
            out.insert(rest[..end].to_ascii_lowercase());
        }
    }
    for s in &structs {
        let mut pending = Vec::new();
        for (ident, wire) in members(s) {
            if ident.is_empty() {
                pending.push(wire);
            } else if text.contains(&format!(".{ident}")) {
                out.extend(pending.drain(..).map(|a| a.to_ascii_lowercase()));
                out.insert(wire.to_ascii_lowercase());
            } else {
                pending.clear();
            }
        }
    }
    out
}

#[test]
fn a_field_the_code_of_a_route_reads_is_in_the_table() {
    let (rows, scopes) = table();
    let code = code();
    let mut unknown = Vec::new();
    for (route, items) in &scopes {
        let in_table: BTreeSet<String> = rows
            .iter()
            .filter(|r| &r.route == route)
            .map(|r| last(&r.field))
            .collect();
        for n in read_names(&code, items) {
            let shared = SHARED
                .iter()
                .any(|(r, names)| r == route && names.contains(&n.as_str()));
            if !in_table.contains(&n) && !OTHER.contains(&n.as_str()) && !shared {
                unknown.push(format!("{route}: {n}"));
            }
        }
    }
    assert!(
        unknown.is_empty(),
        "read by the code of a route, not in tests/fields.txt \
         (run tools/parity-report/fields.py, then decide: implemented, refused, or noop with a reason; \
         or add it to OTHER if it is velarx's own): {unknown:#?}"
    );
}
