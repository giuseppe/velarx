// SPDX-License-Identifier: Apache-2.0
//! What the drift tests of the API (`parameters.rs`, `fields.rs`) share: the
//! sources of the handlers read as text, without their comments and unit
//! tests, and the functions a handler calls.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// The names between quotes in the code, lower case.
pub fn literals(code: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let b = code.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'"' {
            let start = i + 1;
            let mut j = start;
            while j < b.len() && b[j] != b'"' && b[j] != b'\n' && b[j] != b'\\' {
                j += 1;
            }
            if j < b.len() && b[j] == b'"' {
                out.insert(code[start..j].to_ascii_lowercase());
                i = j;
            }
        }
        i += 1;
    }
    out
}

/// The code without its comments, the text of its string literals kept.
pub fn strip_comments(code: &str) -> String {
    let b = code.as_bytes();
    let mut out = String::with_capacity(code.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'"' => {
                let start = i;
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
                i = (i + 1).min(b.len());
                out.push_str(&code[start..i]);
            }
            // a char literal (not a lifetime): '\'', '\\', '\u{7f}', '"', '{'
            b'\'' if b.get(i + 1) == Some(&b'\\') => {
                i = code[i + 3..].find('\'').map_or(b.len(), |e| i + 4 + e);
                out.push_str("' '");
            }
            b'\'' if b.get(i + 2) == Some(&b'\'') => {
                i += 3;
                out.push_str("' '");
            }
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            _ => {
                let c = code[i..].chars().next().unwrap();
                out.push(c);
                i += c.len_utf8();
            }
        }
    }
    out
}

/// The index after the brace that closes the one at `open` (string literals
/// skipped).
pub fn matching(code: &str, open: usize) -> usize {
    let b = code.as_bytes();
    let (mut depth, mut i) = (0usize, open);
    while i < b.len() {
        match b[i] {
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
            }
            b'{' | b'(' => depth += 1,
            b'}' | b')' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    b.len()
}

/// The functions of the handlers: name -> (file stem, body), per file.
pub type Functions = Vec<(String, String, String)>;

pub fn functions(files: &[(String, String)]) -> Functions {
    let mut out = Vec::new();
    for (stem, code) in files {
        for (at, _) in code.match_indices("fn ") {
            if at > 0
                && (code.as_bytes()[at - 1].is_ascii_alphanumeric()
                    || code.as_bytes()[at - 1] == b'_')
            {
                continue;
            }
            let rest = &code[at + 3..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() {
                continue;
            }
            // the body: the first brace after the arguments
            let Some(args) = rest.find('(') else { continue };
            let after = at + 3 + matching(rest, args);
            let Some(open) = code[after..].find(['{', ';']).map(|o| after + o) else {
                continue;
            };
            if code.as_bytes()[open] == b';' {
                continue;
            }
            let end = matching(code, open);
            out.push((name, stem.clone(), code[at..end].to_string()));
        }
    }
    out
}

/// The text of a handler and of the functions it calls (in its file first,
/// else defined once among the handlers), a few calls deep.
pub fn closure(
    fns: &Functions,
    stem: &str,
    name: &str,
    depth: u32,
    seen: &mut BTreeSet<String>,
) -> String {
    let key = format!("{stem}::{name}");
    if depth == 0 || !seen.insert(key) {
        return String::new();
    }
    let here: Vec<_> = fns
        .iter()
        .filter(|f| {
            f.0 == name && (f.1 == stem || Path::new(&f.1).file_stem().is_some_and(|s| s == stem))
        })
        .collect();
    let pick = if here.is_empty() {
        let all: Vec<_> = fns.iter().filter(|f| f.0 == name).collect();
        if all.len() == 1 {
            all
        } else {
            Vec::new()
        }
    } else {
        here
    };
    let mut text = String::new();
    for (_, fstem, body) in pick {
        text.push_str(body);
        text.push('\n');
        // the calls: `name(`, `name::<T>(` and `super::module::name(`
        let b = body.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i].is_ascii_alphabetic() || b[i] == b'_' {
                let s = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b':')
                {
                    i += 1;
                }
                let path = &body[s..i];
                if b.get(i) == Some(&b'(') && !path.ends_with(':') {
                    let mut parts = path.rsplit("::");
                    let callee = parts.next().unwrap_or("");
                    let module = match parts.next() {
                        Some("super") | Some("self") | None => fstem.as_str(),
                        Some(m) => m,
                    };
                    if !matches!(
                        callee,
                        "q" | "q_bool"
                            | "q_i64"
                            | "q_set"
                            | "q_all"
                            | "param"
                            | "new"
                            | "from"
                            | "json"
                    ) {
                        text.push_str(&closure(fns, module, callee, depth - 1, seen));
                    }
                }
            } else {
                i += 1;
            }
        }
    }
    text
}
