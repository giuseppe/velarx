// SPDX-License-Identifier: Apache-2.0
//! `--format`: the subset of Go's text/template that podman's commands
//! take, on the JSON of what a command shows.
//!
//! Actions: `{{.Field.Sub}}`, `{{.}}`, `{{$}}`, strings, numbers,
//! pipelines (`{{.X | upper}}`), parentheses, `{{range PIPE}}…{{else}}…
//! {{end}}`, `{{if PIPE}}…{{else if PIPE}}…{{else}}…{{end}}`,
//! `{{with PIPE}}…{{end}}`, trim markers `{{-` and `-}}`.  Functions:
//! `json`, `upper`, `lower`, `title`, `join`, `split`, `len`, `index`,
//! `printf`, `print`, `println`, `pad`, `truncate`, `contains`, `slice`,
//! `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `not`, `and`, `or`, `html`, `js`,
//! `urlquery`.
//! A template that starts with `table` is a table: a header row (the names
//! of its fields, or those the command gives) and columns aligned on the
//! tabs.

use serde_json::Value;
use std::collections::HashMap;

/// A parsed `--format`.
#[derive(Debug, Clone)]
pub struct Template {
    nodes: Vec<Node>,
    table: bool,
}

#[derive(Debug, Clone)]
enum Node {
    Text(String),
    Action(Pipeline),
    /// `{{$x := PIPE}}`
    Assign(String, Pipeline),
    If(Vec<(Pipeline, Vec<Node>)>, Vec<Node>),
    /// the variables of `range $i, $v := PIPE`, its pipeline, its body, its else
    Range(Vec<String>, Pipeline, Vec<Node>, Vec<Node>),
    With(Pipeline, Vec<Node>, Vec<Node>),
}

type Pipeline = Vec<Command>;
type Command = Vec<Arg>;

#[derive(Debug, Clone)]
enum Arg {
    /// `.A.B` (empty: `.`) with no `var`; `$x.A` a field of the
    /// variable `x`, `$.A` of the root (the variable `""`)
    Field {
        var: Option<String>,
        path: Vec<String>,
    },
    Str(String),
    Num(f64),
    Bool(bool),
    Func(String),
    Sub(Pipeline),
    /// the fields of a value: `(...).A.B`
    Chain(Box<Arg>, Vec<String>),
}

impl Template {
    pub fn parse(src: &str) -> Result<Self, String> {
        let trimmed = src.trim_start();
        let (table, body) = match trimmed.strip_prefix("table") {
            Some(rest) if rest.is_empty() || rest.starts_with(char::is_whitespace) => {
                (true, rest.trim_start())
            }
            _ => (false, src),
        };
        let tokens = lex(&unescape(body))?;
        let mut pos = 0;
        let (nodes, end) = parse_nodes(&tokens, &mut pos)?;
        if let Some(e) = end {
            return Err(format!("unexpected {{{{{e}}}}}"));
        }
        let mut nodes = nodes;
        if table {
            tabify(&mut nodes);
        }
        Ok(Self { nodes, table })
    }

    pub fn is_table(&self) -> bool {
        self.table
    }

    /// The text of one value.
    pub fn render(&self, data: &Value) -> Result<String, String> {
        let mut out = String::new();
        let mut vars = vec![(String::new(), data.clone())];
        exec(&self.nodes, data, &mut vars, &mut out)?;
        Ok(out)
    }

    /// The header row of a table: the names of the fields of its actions,
    /// as `headers` names them, else their last component in capitals.
    pub fn header(&self, headers: &HashMap<&str, &str>) -> String {
        let mut out = String::new();
        header_of(&self.nodes, headers, &mut out);
        out
    }

    /// The text of all `items`: one per line (the template's own newlines
    /// kept), a table with its header and aligned columns.
    pub fn render_all(
        &self,
        items: &[Value],
        headers: &HashMap<&str, &str>,
    ) -> Result<String, String> {
        let mut rows = Vec::new();
        if self.table {
            rows.push(self.header(headers));
        }
        for item in items {
            rows.push(self.render(item)?);
        }
        let mut text = if self.table || rows.iter().any(|r| r.contains('\t')) {
            align(&rows)
        } else {
            rows.join("\n")
        };
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        Ok(text)
    }
}

/// `\t` and `\n` written as such in a --format, as podman takes them.
fn unescape(s: &str) -> String {
    s.replace("\\t", "\t").replace("\\n", "\n")
}

/// `text` with its columns aligned on its tabs, as podman's reports.
pub fn align_text(text: &str) -> String {
    let rows: Vec<String> = text.lines().map(str::to_string).collect();
    let mut out = align(&rows);
    if text.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Columns aligned on the tabs of the rows, as Go's tabwriter (minimum
/// width 12, padding 2) for podman's tables.
fn align(rows: &[String]) -> String {
    let cells: Vec<Vec<&str>> = rows.iter().map(|r| r.split('\t').collect()).collect();
    let cols = cells.iter().map(Vec::len).max().unwrap_or(0);
    let mut widths = vec![0usize; cols];
    for r in &cells {
        for (i, c) in r.iter().enumerate().take(r.len().saturating_sub(1)) {
            widths[i] = widths[i].max(c.chars().count());
        }
    }
    let mut out = Vec::new();
    for r in &cells {
        let mut line = String::new();
        for (i, c) in r.iter().enumerate() {
            line.push_str(c);
            if i + 1 < r.len() {
                let w = (widths[i] + 2).max(12);
                line.push_str(&" ".repeat(w - c.chars().count()));
            }
        }
        out.push(line.trim_end().to_string());
    }
    out.join("\n")
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Text(String),
    Action(Vec<Word>),
}

#[derive(Debug, Clone, PartialEq)]
enum Word {
    Ident(String),
    Field(Option<String>, Vec<String>),
    Declare,
    Comma,
    Str(String),
    Num(f64),
    Pipe,
    Open,
    Close,
    /// `.A.B` right after a `)`
    Chain(Vec<String>),
}

fn lex(src: &str) -> Result<Vec<Tok>, String> {
    let mut toks = Vec::new();
    let mut rest = src;
    while let Some(start) = rest.find("{{") {
        let mut text = &rest[..start];
        let mut inner = &rest[start + 2..];
        if let Some(r) = inner
            .strip_prefix('-')
            .filter(|r| r.starts_with(char::is_whitespace))
        {
            text = text.trim_end();
            inner = r;
        }
        let end = inner.find("}}").ok_or("an action without its }}")?;
        let mut action = &inner[..end];
        let mut after = &inner[end + 2..];
        if let Some(a) = action
            .strip_suffix('-')
            .filter(|a| a.ends_with(char::is_whitespace))
        {
            action = a;
            after = after.trim_start();
        }
        if !text.is_empty() {
            toks.push(Tok::Text(text.to_string()));
        }
        toks.push(Tok::Action(words(action)?));
        rest = after;
    }
    if !rest.is_empty() {
        toks.push(Tok::Text(rest.to_string()));
    }
    Ok(toks)
}

fn words(s: &str) -> Result<Vec<Word>, String> {
    let mut out = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '|' {
            out.push(Word::Pipe);
            i += 1;
        } else if c == '(' {
            out.push(Word::Open);
            i += 1;
        } else if c == ')' {
            out.push(Word::Close);
            i += 1;
        } else if c == '"' || c == '`' {
            let mut v = String::new();
            i += 1;
            loop {
                let Some(&ch) = chars.get(i) else {
                    return Err("a string without its end".into());
                };
                i += 1;
                if ch == c {
                    break;
                }
                if ch == '\\' && c == '"' {
                    let Some(&e) = chars.get(i) else {
                        return Err("a string without its end".into());
                    };
                    i += 1;
                    v.push(match e {
                        'n' => '\n',
                        't' => '\t',
                        other => other,
                    });
                } else {
                    v.push(ch);
                }
            }
            out.push(Word::Str(v));
        } else if c == '.' || c == '$' {
            let start = i;
            i += 1;
            while i < chars.len()
                && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '.')
            {
                i += 1;
            }
            let w: String = chars[start..i].iter().collect();
            let (var, rest) = match w.strip_prefix('$') {
                Some(r) => {
                    let (name, rest) = r.split_once('.').unwrap_or((r, ""));
                    (Some(name.to_string()), rest)
                }
                None => (None, w.as_str()),
            };
            let path: Vec<String> = rest
                .split('.')
                .filter(|p| !p.is_empty())
                .map(str::to_string)
                .collect();
            // `(...).Field`: the fields of what the parentheses give
            if var.is_none() && start > 0 && chars[start - 1] == ')' {
                out.push(Word::Chain(path));
            } else {
                out.push(Word::Field(var, path));
            }
        } else if c == ':' && chars.get(i + 1) == Some(&'=') {
            out.push(Word::Declare);
            i += 2;
        } else if c == ',' {
            out.push(Word::Comma);
            i += 1;
        } else if c.is_ascii_digit()
            || (c == '-' && chars.get(i + 1).is_some_and(char::is_ascii_digit))
        {
            let start = i;
            i += 1;
            while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                i += 1;
            }
            let w: String = chars[start..i].iter().collect();
            out.push(Word::Num(w.parse().map_err(|_| format!("bad number {w}"))?));
        } else if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            out.push(Word::Ident(chars[start..i].iter().collect()));
        } else {
            return Err(format!("unexpected `{c}` in an action"));
        }
    }
    Ok(out)
}

/// The nodes up to an `{{end}}` or `{{else…}}`, which is returned.
fn parse_nodes(toks: &[Tok], pos: &mut usize) -> Result<(Vec<Node>, Option<String>), String> {
    let mut nodes = Vec::new();
    while *pos < toks.len() {
        let tok = &toks[*pos];
        *pos += 1;
        match tok {
            Tok::Text(t) => nodes.push(Node::Text(t.clone())),
            Tok::Action(words) => match words.first() {
                Some(Word::Ident(k)) if k == "end" => return Ok((nodes, Some("end".into()))),
                Some(Word::Ident(k)) if k == "else" => {
                    // `else if PIPE` comes back with its pipeline
                    if let Some(Word::Ident(i)) = words.get(1) {
                        if i == "if" {
                            *pos -= 1;
                            return Ok((nodes, Some("else if".into())));
                        }
                    }
                    return Ok((nodes, Some("else".into())));
                }
                Some(Word::Ident(k)) if k == "if" => {
                    let mut branches = vec![(pipeline(&words[1..])?, Vec::new())];
                    let mut otherwise = Vec::new();
                    loop {
                        let (body, end) = parse_nodes(toks, pos)?;
                        match end.as_deref() {
                            Some("end") => {
                                if let Some(last) = branches.last_mut() {
                                    last.1 = body;
                                }
                                break;
                            }
                            Some("else if") => {
                                if let Some(last) = branches.last_mut() {
                                    last.1 = body;
                                }
                                let Tok::Action(w) = &toks[*pos] else {
                                    return Err("bad else if".into());
                                };
                                *pos += 1;
                                branches.push((pipeline(&w[2..])?, Vec::new()));
                            }
                            Some("else") => {
                                if let Some(last) = branches.last_mut() {
                                    last.1 = body;
                                }
                                let (body, end) = parse_nodes(toks, pos)?;
                                if end.as_deref() != Some("end") {
                                    return Err("if without its end".into());
                                }
                                otherwise = body;
                                break;
                            }
                            _ => return Err("if without its end".into()),
                        }
                    }
                    nodes.push(Node::If(branches, otherwise));
                }
                Some(Word::Ident(k)) if k == "range" || k == "with" => {
                    let (vars, rest) = declared(&words[1..])?;
                    if k == "with" && vars.len() > 1 {
                        return Err("with declares one variable".into());
                    }
                    let p = pipeline(rest)?;
                    let (body, end) = parse_nodes(toks, pos)?;
                    let otherwise = match end.as_deref() {
                        Some("end") => Vec::new(),
                        Some("else") => {
                            let (b, e) = parse_nodes(toks, pos)?;
                            if e.as_deref() != Some("end") {
                                return Err(format!("{k} without its end"));
                            }
                            b
                        }
                        _ => return Err(format!("{k} without its end")),
                    };
                    nodes.push(if k == "range" {
                        Node::Range(vars, p, body, otherwise)
                    } else if let Some(v) = vars.into_iter().next() {
                        // `with $x := PIPE`: the value in $x too
                        Node::With(
                            p,
                            vec![Node::Assign(
                                v,
                                vec![vec![Arg::Field {
                                    var: None,
                                    path: Vec::new(),
                                }]],
                            )]
                            .into_iter()
                            .chain(body)
                            .collect(),
                            otherwise,
                        )
                    } else {
                        Node::With(p, body, otherwise)
                    });
                }
                _ => match declared(words)? {
                    (vars, rest) if vars.len() == 1 => nodes.push(Node::Assign(
                        vars.into_iter().next().unwrap_or_default(),
                        pipeline(rest)?,
                    )),
                    (vars, _) if !vars.is_empty() => {
                        return Err("one variable is declared outside of range".into())
                    }
                    _ => nodes.push(Node::Action(pipeline(words)?)),
                },
            },
        }
    }
    Ok((nodes, None))
}

/// The variables declared at the start of `words` (`$x :=`, `$i, $v :=`),
/// and the rest.
fn declared(words: &[Word]) -> Result<(Vec<String>, &[Word]), String> {
    let Some(at) = words.iter().position(|w| *w == Word::Declare) else {
        return Ok((Vec::new(), words));
    };
    let mut vars = Vec::new();
    for (i, w) in words[..at].iter().enumerate() {
        match (i % 2, w) {
            (0, Word::Field(Some(name), path)) if !name.is_empty() && path.is_empty() => {
                vars.push(name.clone())
            }
            (1, Word::Comma) => {}
            _ => return Err("bad variable declaration".into()),
        }
    }
    if vars.is_empty() || vars.len() > 2 || at % 2 == 0 {
        return Err("bad variable declaration".into());
    }
    Ok((vars, &words[at + 1..]))
}

fn pipeline(words: &[Word]) -> Result<Pipeline, String> {
    let mut cmds = Vec::new();
    let mut cmd = Vec::new();
    let mut i = 0;
    while i < words.len() {
        match &words[i] {
            Word::Pipe => cmds.push(std::mem::take(&mut cmd)),
            Word::Open => {
                let mut depth = 1;
                let start = i + 1;
                while depth > 0 {
                    i += 1;
                    match words.get(i) {
                        Some(Word::Open) => depth += 1,
                        Some(Word::Close) => depth -= 1,
                        None => return Err("( without its )".into()),
                        _ => {}
                    }
                }
                cmd.push(Arg::Sub(pipeline(&words[start..i])?));
            }
            Word::Close => return Err(") without its (".into()),
            Word::Chain(path) => match cmd.pop() {
                Some(a @ Arg::Sub(_)) => cmd.push(Arg::Chain(Box::new(a), path.clone())),
                _ => return Err("a field of nothing".into()),
            },
            Word::Declare | Word::Comma => return Err("unexpected := or , in a pipeline".into()),
            Word::Field(var, path) => cmd.push(Arg::Field {
                var: var.clone(),
                path: path.clone(),
            }),
            Word::Str(s) => cmd.push(Arg::Str(s.clone())),
            Word::Num(n) => cmd.push(Arg::Num(*n)),
            Word::Ident(id) if id == "true" || id == "false" => cmd.push(Arg::Bool(id == "true")),
            Word::Ident(id) if id == "nil" => cmd.push(Arg::Str(String::new())),
            Word::Ident(id) => cmd.push(Arg::Func(id.clone())),
        }
        i += 1;
    }
    cmds.push(cmd);
    if cmds.iter().any(Vec::is_empty) {
        return Err("an empty command in a pipeline".into());
    }
    Ok(cmds)
}

/// The variables in scope, innermost last; `$` is `""`.
type Vars = Vec<(String, Value)>;

fn exec(nodes: &[Node], dot: &Value, vars: &mut Vars, out: &mut String) -> Result<(), String> {
    for n in nodes {
        match n {
            Node::Text(t) => out.push_str(t),
            Node::Action(p) => out.push_str(&text(&eval(p, dot, vars)?)),
            Node::Assign(name, p) => {
                let v = eval(p, dot, vars)?;
                vars.push((name.clone(), v));
            }
            Node::If(branches, otherwise) => {
                let mut done = false;
                for (p, body) in branches {
                    if truth(&eval(p, dot, vars)?) {
                        scoped(body, dot, vars, out)?;
                        done = true;
                        break;
                    }
                }
                if !done {
                    scoped(otherwise, dot, vars, out)?;
                }
            }
            Node::With(p, body, otherwise) => {
                let v = eval(p, dot, vars)?;
                if truth(&v) {
                    scoped(body, &v, vars, out)?;
                } else {
                    scoped(otherwise, dot, vars, out)?;
                }
            }
            Node::Range(names, p, body, otherwise) => {
                let v = eval(p, dot, vars)?;
                let items: Vec<(Value, Value)> = match &v {
                    Value::Array(a) => a
                        .iter()
                        .enumerate()
                        .map(|(i, x)| (serde_json::json!(i), x.clone()))
                        .collect(),
                    Value::Object(o) => {
                        let mut keys: Vec<&String> = o.keys().collect();
                        keys.sort();
                        keys.into_iter()
                            .map(|k| (Value::String(k.clone()), o[k].clone()))
                            .collect()
                    }
                    Value::Null => Vec::new(),
                    _ => return Err(format!("range over {}", text(&v))),
                };
                if items.is_empty() {
                    scoped(otherwise, dot, vars, out)?;
                }
                for (key, item) in &items {
                    let depth = vars.len();
                    match names.as_slice() {
                        [v] => vars.push((v.clone(), item.clone())),
                        [k, v] => {
                            vars.push((k.clone(), key.clone()));
                            vars.push((v.clone(), item.clone()));
                        }
                        _ => {}
                    }
                    let r = exec(body, item, vars, out);
                    vars.truncate(depth);
                    r?;
                }
            }
        }
    }
    Ok(())
}

/// `nodes` with the variables they declare gone at their end.
fn scoped(nodes: &[Node], dot: &Value, vars: &mut Vars, out: &mut String) -> Result<(), String> {
    let depth = vars.len();
    let r = exec(nodes, dot, vars, out);
    vars.truncate(depth);
    r
}

/// The Go names of podman's fields whose JSON names differ: a template
/// sees the Go ones.
const GO_NAMES: &[(&str, &str)] = &[
    ("HealthMaxLogCount", "HealthcheckMaxLogCount"),
    ("HealthMaxLogSize", "HealthcheckMaxLogSize"),
];

/// The zero value of a field of a Go struct, printed when the JSON has
/// none.
#[derive(Clone, Copy)]
enum Zero {
    Str,
    Num,
    List,
    Map,
    Duration,
}

/// podman's structs that templates print whole (`{{.State.Health}}`): the
/// name of the field that holds one (or a list of them) and the fields in
/// Go's order.  Go prints a struct as `{V1 V2 ...}`, where a map of JSON
/// would print as `map[K:V ...]`.
const GO_STRUCTS: &[(&str, &[(&str, Zero)])] = &[
    (
        "Healthcheck",
        &[
            ("Test", Zero::List),
            ("StartPeriod", Zero::Duration),
            ("StartInterval", Zero::Duration),
            ("Interval", Zero::Duration),
            ("Timeout", Zero::Duration),
            ("Retries", Zero::Num),
        ],
    ),
    (
        "Health",
        &[
            ("Status", Zero::Str),
            ("FailingStreak", Zero::Num),
            ("Log", Zero::List),
        ],
    ),
    (
        "Log",
        &[
            ("Start", Zero::Str),
            ("End", Zero::Str),
            ("ExitCode", Zero::Num),
            ("Output", Zero::Str),
        ],
    ),
    (
        "RestartPolicy",
        &[("Name", Zero::Str), ("MaximumRetryCount", Zero::Num)],
    ),
    (
        "Ulimits",
        &[
            ("Name", Zero::Str),
            ("Soft", Zero::Num),
            ("Hard", Zero::Num),
        ],
    ),
    (
        "LogConfig",
        &[
            ("Type", Zero::Str),
            ("Config", Zero::Map),
            ("Path", Zero::Str),
            ("Tag", Zero::Str),
            ("Size", Zero::Str),
        ],
    ),
    (
        "Mounts",
        &[
            ("Type", Zero::Str),
            ("Name", Zero::Str),
            ("Source", Zero::Str),
            ("Destination", Zero::Str),
            ("Driver", Zero::Str),
            ("Mode", Zero::Str),
            ("Options", Zero::List),
            ("RW", Zero::Num),
            ("Propagation", Zero::Str),
            ("SubPath", Zero::Str),
        ],
    ),
];

/// The key of a Go struct in the data of a template: its fields in Go's
/// order, `[[name, value, given]...]` (the zero values the JSON did not
/// have are not given: its `json` leaves them out).
const GO_STRUCT: &str = "\u{2}go-struct";

/// `v`, the value of the field `name`, as the Go struct (or list of them)
/// podman has there.
fn as_go_struct(name: &str, v: Value) -> Value {
    let Some((_, fields)) = GO_STRUCTS.iter().find(|(n, _)| *n == name) else {
        return v;
    };
    let one = |o: &serde_json::Map<String, Value>| {
        let pairs: Vec<Value> = fields
            .iter()
            .map(|(f, zero)| {
                // (a null is the zero value too: a nil map prints map[])
                let value = match (o.get(*f).filter(|v| !v.is_null()), zero) {
                    (Some(v), _) => as_go_struct(f, v.clone()),
                    (None, Zero::Str) => Value::String(String::new()),
                    (None, Zero::Num) => 0.into(),
                    (None, Zero::List) => Value::Array(Vec::new()),
                    (None, Zero::Map) => Value::Object(Default::default()),
                    (None, Zero::Duration) => go_duration_value(0),
                };
                serde_json::json!([f, value, o.contains_key(*f)])
            })
            .collect();
        serde_json::json!({ GO_STRUCT: pairs })
    };
    match v {
        Value::Object(o) if as_go_duration(&Value::Object(o.clone())).is_none() => one(&o),
        Value::Array(a) => Value::Array(
            a.into_iter()
                .map(|e| match e {
                    Value::Object(o) => one(&o),
                    e => e,
                })
                .collect(),
        ),
        v => v,
    }
}

/// The fields of a Go struct of the data, in order.
fn go_struct_fields(v: &Value) -> Option<&Vec<Value>> {
    match v {
        Value::Object(o) if o.len() == 1 => o.get(GO_STRUCT).and_then(Value::as_array),
        _ => None,
    }
}

/// A Go struct of the data as a JSON object: with `all` the zero values
/// too, as its fields are seen.
fn go_struct_object(fields: &[Value], all: bool) -> Value {
    Value::Object(
        fields
            .iter()
            .filter(|p| all || p[2] == true)
            .filter_map(|p| Some((p[0].as_str()?.to_string(), plain(&p[1]))))
            .collect(),
    )
}

/// The key of a Go `time.Duration` in the data of a template: `%v` prints
/// it as Go does (`6s`), `json` as the nanoseconds it is.
const GO_DURATION: &str = "\u{0}go-duration";

/// A Go `time.Duration` of `ns` nanoseconds, as a template sees it.
pub fn go_duration_value(ns: i64) -> Value {
    serde_json::json!({ GO_DURATION: ns })
}

fn as_go_duration(v: &Value) -> Option<i64> {
    match v {
        Value::Object(o) if o.len() == 1 => o.get(GO_DURATION).and_then(Value::as_i64),
        _ => None,
    }
}

/// `v` as its JSON shows it: the durations as numbers.
fn plain(v: &Value) -> Value {
    if let Some(ns) = as_go_duration(v) {
        return ns.into();
    }
    if let Some(fields) = go_struct_fields(v) {
        return go_struct_object(fields, false);
    }
    match v {
        Value::String(s) if s == NIL => Value::Null,
        Value::Object(o) => Value::Object(
            o.iter()
                .filter(|(k, _)| *k != GO_TYPE)
                .map(|(k, v)| (k.clone(), plain(v)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(plain).collect()),
        other => other.clone(),
    }
}

/// What a pointer field of Go that is not there is: it prints `<nil>`,
/// where a key missing in a map prints `<no value>`.
pub(super) const NIL: &str = "\u{1}<nil>";

/// The key of the Go type of an object of the data that is a struct with
/// all its fields there: a field it does not have fails, as Go's (`can't
/// evaluate field X in type T`), where a key missing in a map prints
/// `<no value>`.
pub(super) const GO_TYPE: &str = "\u{3}go-type";

/// The pointer fields of podman's inspect output that its JSON leaves out
/// when they are nil, with the field they are in (`""`: any).
const NIL_POINTERS: &[(&str, &str)] = &[
    ("", "StartupHealthCheck"),
    ("", "HealthCheck"),
    ("", "SizeRw"),
    // (`version` with no engine service)
    ("", "Server"),
    ("", "Healthcheck"),
    ("State", "Health"),
];

fn nil_pointer(path: &[String], i: usize) -> bool {
    NIL_POINTERS.iter().any(|(parent, name)| {
        *name == path[i] && (parent.is_empty() || (i > 0 && path[i - 1] == *parent))
    })
}

fn field(v: &Value, path: &[String]) -> Result<Value, String> {
    // (podman's State has a method Healthcheck, its Health)
    let path: Vec<String> = path
        .iter()
        .enumerate()
        .map(
            |(i, p)| match (i.checked_sub(1).map(|j| path[j].as_str()), p.as_str()) {
                (Some("State"), "Healthcheck") => "Health".to_string(),
                _ => p.clone(),
            },
        )
        .collect();
    let path = path.as_slice();
    let mut cur = v.clone();
    for (i, p) in path.iter().enumerate() {
        let last = i + 1 == path.len();
        if let Some(fields) = go_struct_fields(&cur) {
            cur = go_struct_object(fields, true);
        }
        cur = match &cur {
            Value::Object(o) if o.contains_key(GO_TYPE) => match o.get(p) {
                Some(v) => v.clone(),
                None => {
                    return Err(format!(
                        "at <.{}>: can't evaluate field {p} in type {}",
                        path[..=i].join("."),
                        text(&o[GO_TYPE])
                    ))
                }
            },
            Value::Object(o) => match o.get(p).or_else(|| {
                // podman's fields are Go's: a JSON key in another case
                // (`dns_enabled` is `.DNSEnabled`), or another name
                o.iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(p))
                    .or_else(|| {
                        o.iter().find(|(k, _)| {
                            k.contains('_') && k.replace('_', "").eq_ignore_ascii_case(p)
                        })
                    })
                    .map(|(_, v)| v)
                    .or_else(|| {
                        GO_NAMES
                            .iter()
                            .find(|(go, _)| go == p)
                            .and_then(|(_, json)| o.get(*json))
                    })
            }) {
                Some(v) => v.clone(),
                None if last && nil_pointer(path, i) => Value::String(NIL.into()),
                // (Go fails on a field of a nil pointer; podman's version
                // template has a Server whose fields are there)
                None if nil_pointer(path, i) => {
                    let Some((_, go_type)) = NIL_POINTER_TYPES.iter().find(|(n, _)| n == p) else {
                        return Ok(Value::Null);
                    };
                    return Err(format!(
                        "at <.{}>: nil pointer evaluating *{go_type}.{}",
                        path.join("."),
                        path[i + 1]
                    ));
                }
                None => Value::Null,
            },
            _ => Value::Null,
        };
    }
    Ok(match path.last() {
        Some(name) => as_go_struct(name, cur),
        None => cur,
    })
}

/// The Go types of the pointers of [`NIL_POINTERS`], for the error of a
/// field of one that is nil.
const NIL_POINTER_TYPES: &[(&str, &str)] = &[
    ("Healthcheck", "manifest.Schema2HealthConfig"),
    ("StartupHealthCheck", "define.StartupHealthCheck"),
    ("Health", "define.HealthCheckResults"),
];

fn eval(p: &Pipeline, dot: &Value, vars: &Vars) -> Result<Value, String> {
    let mut prev: Option<Value> = None;
    for cmd in p {
        let mut args: Vec<Value> = Vec::new();
        let func = match &cmd[0] {
            Arg::Func(f) => Some(f.clone()),
            _ => None,
        };
        let operands = if func.is_some() { &cmd[1..] } else { &cmd[..] };
        for a in operands {
            args.push(match a {
                Arg::Field { var: None, path } => field(dot, path)?,
                Arg::Field {
                    var: Some(name),
                    path,
                } => match vars.iter().rev().find(|(n, _)| n == name) {
                    Some((_, v)) => field(v, path)?,
                    None => return Err(format!("undefined variable ${name}")),
                },
                Arg::Str(s) => Value::String(s.clone()),
                Arg::Num(n) => serde_json::json!(n),
                Arg::Bool(b) => Value::Bool(*b),
                Arg::Sub(p) => eval(p, dot, vars)?,
                Arg::Chain(sub, path) => match sub.as_ref() {
                    Arg::Sub(p) => field(&eval(p, dot, vars)?, path)?,
                    _ => return Err("a field of nothing".into()),
                },
                Arg::Func(f) => call(f, Vec::new())?,
            });
        }
        if let Some(v) = prev.take() {
            args.push(v);
        }
        prev = Some(match func {
            Some(f) => call(&f, args)?,
            None if args.len() > 1 => {
                // a method of podman's objects: `{{.Label "key"}}`
                let (Arg::Field { var, path }, Some((_, rest))) = (&cmd[0], args.split_first())
                else {
                    return Err("a value with arguments".into());
                };
                let Some((name, parent)) = path.split_last() else {
                    return Err("a value with arguments".into());
                };
                let receiver = match var {
                    None => field(dot, parent)?,
                    Some(v) => match vars.iter().rev().find(|(n, _)| n == v) {
                        Some((_, val)) => field(val, parent)?,
                        None => return Err(format!("undefined variable ${v}")),
                    },
                };
                method(&receiver, name, rest)?
            }
            None => args.remove(0),
        });
    }
    Ok(prev.unwrap_or(Value::Null))
}

/// The methods of podman's objects that its templates call.
fn method(receiver: &Value, name: &str, args: &[Value]) -> Result<Value, String> {
    match (name, args) {
        // ps and pod ps: a label by its key, "" if not there
        ("Label", [key]) => {
            let key = text(key);
            Ok(match &receiver["Labels"] {
                Value::Object(o) => o.get(&key).cloned().unwrap_or(Value::String(String::new())),
                // (the labels as ps shows them: "k=v,k2=v2")
                Value::String(s) => Value::String(
                    s.split(',')
                        .find_map(|kv| {
                            kv.split_once('=')
                                .filter(|(k, _)| *k == key)
                                .map(|(_, v)| v.to_string())
                        })
                        .unwrap_or_default(),
                ),
                _ => Value::String(String::new()),
            })
        }
        _ => Err(format!(
            "can't call method/function {name:?} with {} arguments",
            args.len()
        )),
    }
}

fn call(f: &str, args: Vec<Value>) -> Result<Value, String> {
    let n = |k: usize| -> Result<(), String> {
        if args.len() == k {
            Ok(())
        } else {
            Err(format!("{f} takes {k} argument(s)"))
        }
    };
    Ok(match f {
        "json" => {
            n(1)?;
            Value::String(serde_json::to_string(&plain(&args[0])).map_err(|e| e.to_string())?)
        }
        "upper" => {
            n(1)?;
            Value::String(text(&args[0]).to_uppercase())
        }
        "lower" => {
            n(1)?;
            Value::String(text(&args[0]).to_lowercase())
        }
        "title" => {
            n(1)?;
            let t = text(&args[0]);
            let mut c = t.chars();
            Value::String(
                c.next()
                    .map(|f| f.to_uppercase().chain(c).collect())
                    .unwrap_or_default(),
            )
        }
        "len" => {
            n(1)?;
            serde_json::json!(match &args[0] {
                Value::Array(a) => a.len(),
                Value::Object(o) => o.len(),
                Value::String(s) if s == NIL => return Err("len of nil pointer".into()),
                Value::String(s) => s.chars().count(),
                Value::Null => 0,
                other => return Err(format!("len of {}", text(other))),
            })
        }
        "join" => {
            n(2)?;
            let items = match &args[0] {
                Value::Array(a) => a.iter().map(text).collect::<Vec<_>>(),
                Value::Null => Vec::new(),
                other => vec![text(other)],
            };
            Value::String(items.join(&text(&args[1])))
        }
        "split" => {
            n(2)?;
            let s = text(&args[0]);
            Value::Array(
                s.split(&text(&args[1]))
                    .map(|p| Value::String(p.into()))
                    .collect(),
            )
        }
        "contains" => {
            n(2)?;
            Value::Bool(text(&args[0]).contains(&text(&args[1])))
        }
        "truncate" => {
            n(2)?;
            let s = text(&args[0]);
            let k = args[1].as_f64().unwrap_or(0.0).max(0.0) as usize;
            Value::String(s.chars().take(k).collect())
        }
        "index" => {
            if args.is_empty() {
                return Err("index takes a value".into());
            }
            let mut cur = args[0].clone();
            for k in &args[1..] {
                cur = match (&cur, k) {
                    (Value::Object(o), _) => o.get(&text(k)).cloned().unwrap_or(Value::Null),
                    (Value::Array(a), Value::Number(i)) => a
                        .get(i.as_f64().unwrap_or(-1.0) as usize)
                        .cloned()
                        .unwrap_or(Value::Null),
                    _ => Value::Null,
                };
            }
            cur
        }
        "printf" => {
            if args.is_empty() {
                return Err("printf takes a format".into());
            }
            Value::String(printf(&text(&args[0]), &args[1..]))
        }
        "print" => Value::String(go_sprint(&args)),
        "println" => Value::String(args.iter().map(text).collect::<Vec<_>>().join(" ") + "\n"),
        "pad" => {
            n(3)?;
            let s = text(&args[0]);
            // (Go's: the paddings are integers, a negative one is none)
            let count = |v: &Value| match v.as_f64().filter(|f| f.fract() == 0.0) {
                Some(n) => Ok(n.clamp(0.0, 65536.0) as usize),
                None => Err(format!("pad: expected integer; found {v}")),
            };
            let (left, right) = (count(&args[1])?, count(&args[2])?);
            if s.is_empty() {
                Value::String(s)
            } else {
                Value::String(format!("{}{s}{}", " ".repeat(left), " ".repeat(right)))
            }
        }
        "slice" => {
            if args.is_empty() || args.len() > 4 {
                return Err("slice takes a value and up to three indexes".into());
            }
            let idx = args[1..]
                .iter()
                .map(|v| match v.as_f64() {
                    Some(f) if f >= 0.0 => Ok(f as usize),
                    _ => Err(format!("slice index {} is not a number", text(v))),
                })
                .collect::<Result<Vec<_>, _>>()?;
            match &args[0] {
                Value::String(s) => {
                    let b = s.as_bytes();
                    let (i, j) = (
                        idx.first().copied().unwrap_or(0),
                        idx.get(1).copied().unwrap_or(b.len()),
                    );
                    if idx.len() > 2 {
                        return Err("cannot 3-index slice a string".into());
                    }
                    if i > j || j > b.len() {
                        return Err(format!("index out of range: {}", j.max(i)));
                    }
                    Value::String(String::from_utf8_lossy(&b[i..j]).into_owned())
                }
                Value::Array(a) => {
                    let (i, j) = (
                        idx.first().copied().unwrap_or(0),
                        idx.get(1).copied().unwrap_or(a.len()),
                    );
                    if i > j || j > a.len() {
                        return Err(format!("index out of range: {}", j.max(i)));
                    }
                    Value::Array(a[i..j].to_vec())
                }
                other => return Err(format!("can't slice item of type {}", kind(other))),
            }
        }
        "eq" => {
            if args.len() < 2 {
                return Err("eq takes at least 2 arguments".into());
            }
            Value::Bool(args[1..].iter().any(|b| text(&args[0]) == text(b)))
        }
        "lt" | "le" | "gt" | "ge" => {
            n(2)?;
            let ord = compare(&args[0], &args[1])?;
            Value::Bool(match f {
                "lt" => ord.is_lt(),
                "le" => ord.is_le(),
                "gt" => ord.is_gt(),
                _ => ord.is_ge(),
            })
        }
        "html" => Value::String(escape_html(&go_sprint(&args))),
        "js" => Value::String(escape_js(&go_sprint(&args))),
        "urlquery" => Value::String(escape_query(&go_sprint(&args))),
        "ne" => {
            n(2)?;
            Value::Bool(text(&args[0]) != text(&args[1]))
        }
        "not" => {
            n(1)?;
            Value::Bool(!truth(&args[0]))
        }
        "and" => Value::Bool(args.iter().all(truth)),
        "or" => Value::Bool(args.iter().any(truth)),
        other => return Err(format!("function \"{other}\" not defined")),
    })
}

/// Go's `fmt.Sprint`: a space between two operands when neither is a
/// string.
fn go_sprint(args: &[Value]) -> String {
    let mut out = String::new();
    for (i, a) in args.iter().enumerate() {
        if i > 0 && !args[i - 1].is_string() && !a.is_string() {
            out.push(' ');
        }
        out.push_str(&text(a));
    }
    out
}

/// The kind of a value as Go's errors name it.
fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "nil",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "slice",
        Value::Object(_) => "map",
    }
}

/// The order of two values of `lt`, `le`, `gt` and `ge`: numbers by value,
/// strings by bytes, others are not comparable.
fn compare(a: &Value, b: &Value) -> Result<std::cmp::Ordering, String> {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x
            .as_f64()
            .zip(y.as_f64())
            .and_then(|(x, y)| x.partial_cmp(&y))
            .ok_or_else(|| "incompatible types for comparison".into()),
        (Value::String(x), Value::String(y)) => Ok(x.as_bytes().cmp(y.as_bytes())),
        (Value::Bool(_), Value::Bool(_)) | (Value::Null, _) | (_, Value::Null) => {
            Err("invalid type for comparison".into())
        }
        _ => Err("incompatible types for comparison".into()),
    }
}

/// Go's `template.HTMLEscapeString`.
fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\0' => out.push('\u{FFFD}'),
            c => out.push(c),
        }
    }
    out
}

/// Go's `template.JSEscapeString`.
fn escape_js(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '"' => out.push_str("\\\""),
            '<' => out.push_str("\\u003C"),
            '>' => out.push_str("\\u003E"),
            '&' => out.push_str("\\u0026"),
            '=' => out.push_str("\\u003D"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Go's `url.QueryEscape`.
fn escape_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            b => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn printf(fmt: &str, args: &[Value]) -> String {
    let mut out = String::new();
    let mut it = args.iter();
    let mut chars = fmt.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        // flags and width are taken but not applied, but for %-Ns
        let mut spec = String::new();
        while let Some(&d) = chars.peek() {
            if d.is_ascii_digit() || d == '-' || d == '.' {
                spec.push(d);
                chars.next();
            } else {
                break;
            }
        }
        match chars.next() {
            Some('%') => out.push('%'),
            Some(v @ ('s' | 'v' | 'd' | 'q')) => {
                let a = it.next().map(text).unwrap_or_default();
                let a = if v == 'q' { format!("{a:?}") } else { a };
                let width: usize = spec
                    .trim_start_matches('-')
                    .split('.')
                    .next()
                    .and_then(|w| w.parse().ok())
                    .unwrap_or(0);
                if spec.starts_with('-') {
                    out.push_str(&format!("{a:<width$}"));
                } else {
                    out.push_str(&format!("{a:>width$}"));
                }
            }
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

fn truth(v: &Value) -> bool {
    if let Some(ns) = as_go_duration(v) {
        return ns != 0;
    }
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty() && s != NIL,
        // (a struct of Go is true)
        Value::Object(_) if go_struct_fields(v).is_some() => true,
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// A value as Go's `%v` prints it.
pub fn text(v: &Value) -> String {
    if let Some(ns) = as_go_duration(v) {
        return velarx_proto::duration::go_duration_string(ns);
    }
    match v {
        Value::Null => "<no value>".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => match (n.as_i64(), n.as_u64(), n.as_f64()) {
            (Some(i), _, _) => i.to_string(),
            (_, Some(u), _) => u.to_string(),
            (_, _, Some(f)) if f.fract() == 0.0 && f.abs() < 1e15 => format!("{}", f as i64),
            (_, _, Some(f)) => f.to_string(),
            _ => n.to_string(),
        },
        Value::String(s) if s == NIL => "<nil>".into(),
        Value::String(s) => s.clone(),
        Value::Array(a) => format!("[{}]", a.iter().map(text).collect::<Vec<_>>().join(" ")),
        Value::Object(_) if go_struct_fields(v).is_some() => {
            let fields = go_struct_fields(v).into_iter().flatten();
            let values: Vec<String> = fields.map(|p| text(&p[1])).collect();
            format!("{{{}}}", values.join(" "))
        }
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().filter(|k| *k != GO_TYPE).collect();
            keys.sort();
            format!(
                "map[{}]",
                keys.iter()
                    .map(|k| format!("{k}:{}", text(&o[*k])))
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        }
    }
}

fn header_of(nodes: &[Node], headers: &HashMap<&str, &str>, out: &mut String) {
    for n in nodes {
        match n {
            Node::Text(t) => out.push_str(t),
            Node::Action(p) => {
                let name = p
                    .first()
                    .and_then(|c| {
                        c.iter().rev().find_map(|a| match a {
                            Arg::Field { path, .. } => path.last().cloned(),
                            _ => None,
                        })
                    })
                    .unwrap_or_default();
                match headers.get(name.as_str()) {
                    Some(h) => out.push_str(h),
                    None => out.push_str(&name.to_uppercase()),
                }
            }
            Node::If(branches, _) => {
                if let Some((_, b)) = branches.first() {
                    header_of(b, headers, out)
                }
            }
            Node::Range(_, _, b, _) | Node::With(_, b, _) => header_of(b, headers, out),
            Node::Assign(..) => {}
        }
    }
}

/// The columns of a table: as podman's, each space of its text (the actions
/// have their own) separates two.
fn tabify(nodes: &mut [Node]) {
    for node in nodes {
        match node {
            Node::Text(t) => *t = t.replace(' ', "\t"),
            Node::If(branches, other) => {
                for (_, body) in branches {
                    tabify(body);
                }
                tabify(other);
            }
            Node::Range(_, _, body, other) | Node::With(_, body, other) => {
                tabify(body);
                tabify(other);
            }
            Node::Action(_) | Node::Assign(..) => {}
        }
    }
}

/// `--format` of a list: `json` (the whole list), else a template applied
/// to each item.
pub fn format_list(
    format: &str,
    items: &[Value],
    headers: &HashMap<&str, &str>,
) -> Result<String, String> {
    if format == "json" {
        let mut s = serde_json::to_string_pretty(items).map_err(|e| e.to_string())?;
        s.push('\n');
        return Ok(s);
    }
    Template::parse(format)?.render_all(items, headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn r(t: &str, v: Value) -> String {
        Template::parse(t).unwrap().render(&v).unwrap()
    }

    #[test]
    fn the_functions_of_go_and_podman() {
        let v = json!({"ID": "abcdef", "Names": ["web", "w"], "N": 3, "Empty": ""});
        assert_eq!(r("[{{pad .ID 1 2}}]", v.clone()), "[ abcdef  ]");
        assert_eq!(r("[{{pad .Empty 1 2}}]", v.clone()), "[]");
        assert!(Template::parse("{{pad .ID 3 \"x\"}}")
            .unwrap()
            .render(&v)
            .is_err());
        assert_eq!(r("{{print .ID}}", v.clone()), "abcdef");
        assert_eq!(r("{{print 1 2 \"a\" 3}}", v.clone()), "1 2a3");
        assert_eq!(r("{{println .ID .N}}", v.clone()), "abcdef 3\n");
        assert_eq!(r("{{slice .ID 1 3}}", v.clone()), "bc");
        assert_eq!(r("{{slice .ID 2}}", v.clone()), "cdef");
        assert_eq!(r("{{slice .Names 1}}", v.clone()), "[w]");
        assert!(Template::parse("{{slice .ID 3 9}}")
            .unwrap()
            .render(&v)
            .is_err());
        assert_eq!(
            r("{{lt 1 2}} {{le 2 2}} {{gt 1 2}} {{ge 1 2}}", v.clone()),
            "true true false false"
        );
        assert_eq!(r("{{lt .N 4}} {{lt \"a\" \"b\"}}", v.clone()), "true true");
        assert!(Template::parse("{{lt 1 \"a\"}}")
            .unwrap()
            .render(&v)
            .is_err());
        assert_eq!(r("{{eq .N 1 2 3}} {{eq .N 1}}", v.clone()), "true false");
        assert_eq!(
            r("{{html \"<a href='x'>&\"}}", v.clone()),
            "&lt;a href=&#39;x&#39;&gt;&amp;"
        );
        assert_eq!(r("{{js \"a='b'\"}}", v.clone()), "a\\u003D\\'b\\'");
        assert_eq!(r("{{urlquery \"a b&c/d\"}}", v.clone()), "a+b%26c%2Fd");
    }

    #[test]
    fn the_go_fields_of_snake_case_keys_and_nil_pointers() {
        let n = json!({"dns_enabled": true, "network_interface": "br0", "ipv6_enabled": false});
        assert_eq!(
            r("{{.DNSEnabled}} {{.NetworkInterface}} {{.IPv6Enabled}}", n),
            "true br0 false"
        );
        // a pointer that is there in another case is not nil
        let i = json!({"Healthcheck": {"Test": ["CMD", "true"]}});
        assert_eq!(r("{{.HealthCheck.Test}}", i), "[CMD true]");
        assert_eq!(r("{{.HealthCheck}}", json!({})), "<nil>");
        assert_eq!(r("{{if .Server}}y{{else}}n{{end}}", json!({})), "n");
    }

    #[test]
    fn fields_functions_and_pipelines() {
        let v = json!({"ID": "abcdef0123456789", "Names": ["web", "w"], "State": {"Status": "running", "Pid": 42},
                       "Labels": {"b": "2", "a": "1"}, "Empty": "", "N": 3});
        assert_eq!(
            r("{{.ID}} {{.State.Status}}", v.clone()),
            "abcdef0123456789 running"
        );
        assert_eq!(r("{{.state.status}}", v.clone()), "running");
        assert_eq!(r("{{.Missing}}", v.clone()), "<no value>");
        // a nil pointer of Go, not a missing key
        let c = serde_json::json!({"Config": {}});
        assert_eq!(r("{{.Config.StartupHealthCheck}}", c.clone()), "<nil>");
        assert_eq!(
            r(
                "{{if .Config.StartupHealthCheck}}y{{else}}n{{end}}",
                c.clone()
            ),
            "n"
        );
        // json of it is null, as Go's; State.Health too, only there
        assert_eq!(r("{{json .Config.Healthcheck}}", c.clone()), "null");
        let st = serde_json::json!({"State": {}, "Health": 1});
        assert_eq!(r("{{.State.Health}}", st.clone()), "<nil>");
        assert_eq!(r("{{json .State.Health}}", st.clone()), "null");
        assert_eq!(r("{{.State.Nope}}", st), "<no value>");
        assert_eq!(r("{{.State.Pid}}", v.clone()), "42");
        assert_eq!(r("{{json .Names}}", v.clone()), r#"["web","w"]"#);
        assert_eq!(r("{{.Names | json}}", v.clone()), r#"["web","w"]"#);
        assert_eq!(r("{{join .Names \",\"}}", v.clone()), "web,w");
        assert_eq!(r("{{upper .State.Status}}", v.clone()), "RUNNING");
        assert_eq!(r("{{len .Names}}", v.clone()), "2");
        assert_eq!(r("{{index .Labels \"a\"}}", v.clone()), "1");
        assert_eq!(r("{{.Labels}}", v.clone()), "map[a:1 b:2]");
        assert_eq!(r("{{.Names}}", v.clone()), "[web w]");
        assert_eq!(r("{{truncate .ID 12}}", v.clone()), "abcdef012345");
        assert_eq!(
            r("{{printf \"%s-%d\" .State.Status .N}}", v.clone()),
            "running-3"
        );
        assert_eq!(
            r("{{printf \"%-8s|\" .State.Status}}", v.clone()),
            "running |"
        );
        assert_eq!(r("{{(index .Names 0) | upper}}", v.clone()), "WEB");
        assert_eq!(
            r("{{$.ID}} {{$.State.Status}}", v.clone()),
            "abcdef0123456789 running"
        );
        assert_eq!(r("{{json .}}", json!({"a": 1})), r#"{"a":1}"#);
        assert_eq!(
            r("{{(index .Names 1).x}}", json!({"Names": [{}, {"x": "y"}]})),
            "y"
        );
        assert_eq!(
            r(
                "{{index (index .L 0).A \"k\"}}",
                json!({"L": [{"A": {"k": "v"}}]})
            ),
            "v"
        );
        assert_eq!(r("{{ .Label \"a\" }}|{{.Label \"x\"}}", v.clone()), "1|");
        assert_eq!(r("{{.Label \"k\"}}", json!({"Labels": "j=1,k=2"})), "2");
        assert!(Template::parse("{{.ID 1}}").unwrap().render(&v).is_err());
        assert_eq!(r("a\\tb\\n", json!({})), "a\tb\n");
    }

    #[test]
    fn control_structures() {
        let v = json!({"Names": ["a", "b"], "On": true, "None": [], "S": "x", "M": {"k": "v"}});
        assert_eq!(r("{{range .Names}}<{{.}}>{{end}}", v.clone()), "<a><b>");
        assert_eq!(
            r("{{range .None}}x{{else}}empty{{end}}", v.clone()),
            "empty"
        );
        assert_eq!(r("{{if .On}}yes{{else}}no{{end}}", v.clone()), "yes");
        assert_eq!(
            r("{{if .None}}yes{{else if .S}}s{{else}}no{{end}}", v.clone()),
            "s"
        );
        assert_eq!(r("{{if eq .S \"x\"}}eq{{end}}", v.clone()), "eq");
        assert_eq!(r("{{with .M}}{{.k}}{{end}}", v.clone()), "v");
        assert_eq!(r("{{- range .Names -}} {{.}} {{- end}}", v.clone()), "ab");
        assert_eq!(
            r("{{range $i, $n := .Names}}{{$i}}={{$n}} {{end}}", v.clone()),
            "0=a 1=b "
        );
        assert_eq!(
            r("{{range $k, $v := .M}}{{$k}}:{{$v}}{{end}}", v.clone()),
            "k:v"
        );
        assert_eq!(
            r("{{range $n := .Names}}{{$n}}{{$.S}}{{end}}", v.clone()),
            "axbx"
        );
        assert_eq!(r("{{$x := .S}}{{$x}}{{$x | upper}}", v.clone()), "xX");
        assert_eq!(r("{{with $m := .M}}{{$m.k}}{{end}}", v.clone()), "v");
        assert!(Template::parse("{{range $n := .Names}}{{end}}{{$n}}")
            .unwrap()
            .render(&v)
            .is_err());
        assert!(Template::parse("{{$a, $b, $c := .X}}").is_err());
        assert!(Template::parse("{{range .Names}}").is_err());
        assert!(Template::parse("{{end}}").is_err());
        assert!(Template::parse("{{.X").is_err());
        assert!(Template::parse("{{nosuch .X}}")
            .unwrap()
            .render(&v)
            .is_err());
    }

    #[test]
    fn tables_and_json() {
        let items = vec![
            json!({"ID": "a1", "Names": "web"}),
            json!({"ID": "b22222222222222", "Names": "db"}),
        ];
        let headers = HashMap::from([("ID", "CONTAINER ID")]);
        let out = format_list("table {{.ID}}\t{{.Names}}", &items, &headers).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "CONTAINER ID     NAMES");
        assert_eq!(lines[1], "a1               web");
        assert_eq!(lines[2], "b22222222222222  db");
        assert_eq!(
            format_list("{{.ID}}", &items, &headers).unwrap(),
            "a1\nb22222222222222\n"
        );
        let j: Value =
            serde_json::from_str(&format_list("json", &items, &headers).unwrap()).unwrap();
        assert_eq!(j, json!(items));
    }

    #[test]
    fn durations_print_as_go_prints_them() {
        for (ns, want) in [
            (0, "0s"),
            (6_000_000_000, "6s"),
            (90_000_000_000, "1m30s"),
            (3_600_000_000_000, "1h0m0s"),
            (1_500_000_000, "1.5s"),
            (500_000_000, "500ms"),
            (1_234_567, "1.234567ms"),
            (1_500, "1.5µs"),
            (7, "7ns"),
            (-2_000_000_000, "-2s"),
        ] {
            assert_eq!(velarx_proto::duration::go_duration_string(ns), want, "{ns}");
        }
        let v = json!({"D": go_duration_value(90_000_000_000), "Z": go_duration_value(0)});
        assert_eq!(r("{{.D}}", v.clone()), "1m30s");
        assert_eq!(r("{{json .}}", v.clone()), r#"{"D":90000000000,"Z":0}"#);
        assert_eq!(r("{{if .Z}}y{{else}}n{{end}}", v), "n");
    }

    #[test]
    fn the_spaces_of_a_table_are_its_columns() {
        let items = vec![json!({"ID": "a1", "Names": "web"})];
        let headers = HashMap::new();
        assert_eq!(
            format_list("table {{.ID}} {{.Names}}", &items, &headers).unwrap(),
            format_list("table {{.ID}}\t{{.Names}}", &items, &headers).unwrap()
        );
        let plain = format_list("{{.ID}} {{.Names}}", &items, &headers).unwrap();
        assert_eq!(plain, "a1 web\n");
    }

    #[test]
    fn podman_s_structs_print_as_go_s_and_their_nil_pointers_fail() {
        let v = json!({
            "Config": {"Healthcheck": {
                "Test": ["CMD-SHELL", "true"],
                "Interval": go_duration_value(30_000_000_000),
                "Timeout": go_duration_value(30_000_000_000),
                "StartPeriod": go_duration_value(0),
                "Retries": 3,
            }, "Labels": {"b": "2", "a": "1"}},
            "State": {"Health": {"Status": "starting", "FailingStreak": 0, "Log": []}},
            "HostConfig": {
                "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                "Ulimits": [{"Name": "RLIMIT_CORE", "Soft": -1, "Hard": -1}],
            },
        });
        assert_eq!(
            r("{{.Config.Healthcheck}}", v.clone()),
            "{[CMD-SHELL true] 0s 0s 30s 30s 3}"
        );
        assert_eq!(r("{{.State.Health}}", v.clone()), "{starting 0 []}");
        // (State's method Healthcheck is its Health)
        assert_eq!(r("{{.State.Healthcheck.FailingStreak}}", v.clone()), "0");
        assert_eq!(r("{{.HostConfig.RestartPolicy}}", v.clone()), "{no 0}");
        assert_eq!(
            r("{{.HostConfig.Ulimits}}", v.clone()),
            "[{RLIMIT_CORE -1 -1}]"
        );
        // a map stays a map; the fields of a struct are there
        assert_eq!(r("{{.Config.Labels}}", v.clone()), "map[a:1 b:2]");
        assert_eq!(
            r(
                "{{range .HostConfig.Ulimits}}{{.Name}}={{.Soft}}{{end}}",
                v.clone()
            ),
            "RLIMIT_CORE=-1"
        );
        assert_eq!(
            r("{{json .HostConfig.RestartPolicy}}", v.clone()),
            r#"{"MaximumRetryCount":0,"Name":"no"}"#
        );
        // a nil pointer prints <nil>, a field of it fails
        let none = json!({"Config": {}, "State": {}});
        assert_eq!(r("{{.Config.Healthcheck}}", none.clone()), "<nil>");
        let e = Template::parse("{{.Config.Healthcheck.Test}}")
            .unwrap()
            .render(&none)
            .unwrap_err();
        assert_eq!(
            e,
            "at <.Config.Healthcheck.Test>: nil pointer evaluating \
             *manifest.Schema2HealthConfig.Test"
        );
    }
}
