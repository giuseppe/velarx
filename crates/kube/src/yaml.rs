// SPDX-License-Identifier: Apache-2.0
//! The YAML of `kube play` and `kube generate`.
//!
//! Parsing turns the documents of a stream into JSON trees whose scalars are
//! strings (a plain `null`, `~` or empty scalar is null):
//! the play code reads every field as text and parses what it needs.  A
//! plain scalar that YAML reads as a boolean, a number or a time is the text
//! podman's decoding makes of it for a field of text (`1.10` is `1.1`,
//! `0x1F` is `31`, `TRUE` is `true`), so that a label or a value is what
//! podman would have.  The
//! input is untrusted: its size, its depth, the number of documents and the
//! number of nodes, aliases expanded, are bounded, so an alias bomb or a
//! deeply nested document is refused instead of exhausting the engine.
//!
//! Emitting writes block YAML from a JSON tree: a string plain when it
//! cannot be read as anything else (as podman writes `kind: Pod`), else
//! double quoted.

use serde_json::{Map, Value};

/// The largest YAML stream accepted.
pub const MAX_SIZE: usize = 4 * 1024 * 1024;
/// The deepest nesting of sequences and mappings.
pub const MAX_DEPTH: usize = 64;
/// The most documents in a stream.
pub const MAX_DOCUMENTS: usize = 256;
/// The most nodes of all the documents, the copies made by aliases counted.
pub const MAX_NODES: usize = 100_000;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum YamlError {
    #[error("invalid YAML: {0}")]
    Syntax(String),
    #[error("the YAML is too large: {0}")]
    Limit(&'static str),
}

/// An open sequence or mapping.
enum Frame {
    Seq {
        items: Vec<Value>,
        anchor: usize,
        start: usize,
    },
    Map {
        map: Map<String, Value>,
        key: Option<String>,
        anchor: usize,
        start: usize,
    },
}

struct Builder {
    stack: Vec<Frame>,
    docs: Vec<Value>,
    /// The anchored nodes and how many nodes each is.
    anchors: std::collections::HashMap<usize, (Value, usize)>,
    nodes: usize,
}

impl Builder {
    fn count(&mut self, n: usize) -> Result<(), YamlError> {
        self.nodes = self.nodes.saturating_add(n);
        if self.nodes > MAX_NODES {
            return Err(YamlError::Limit("too many nodes"));
        }
        Ok(())
    }

    /// Put a complete node where it belongs.
    fn insert(&mut self, v: Value) -> Result<(), YamlError> {
        match self.stack.last_mut() {
            None => {
                if self.docs.len() >= MAX_DOCUMENTS {
                    return Err(YamlError::Limit("too many documents"));
                }
                self.docs.push(v);
            }
            Some(Frame::Seq { items, .. }) => items.push(v),
            Some(Frame::Map { map, key, .. }) => match key.take() {
                Some(k) => {
                    if map.contains_key(&k) {
                        return Err(YamlError::Syntax(format!("duplicate key `{k}`")));
                    }
                    map.insert(k, v);
                }
                None => match v {
                    Value::String(k) => *key = Some(k),
                    Value::Null => *key = Some(String::new()),
                    _ => return Err(YamlError::Syntax("a key that is not a scalar".into())),
                },
            },
        }
        Ok(())
    }

    fn open(&mut self, f: Frame) -> Result<(), YamlError> {
        if self.stack.len() >= MAX_DEPTH {
            return Err(YamlError::Limit("nested too deeply"));
        }
        self.count(1)?;
        self.stack.push(f);
        Ok(())
    }

    fn close(&mut self) -> Result<(), YamlError> {
        let (v, anchor, start) = match self.stack.pop() {
            Some(Frame::Seq {
                items,
                anchor,
                start,
            }) => (Value::Array(items), anchor, start),
            Some(Frame::Map {
                map,
                key,
                anchor,
                start,
            }) => {
                if key.is_some() {
                    return Err(YamlError::Syntax("a key without a value".into()));
                }
                (Value::Object(map), anchor, start)
            }
            None => return Err(YamlError::Syntax("unbalanced document".into())),
        };
        if anchor != 0 {
            let size = self.nodes - start;
            self.anchors.insert(anchor, (v.clone(), size));
        }
        self.insert(v)
    }
}

/// A scalar as text; a plain `null`, `~` or empty scalar is null, and one
/// without a tag that YAML reads as something else than a string is
/// [`resolved`].
fn scalar(
    text: String,
    style: yaml_rust2::scanner::TScalarStyle,
    untagged: bool,
) -> Result<Value, String> {
    use yaml_rust2::scanner::TScalarStyle;
    if style != TScalarStyle::Plain {
        return Ok(Value::String(text));
    }
    if matches!(text.as_str(), "" | "~" | "null" | "Null" | "NULL") {
        return Ok(Value::Null);
    }
    if !untagged {
        return Ok(Value::String(text));
    }
    Ok(Value::String(resolved(&text)?.unwrap_or(text)))
}

/// The text podman's decoding gives a field of text for the plain scalar
/// `text` when YAML reads it as a boolean, a number or a time (the rules of
/// the YAML library of Kubernetes, then Go's writing of the value: a float
/// as the shortest of 32 bits, a time as RFC 3339); none for a string.  An
/// infinity or a NaN written as such is refused: it is no number of JSON.
fn resolved(text: &str) -> Result<Option<String>, String> {
    match text {
        "true" | "True" | "TRUE" => return Ok(Some("true".into())),
        "false" | "False" | "FALSE" => return Ok(Some("false".into())),
        ".inf" | ".Inf" | ".INF" | "+.inf" | "+.Inf" | "+.INF" | "-.inf" | "-.Inf" | "-.INF"
        | ".nan" | ".NaN" | ".NAN" => {
            return Err(format!("`{text}` is not a number JSON has"));
        }
        _ => {}
    }
    match text.as_bytes().first() {
        Some(b'.') => Ok(text.parse::<f64>().ok().map(go_float32)),
        Some(b'0'..=b'9' | b'+' | b'-') => {
            if let Some(time) = timestamp(text) {
                return Ok(Some(time));
            }
            let plain = text.replace('_', "");
            if let Some(n) = go_int(&plain) {
                return Ok(Some(n.to_string()));
            }
            if let Some(n) = go_uint(&plain) {
                return Ok(Some(n.to_string()));
            }
            Ok(yaml_float(&plain)
                .then(|| plain.parse::<f64>().ok())
                .flatten()
                .map(go_float32))
        }
        _ => Ok(None),
    }
}

/// The digits of `s` with Go's prefixes (`0x`, `0o`, `0b`, a `0` for
/// octal): the radix and the digits.
fn go_radix(s: &str) -> (u32, &str) {
    let lower = |p: &str| s.len() > 2 && s[..2].eq_ignore_ascii_case(p);
    if lower("0x") {
        (16, &s[2..])
    } else if lower("0o") {
        (8, &s[2..])
    } else if lower("0b") {
        (2, &s[2..])
    } else if s.len() > 1 && s.starts_with('0') {
        (8, &s[1..])
    } else {
        (10, s)
    }
}

/// Go's `strconv.ParseInt(s, 0, 64)` (without underscores).
fn go_int(s: &str) -> Option<i64> {
    let (negative, unsigned) = match s.as_bytes().first()? {
        b'-' => (true, &s[1..]),
        b'+' => (false, &s[1..]),
        _ => (false, s),
    };
    let (radix, digits) = go_radix(unsigned);
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    let magnitude = u64::from_str_radix(digits, radix).ok()?;
    if negative {
        0i64.checked_sub_unsigned(magnitude)
    } else {
        i64::try_from(magnitude).ok()
    }
}

/// Go's `strconv.ParseUint(s, 0, 64)` (without underscores).
fn go_uint(s: &str) -> Option<u64> {
    let (radix, digits) = go_radix(s);
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

/// Whether `s` is a float as the YAML library writes one:
/// `[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?`.
fn yaml_float(s: &str) -> bool {
    let s = s.strip_prefix(['-', '+']).unwrap_or(s);
    let (mantissa, exponent) = match s.find(['e', 'E']) {
        Some(at) => (&s[..at], Some(&s[at + 1..])),
        None => (s, None),
    };
    let digits = |d: &str| !d.is_empty() && d.bytes().all(|c| c.is_ascii_digit());
    let mantissa_ok = match mantissa.split_once('.') {
        Some(("", fraction)) => digits(fraction),
        Some((whole, fraction)) => digits(whole) && (fraction.is_empty() || digits(fraction)),
        None => digits(mantissa),
    };
    mantissa_ok && exponent.is_none_or(|e| digits(e.strip_prefix(['-', '+']).unwrap_or(e)))
}

/// Go's `strconv.FormatFloat(f, 'g', -1, 32)`: the shortest digits of the
/// 32-bit float, with an exponent below 1e-4 and from 1e6 on.
fn go_float32(f: f64) -> String {
    let x = f as f32;
    if x.is_infinite() {
        return if x > 0.0 { "+Inf" } else { "-Inf" }.into();
    }
    if x == 0.0 {
        return if x.is_sign_negative() { "-0" } else { "0" }.into();
    }
    let sci = format!("{:e}", x.abs());
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let sign = if x < 0.0 { "-" } else { "" };
    if !(-4..6).contains(&exp) {
        let rest = if digits.len() > 1 {
            format!(".{}", &digits[1..])
        } else {
            String::new()
        };
        let esign = if exp < 0 { '-' } else { '+' };
        return format!("{sign}{}{rest}e{esign}{:02}", &digits[..1], exp.abs());
    }
    if exp < 0 {
        return format!("{sign}0.{}{digits}", "0".repeat((-exp - 1) as usize));
    }
    let whole = exp as usize + 1;
    if digits.len() <= whole {
        format!("{sign}{digits}{}", "0".repeat(whole - digits.len()))
    } else {
        format!("{sign}{}.{}", &digits[..whole], &digits[whole..])
    }
}

/// A plain time of YAML (`2001-12-14`, `2001-12-14t21:59:43.10-05:00`,
/// `2001-12-14 21:59:43.10` in UTC) as Go writes it in JSON (RFC 3339, the
/// zeros at the end of the fraction left out); none for anything else.
fn timestamp(s: &str) -> Option<String> {
    /// One or two digits.
    fn number(rest: &mut &str) -> Option<u32> {
        let n = rest.bytes().take(2).take_while(u8::is_ascii_digit).count();
        let v = rest.get(..n).filter(|_| n > 0)?.parse().ok()?;
        *rest = &rest[n..];
        Some(v)
    }
    fn expect(rest: &mut &str, c: char) -> Option<()> {
        *rest = rest.strip_prefix(c)?;
        Some(())
    }
    let b = s.as_bytes();
    if b.len() < 5 || !b[..4].iter().all(u8::is_ascii_digit) || b[4] != b'-' {
        return None;
    }
    let year: u32 = s[..4].parse().ok()?;
    let mut rest = &s[5..];
    let month = number(&mut rest)?;
    expect(&mut rest, '-')?;
    let day = number(&mut rest)?;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if day == 0 || day > days {
        return None;
    }
    let date = format!("{year:04}-{month:02}-{day:02}");
    if rest.is_empty() {
        return Some(format!("{date}T00:00:00Z"));
    }
    let zoned = match rest.as_bytes()[0] {
        b'T' | b't' => true,
        b' ' => false,
        _ => return None,
    };
    rest = &rest[1..];
    let hour = number(&mut rest)?;
    expect(&mut rest, ':')?;
    let minute = number(&mut rest)?;
    expect(&mut rest, ':')?;
    let second = number(&mut rest)?;
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let mut fraction = String::new();
    if let Some(after) = rest.strip_prefix(['.', ',']) {
        let n = after.bytes().take_while(u8::is_ascii_digit).count();
        if n > 0 {
            let nanos: String = after[..n]
                .chars()
                .chain(std::iter::repeat('0'))
                .take(9)
                .collect();
            let nanos = nanos.trim_end_matches('0');
            if !nanos.is_empty() {
                fraction = format!(".{nanos}");
            }
            rest = &after[n..];
        }
    }
    let zone = if !zoned {
        (rest.is_empty()).then(|| "Z".to_string())?
    } else if rest == "Z" {
        "Z".into()
    } else {
        let b = rest.as_bytes();
        let two = |at: usize| -> Option<u32> {
            let d = rest.get(at..at + 2)?;
            d.bytes()
                .all(|c| c.is_ascii_digit())
                .then(|| d.parse().ok())?
        };
        if b.len() != 6 || !matches!(b[0], b'+' | b'-') || b[3] != b':' {
            return None;
        }
        let (h, m) = (two(1)?, two(4)?);
        if h > 24 || m > 60 {
            return None;
        }
        if h == 0 && m == 0 {
            "Z".into()
        } else {
            rest.to_string()
        }
    };
    Some(format!(
        "{date}T{hour:02}:{minute:02}:{second:02}{fraction}{zone}"
    ))
}

/// The documents of a YAML stream, empty ones left out.
pub fn parse_documents(input: &str) -> Result<Vec<Value>, YamlError> {
    use yaml_rust2::parser::{Event, Parser};
    if input.len() > MAX_SIZE {
        return Err(YamlError::Limit("larger than 4 MiB"));
    }
    let mut b = Builder {
        stack: Vec::new(),
        docs: Vec::new(),
        anchors: std::collections::HashMap::new(),
        nodes: 0,
    };
    let mut parser = Parser::new_from_str(input);
    loop {
        let (event, mark) = parser
            .next_token()
            .map_err(|e| YamlError::Syntax(e.to_string()))?;
        let at = |m: String| YamlError::Syntax(format!("{m} at line {}", mark.line()));
        match event {
            Event::StreamEnd => break,
            Event::StreamStart | Event::DocumentStart | Event::Nothing => {}
            Event::DocumentEnd => {
                if !b.stack.is_empty() {
                    return Err(at("unbalanced document".into()));
                }
                // documents are separate trees: an alias does not reach
                // into the previous one
                b.anchors.clear();
            }
            Event::Scalar(text, style, anchor, tag) => {
                b.count(1)?;
                let v = scalar(text, style, tag.is_none()).map_err(at)?;
                if anchor != 0 {
                    b.anchors.insert(anchor, (v.clone(), 1));
                }
                b.insert(v)?;
            }
            Event::Alias(id) => {
                let (v, size) = b
                    .anchors
                    .get(&id)
                    .cloned()
                    .ok_or_else(|| at("an alias of an unknown anchor".into()))?;
                // the copy is as many nodes as the original
                b.count(size)?;
                b.insert(v)?;
            }
            Event::SequenceStart(anchor, _tag) => {
                let start = b.nodes;
                b.open(Frame::Seq {
                    items: Vec::new(),
                    anchor,
                    start,
                })?;
            }
            Event::MappingStart(anchor, _tag) => {
                let start = b.nodes;
                b.open(Frame::Map {
                    map: Map::new(),
                    key: None,
                    anchor,
                    start,
                })?;
            }
            Event::SequenceEnd | Event::MappingEnd => b.close()?,
        }
    }
    if !b.stack.is_empty() {
        return Err(YamlError::Syntax("unbalanced document".into()));
    }
    Ok(b.docs.into_iter().filter(|d| !d.is_null()).collect())
}

/// Whether `s` reads back as the same string when written plain: no
/// indicator, no space, nothing YAML would take for a number, a boolean or
/// null.
fn plain_ok(s: &str) -> bool {
    let first = s.as_bytes().first().copied();
    !s.is_empty()
        && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b'/' | b':' | b'@' | b'+' | b'='))
        && first.is_some_and(|c| c.is_ascii_alphanumeric() || c == b'/' || c == b'_')
        && !s.ends_with(':')
        && !matches!(
            s.to_ascii_lowercase().as_str(),
            "true" | "false" | "yes" | "no" | "on" | "off" | "null" | "y" | "n" | "nan" | "inf"
        )
        && s.parse::<f64>().is_err()
        && timestamp(s).is_none()
        // 0o17, 0x1f, 1_000, 1e3 and the like
        && !(first.is_some_and(|c| c.is_ascii_digit()) && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'+' | b'-')))
}

/// A key as it is written: plain when that cannot be read differently.
fn key(k: &str) -> String {
    if plain_ok(k) {
        k.to_string()
    } else {
        quote(k)
    }
}

/// A double quoted string.
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A value that fits on its line.
fn inline(v: &Value) -> Option<String> {
    match v {
        Value::Null => Some("null".into()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) => Some(key(s)),
        Value::Array(a) if a.is_empty() => Some("[]".into()),
        Value::Object(m) if m.is_empty() => Some("{}".into()),
        _ => None,
    }
}

fn emit_map(m: &Map<String, Value>, indent: usize, first: Option<&str>, out: &mut String) {
    let pad = " ".repeat(indent);
    for (i, (k, v)) in m.iter().enumerate() {
        match (i, first) {
            (0, Some(prefix)) => out.push_str(prefix),
            _ => out.push_str(&pad),
        }
        out.push_str(&key(k));
        out.push(':');
        match inline(v) {
            Some(s) => {
                out.push(' ');
                out.push_str(&s);
                out.push('\n');
            }
            None => {
                out.push('\n');
                match v {
                    Value::Object(o) => emit_map(o, indent + 2, None, out),
                    // a sequence of a mapping at the indentation of its key
                    Value::Array(a) => emit_seq(a, indent, out),
                    _ => {}
                }
            }
        }
    }
}

fn emit_seq(a: &[Value], indent: usize, out: &mut String) {
    let pad = " ".repeat(indent);
    for v in a {
        match (inline(v), v) {
            (Some(s), _) => {
                out.push_str(&pad);
                out.push_str("- ");
                out.push_str(&s);
                out.push('\n');
            }
            (None, Value::Object(o)) => emit_map(o, indent + 2, Some(&format!("{pad}- ")), out),
            (None, Value::Array(inner)) => {
                out.push_str(&pad);
                out.push_str("-\n");
                emit_seq(inner, indent + 2, out);
            }
            _ => {}
        }
    }
}

/// The YAML of documents, each started with `---`.
pub fn emit_documents(docs: &[Value]) -> String {
    let mut out = String::new();
    for d in docs {
        out.push_str("---\n");
        match (inline(d), d) {
            (Some(s), _) => {
                out.push_str(&s);
                out.push('\n');
            }
            (None, Value::Object(o)) => emit_map(o, 0, None, &mut out),
            (None, Value::Array(a)) => emit_seq(a, 0, &mut out),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn documents_as_string_trees() {
        let docs = parse_documents(
            "# a comment\n---\napiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: a\n    ports:\n    - containerPort: 80\n    tty: true\n    x: ~\n---\n---\nkind: \"PersistentVolumeClaim\"\n",
        )
        .unwrap();
        assert_eq!(docs.len(), 2);
        assert_eq!(
            docs[0],
            json!({"apiVersion": "v1", "kind": "Pod", "spec": {"containers": [
                {"name": "a", "ports": [{"containerPort": "80"}], "tty": "true", "x": null}]}})
        );
        assert_eq!(docs[1]["kind"], "PersistentVolumeClaim");
        // flow style, block scalars, anchors
        let d = parse_documents("a: &x [1, 2]\nb: *x\nc: |\n  line\n  two\nd: {e: f}\n").unwrap();
        assert_eq!(
            d[0],
            json!({"a": ["1", "2"], "b": ["1", "2"], "c": "line\ntwo\n", "d": {"e": "f"}})
        );
        // quoted null stays text
        assert_eq!(parse_documents("a: \"null\"").unwrap()[0]["a"], "null");
    }

    #[test]
    fn refuses_what_is_not_kube_yaml() {
        for bad in ["a: [", "a: *nope", "a: 1\na: 2", "? [a]\n: b", "a: \"x"] {
            assert!(parse_documents(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn limits() {
        assert_eq!(
            parse_documents(&" ".repeat(MAX_SIZE + 1)),
            Err(YamlError::Limit("larger than 4 MiB"))
        );
        let deep = format!(
            "{}1{}",
            "[".repeat(MAX_DEPTH + 1),
            "]".repeat(MAX_DEPTH + 1)
        );
        assert!(parse_documents(&deep).is_err());
        let block_deep: String = (0..MAX_DEPTH + 1)
            .map(|i| format!("{}k:\n", "  ".repeat(i)))
            .collect();
        assert_eq!(
            parse_documents(&(block_deep + &"  ".repeat(MAX_DEPTH + 1) + "k: v\n")),
            Err(YamlError::Limit("nested too deeply"))
        );
        let many = "a: 1\n---\n".repeat(MAX_DOCUMENTS + 1);
        assert_eq!(
            parse_documents(&many),
            Err(YamlError::Limit("too many documents"))
        );
        // billion laughs: each level doubles the copies
        let mut bomb = String::from("a0: &a0 [x, x]\n");
        for i in 1..40 {
            bomb.push_str(&format!("a{i}: &a{i} [*a{}, *a{}]\n", i - 1, i - 1));
        }
        assert_eq!(
            parse_documents(&bomb),
            Err(YamlError::Limit("too many nodes"))
        );
    }

    /// The text podman 5.8 gives a label written as each plain scalar
    /// (`podman kube play`, then `pod inspect`).
    #[test]
    fn plain_scalars_are_read_as_podman_reads_them() {
        for (plain, podman) in [
            ("1", "1"),
            ("1.0", "1"),
            ("1e3", "1000"),
            ("1.10", "1.1"),
            ("0o17", "15"),
            ("0O17", "15"),
            ("017", "15"),
            ("08", "8"),
            ("09.5", "9.5"),
            ("1_000", "1000"),
            ("1__0", "10"),
            ("1_0.5", "10.5"),
            ("+1", "1"),
            ("-0", "0"),
            (".5", "0.5"),
            ("+.5", "0.5"),
            ("1.", "1"),
            ("0x1F", "31"),
            ("+0x10", "16"),
            ("-0x10", "-16"),
            ("0b11", "3"),
            ("-0b11", "-3"),
            ("0x", "0x"),
            ("0b", "0b"),
            ("12345678901234567890", "12345678901234567890"),
            ("1e6", "1e+06"),
            ("1.0e+3", "1000"),
            ("123456.0", "123456"),
            ("1234567.0", "1.234567e+06"),
            ("0.0001", "0.0001"),
            ("0.00001", "1e-05"),
            ("-1.5e-7", "-1.5e-07"),
            ("1e-50", "0"),
            ("1e100", "+Inf"),
            ("0.1", "0.1"),
            ("3.14159265358979", "3.1415927"),
            ("True", "true"),
            ("TRUE", "true"),
            ("on", "on"),
            ("off", "off"),
            ("no", "no"),
            ("yes", "yes"),
            ("1:20", "1:20"),
            ("2001-01-01", "2001-01-01T00:00:00Z"),
            ("2002-1-2", "2002-01-02T00:00:00Z"),
            (
                "2001-12-14t21:59:43.10-05:00",
                "2001-12-14T21:59:43.1-05:00",
            ),
            ("2001-12-14 21:59:43.10", "2001-12-14T21:59:43.1Z"),
            ("2001-12-15T02:59:43.1Z", "2001-12-15T02:59:43.1Z"),
            ("2001-12-14T21:59:43+01:00", "2001-12-14T21:59:43+01:00"),
            // (a time with a T needs its zone)
            ("2001-12-14T21:59:43", "2001-12-14T21:59:43"),
            ("2001-02-30", "2001-02-30"),
        ] {
            let doc = parse_documents(&format!("a: {plain}\n")).unwrap();
            assert_eq!(doc[0]["a"], podman, "{plain}");
        }
        // what is quoted or tagged is the text; a key is read as a value is
        let doc = parse_documents("a: \"1.0\"\nb: '0x10'\nc: !!str 1.0\n1.0: x\n017: y\n").unwrap();
        assert_eq!(doc[0]["a"], "1.0");
        assert_eq!(doc[0]["b"], "0x10");
        assert_eq!(doc[0]["c"], "1.0");
        assert_eq!(doc[0]["1"], "x");
        assert_eq!(doc[0]["15"], "y");
        // (podman: "json: unsupported value")
        for bad in ["a: .inf\n", "a: -.Inf\n", "a: .nan\n"] {
            assert!(parse_documents(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn plain_only_when_unambiguous() {
        for p in [
            "Pod",
            "v1",
            "apps/v1",
            "docker.io/library/alpine:latest",
            "a@sha256:00",
            "web-pod",
            "/srv",
            "x=1",
        ] {
            assert!(plain_ok(p), "{p}");
        }
        for q in [
            "",
            "true",
            "No",
            "null",
            "~",
            "1",
            "1.5",
            "0x1f",
            "1e3",
            "08",
            "a b",
            "-x",
            ":x",
            "x:",
            "#c",
            "a,b",
            "*a",
            "&a",
            "!t",
            "{}",
            "'q'",
            "nan",
            "0o17",
            "TRUE",
            "2001-12-14t21:59:43.10-05:00",
        ] {
            assert!(!plain_ok(q), "{q}");
            // and whatever it is, it reads back as the same text
            let doc = serde_json::json!({ "k": q });
            assert_eq!(
                parse_documents(&emit_documents(&[doc])).unwrap()[0]["k"],
                serde_json::json!(q),
                "{q}"
            );
        }
    }

    #[test]
    fn emits_what_it_parses() {
        let doc = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "p", "labels": {"app": "web", "a/b": "yes"}, "annotations": {}},
            "spec": {
                "containers": [{
                    "name": "c",
                    "command": ["sh", "-c", "echo \"hi\"\n"],
                    "ports": [{"containerPort": 80, "hostPort": 8080}],
                    "env": [{"name": "A", "value": "true"}, {"name": "B", "value": ""}],
                    "tty": true,
                    "x": null,
                    "nested": [[1, 2], []],
                }],
                "true": "key that is a keyword",
                "8": "numeric key",
            },
        });
        let text = emit_documents(&[doc.clone(), json!({"kind": "Service"})]);
        assert!(text.starts_with("---\napiVersion: v1\n"));
        assert!(text.contains("  containers:\n  - command:\n    - sh\n"));
        let back = parse_documents(&text).unwrap();
        assert_eq!(back.len(), 2);
        // the numbers and booleans come back as text
        assert_eq!(
            back[0]["spec"]["containers"][0]["ports"][0]["hostPort"],
            "8080"
        );
        assert_eq!(back[0]["spec"]["containers"][0]["tty"], "true");
        assert_eq!(
            back[0]["spec"]["containers"][0]["command"],
            doc["spec"]["containers"][0]["command"]
        );
        assert_eq!(back[0]["spec"]["containers"][0]["env"][1]["value"], "");
        assert_eq!(back[0]["spec"]["containers"][0]["x"], Value::Null);
        assert_eq!(back[0]["spec"]["true"], "key that is a keyword");
        assert_eq!(back[0]["spec"]["8"], "numeric key");
        assert_eq!(back[0]["metadata"]["labels"]["a/b"], "yes");
        assert_eq!(back[0]["metadata"]["annotations"], json!({}));
        assert_eq!(
            back[0]["spec"]["containers"][0]["nested"],
            json!([["1", "2"], []])
        );
        assert_eq!(back[1]["kind"], "Service");
    }

    /// Random and mutated streams: no panic, the limits hold, and what is
    /// emitted parses back.
    #[test]
    fn fuzz_documents() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x7a31);
        let seeds = [
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n  - name: c\n    image: alpine\n    command: [sh, -c, 'x']\n",
            "a: &x {b: [1, 2, *y]}\nc: *x\n---\n- - - [\"q\", 'r']\n",
            "k: |\n  text\n  more\nl: >-\n  folded\n? complex\n: value\n",
            "%YAML 1.2\n---\n!!str a: !custom b\n...\n",
        ];
        let alphabet: &[u8] = b" \n\t:-[]{},&*!|>'\"#%?@`abcxyz019.~\\";
        for i in 0..40_000 {
            let mut s: Vec<u8> = if i % 5 == 0 {
                let n = rng.gen_range(0..120);
                (0..n)
                    .map(|_| alphabet[rng.gen_range(0..alphabet.len())])
                    .collect()
            } else {
                seeds[i % seeds.len()].as_bytes().to_vec()
            };
            for _ in 0..rng.gen_range(0..6) {
                if s.is_empty() {
                    break;
                }
                let at = rng.gen_range(0..s.len());
                match rng.gen_range(0..4) {
                    0 => s[at] = alphabet[rng.gen_range(0..alphabet.len())],
                    1 => s.truncate(at),
                    2 => s.insert(at, alphabet[rng.gen_range(0..alphabet.len())]),
                    _ => {
                        let piece = s[at..].to_vec();
                        s.extend_from_slice(&piece);
                    }
                }
            }
            let Ok(text) = String::from_utf8(s) else {
                continue;
            };
            if let Ok(docs) = parse_documents(&text) {
                assert!(docs.len() <= MAX_DOCUMENTS);
                let again = parse_documents(&emit_documents(&docs)).unwrap();
                assert_eq!(again.len(), docs.len(), "{text:?}");
            }
        }
    }
}
