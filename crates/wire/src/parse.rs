// SPDX-License-Identifier: Apache-2.0
//! Containerfiles: the instructions, the words of their arguments with the
//! variables expanded, and the patterns of `.containerignore`.
//!
//! The rules are those of buildah's builder: a `\` at the end of a line
//! continues it (`# escape=` changes the character), a continuation line keeps
//! its leading white space, comment lines and empty lines are dropped inside a
//! continued instruction, a byte order mark at the start is ignored, `$NAME`,
//! `${NAME}`, `${NAME:-word}`, `${NAME:+word}`, `${NAME:?word}`, `${NAME#pat}`,
//! `${NAME##pat}`, `${NAME%pat}`, `${NAME%%pat}` and `${NAME/pat/word}` (also
//! `//`, `/#` and `/%`) are expanded outside single quotes (any other form
//! is an error), and the exec form of RUN, CMD, ENTRYPOINT, SHELL, COPY, ADD and
//! VOLUME is a JSON array of strings.  RUN, COPY and ADD take
//! here-documents (`<<EOF`, `<<-EOF`, `<<"EOF"`, several on a line): their
//! lines follow the instruction, verbatim, up to the line of the delimiter.

/// The largest Containerfile and ignore file read.
pub const MAX_FILE: u64 = 16 * 1024 * 1024;

/// How deep `${A:-${B:-...}}` may nest.
const MAX_NESTING: usize = 64;

const KEYWORDS: &[&str] = &[
    "FROM",
    "RUN",
    "COPY",
    "ADD",
    "ENV",
    "ARG",
    "WORKDIR",
    "USER",
    "ENTRYPOINT",
    "CMD",
    "LABEL",
    "EXPOSE",
    "VOLUME",
    "STOPSIGNAL",
    "SHELL",
    "MAINTAINER",
    "ONBUILD",
    "HEALTHCHECK",
];

/// One instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instr {
    /// Upper case.
    pub keyword: String,
    /// The arguments after the flags, not expanded.
    pub args: String,
    /// The exec form.
    pub json: Option<Vec<String>>,
    /// `--name=value` flags.
    pub flags: Vec<String>,
    /// The line it starts on.
    pub line: usize,
    /// The here-documents of the line, in order.
    pub heredocs: Vec<Heredoc>,
}

/// A here-document of RUN, COPY or ADD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heredoc {
    /// The delimiter, without its quotes.
    pub name: String,
    /// The lines, each with its newline, as written.
    pub body: String,
    /// `<<-`: the leading tabs of the lines are removed.
    pub chomp: bool,
    /// Variables are expanded in it (COPY, ADD): the delimiter is not quoted.
    pub expand: bool,
}

impl Heredoc {
    /// The content: the body, without the leading tabs of `<<-`.
    pub fn content(&self) -> String {
        if !self.chomp {
            return self.body.clone();
        }
        self.body
            .split_inclusive('\n')
            .map(|l| l.trim_start_matches('\t'))
            .collect()
    }

    /// The name of the file of its content (COPY's file, RUN's script):
    /// the delimiter as one component.
    pub fn file_name(&self) -> String {
        match self.name.replace('/', "_") {
            n if n == "." || n == ".." => n.replace('.', "_"),
            n => n,
        }
    }
}

/// The here-document a word of a command line opens (`<<EOF`, `2<<-"EOF"`):
/// its delimiter, whether it strips tabs and whether it is not quoted.
pub fn heredoc_marker(word: &str) -> Option<(String, bool, bool)> {
    let rest = word.trim_start_matches(|c: char| c.is_ascii_digit());
    let rest = rest.strip_prefix("<<")?;
    let (chomp, rest) = match rest.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, rest),
    };
    if rest.starts_with('<') {
        return None;
    }
    let (name, expand) = match rest.chars().next() {
        Some(q @ ('"' | '\'')) => (rest.strip_prefix(q)?.strip_suffix(q)?, false),
        _ => (rest, true),
    };
    let valid = !name.is_empty()
        && name
            .chars()
            .all(|c| !is_space(c) && !matches!(c, '"' | '\'' | '<' | '>' | '|' | '&' | ';'));
    valid.then(|| (name.to_string(), chomp, expand))
}

/// The words of a command line as written (quotes kept), split where a
/// shell would split them.
fn raw_words(s: &str, escape: char) -> Vec<&str> {
    let mut words = Vec::new();
    let (mut start, mut quote, mut escaped) = (None, None, false);
    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if c == escape && quote != Some('\'') {
            escaped = true;
            start.get_or_insert(i);
            continue;
        }
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if is_space(c) => {
                if let Some(b) = start.take() {
                    words.push(&s[b..i]);
                }
            }
            None => {
                if c == '"' || c == '\'' {
                    quote = Some(c);
                }
                start.get_or_insert(i);
            }
        }
    }
    if let Some(b) = start {
        words.push(&s[b..]);
    }
    words
}

impl Instr {
    /// The value of the flag `--name=value`, the last one if repeated.
    pub fn flag(&self, name: &str) -> Option<&str> {
        self.flags
            .iter()
            .rev()
            .find_map(|f| f.strip_prefix("--")?.strip_prefix(name)?.strip_prefix('='))
    }

    /// The values of the flag `--name=value` given any number of times.
    pub fn flag_values(&self, name: &str) -> Vec<&str> {
        self.flags
            .iter()
            .filter_map(|f| f.strip_prefix("--")?.strip_prefix(name)?.strip_prefix('='))
            .collect()
    }

    /// A flag that is a boolean: `--name` or `--name=true`, `--name=false`;
    /// false when it is not given.
    pub fn flag_bool(&self, name: &str) -> Result<bool, String> {
        match self.flags.iter().rev().find_map(|f| {
            let rest = f.strip_prefix("--")?.strip_prefix(name)?;
            match rest {
                "" => Some(""),
                _ => rest.strip_prefix('='),
            }
        }) {
            None => Ok(false),
            Some("" | "true") => Ok(true),
            Some("false") => Ok(false),
            Some(v) => Err(format!(
                "line {}: invalid --{name}={v}: true or false",
                self.line
            )),
        }
    }

    /// Refuse the flags that are not in `allowed`.
    pub fn check_flags(&self, allowed: &[&str]) -> Result<(), String> {
        for f in &self.flags {
            let name = f
                .trim_start_matches("--")
                .split('=')
                .next()
                .unwrap_or_default();
            if !allowed.contains(&name) {
                return Err(format!(
                    "line {}: unsupported flag `{f}` for {}",
                    self.line, self.keyword
                ));
            }
        }
        Ok(())
    }

    /// The instruction as the history of an image shows it: the credentials
    /// of its URLs are hidden.
    pub fn text(&self) -> String {
        crate::redact::urls(&self.raw_text())
    }

    /// The instruction as written, credentials included: for cache keys,
    /// never for anything that is shown or stored.
    pub fn raw_text(&self) -> String {
        let mut s = self.keyword.clone();
        for f in &self.flags {
            s.push(' ');
            s.push_str(f);
        }
        if !self.args.is_empty() {
            s.push(' ');
            s.push_str(&self.args);
        }
        for h in &self.heredocs {
            s.push('\n');
            s.push_str(&h.body);
            s.push_str(&h.name);
        }
        s
    }

    /// The here-document a source of COPY or ADD names (`<<EOF`, the
    /// quotes taken out), if it is one of this instruction's.
    pub fn heredoc_of(&self, word: &str) -> Option<&Heredoc> {
        let (name, _, _) = heredoc_marker(word)?;
        self.heredocs.iter().find(|h| h.name == name)
    }

    /// Whether the command line is one here-document and nothing else
    /// (`RUN <<EOF`): its content is the command.
    pub fn only_heredoc(&self) -> Option<&Heredoc> {
        match self.heredocs.as_slice() {
            [h] if heredoc_marker(self.args.trim()).is_some_and(|(n, _, _)| n == h.name) => Some(h),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage {
    /// `AS name`.
    pub name: Option<String>,
    /// The argument of FROM, not expanded.
    pub base: String,
    /// `FROM --platform=`.
    pub platform: Option<String>,
    pub instrs: Vec<Instr>,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Containerfile {
    /// The ARG instructions before the first FROM.
    pub global_args: Vec<Instr>,
    pub stages: Vec<Stage>,
    /// The escape character of the words (`# escape=`).
    pub escape: char,
}

fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

fn takes_flags(kw: &str) -> bool {
    matches!(kw, "FROM" | "RUN" | "COPY" | "ADD" | "HEALTHCHECK")
}

fn takes_heredocs(kw: &str) -> bool {
    matches!(kw, "RUN" | "COPY" | "ADD")
}

fn takes_json(kw: &str) -> bool {
    matches!(
        kw,
        "RUN" | "CMD" | "ENTRYPOINT" | "SHELL" | "COPY" | "ADD" | "VOLUME"
    )
}

/// The JSON array of strings in `s`, if it is one.
pub fn json_array(s: &str) -> Option<Vec<String>> {
    serde_json::from_str::<Vec<String>>(s).ok()
}

/// The parser directives at the top of the file: `# escape=` only.
fn escape_directive(data: &str) -> Result<char, String> {
    for line in data.lines() {
        let Some(rest) = line.trim().strip_prefix('#') else {
            break;
        };
        let Some((key, value)) = rest.split_once('=') else {
            break;
        };
        match key.trim().to_ascii_lowercase().as_str() {
            "escape" => {
                return match value.trim() {
                    "\\" => Ok('\\'),
                    "`" => Ok('`'),
                    v => Err(format!("invalid escape character `{v}`")),
                }
            }
            "syntax" | "check" => {}
            _ => break,
        }
    }
    Ok('\\')
}

impl Containerfile {
    pub fn parse(data: &str) -> Result<Self, String> {
        let data = data.strip_prefix('\u{feff}').unwrap_or(data);
        let escape = escape_directive(data)?;
        let mut file = Containerfile {
            global_args: Vec::new(),
            stages: Vec::new(),
            escape,
        };
        let mut logical = String::new();
        let mut start = 0;
        let mut continuing = false;
        let lines: Vec<&str> = data.split('\n').collect();
        let mut i = 0;
        while i < lines.len() {
            let raw = lines[i];
            i += 1;
            // A continuation line keeps its leading white space.
            let line = if continuing {
                raw.trim_end_matches(is_space)
            } else {
                raw.trim_matches(is_space)
            };
            // Comments and empty lines, also inside continuations.
            if line.trim_start_matches(is_space).starts_with('#')
                || line.trim_start_matches(is_space).is_empty()
            {
                continue;
            }
            if !continuing {
                start = i;
            }
            if let Some(head) = line.strip_suffix(escape) {
                logical.push_str(head);
                continuing = true;
                continue;
            }
            logical.push_str(line);
            continuing = false;
            if !logical.is_empty() {
                let text = std::mem::take(&mut logical);
                let heredocs = Self::heredocs(&text, escape, &lines, &mut i, start)?;
                file.add(&text, start, heredocs)?;
            }
        }
        if !logical.is_empty() {
            file.add(&logical, start, Vec::new())?;
        }
        if file.stages.is_empty() {
            return Err("no FROM instruction".into());
        }
        Ok(file)
    }

    /// An ONBUILD trigger (of this Containerfile or of a base image) as the
    /// instruction it runs; FROM, MAINTAINER and ONBUILD cannot be ones.
    pub fn trigger(&self, text: &str, lineno: usize) -> Result<Instr, String> {
        let instr = Self::instr(text.trim_matches(is_space), lineno)?;
        if matches!(instr.keyword.as_str(), "FROM" | "MAINTAINER" | "ONBUILD") {
            return Err(format!(
                "line {lineno}: {} is not allowed as an ONBUILD trigger",
                instr.keyword
            ));
        }
        Ok(instr)
    }

    /// The here-documents the instruction `text` opens, their lines taken
    /// from `lines` at `next` (which moves past them).
    fn heredocs(
        text: &str,
        escape: char,
        lines: &[&str],
        next: &mut usize,
        lineno: usize,
    ) -> Result<Vec<Heredoc>, String> {
        let kw_end = text.find(is_space).unwrap_or(text.len());
        if !takes_heredocs(&text[..kw_end].to_ascii_uppercase()) {
            return Ok(Vec::new());
        }
        let rest = text[kw_end..].trim_start_matches(is_space);
        if rest.starts_with('[') && json_array(rest.trim_end_matches(is_space)).is_some() {
            return Ok(Vec::new());
        }
        let mut docs = Vec::new();
        for w in raw_words(rest, escape) {
            let Some((name, chomp, expand)) = heredoc_marker(w) else {
                continue;
            };
            let mut body = String::new();
            loop {
                let Some(l) = lines.get(*next) else {
                    return Err(format!(
                        "line {lineno}: the here-document `{name}` has no end"
                    ));
                };
                *next += 1;
                let cmp = if chomp { l.trim_start_matches('\t') } else { l };
                if cmp.trim_end_matches('\r') == name {
                    break;
                }
                // (a line ending of Windows is no part of the line, as for
                // the instructions)
                body.push_str(l.strip_suffix('\r').unwrap_or(l));
                body.push('\n');
            }
            docs.push(Heredoc {
                name,
                body,
                chomp,
                expand,
            });
        }
        Ok(docs)
    }

    fn instr(line: &str, lineno: usize) -> Result<Instr, String> {
        let kw_end = line.find(is_space).unwrap_or(line.len());
        let keyword = line[..kw_end].to_ascii_uppercase();
        if !KEYWORDS.contains(&keyword.as_str()) {
            return Err(format!("line {lineno}: unknown instruction `{keyword}`"));
        }
        let mut rest = line[kw_end..].trim_start_matches(is_space);
        let mut flags = Vec::new();
        if takes_flags(&keyword) {
            while rest.starts_with("--") {
                let end = rest.find(is_space).unwrap_or(rest.len());
                flags.push(rest[..end].to_string());
                rest = rest[end..].trim_start_matches(is_space);
            }
        }
        let args = rest.trim_end_matches(is_space).to_string();
        let json = if takes_json(&keyword) && args.starts_with('[') {
            json_array(&args)
        } else {
            None
        };
        Ok(Instr {
            keyword,
            args,
            json,
            flags,
            line: lineno,
            heredocs: Vec::new(),
        })
    }

    fn add(&mut self, line: &str, lineno: usize, heredocs: Vec<Heredoc>) -> Result<(), String> {
        let mut instr = Self::instr(line, lineno)?;
        instr.heredocs = heredocs;
        if instr.keyword == "ONBUILD" {
            self.trigger(&instr.args, lineno)?;
        }
        if instr.keyword == "FROM" {
            instr.check_flags(&["platform"])?;
            let words = split_words(&instr.args, self.escape, &|_| None)?;
            let name = match words.as_slice() {
                [_] => None,
                [_, as_, name] if as_.eq_ignore_ascii_case("AS") => Some(name.clone()),
                _ => return Err(format!("line {lineno}: invalid FROM")),
            };
            self.stages.push(Stage {
                name,
                base: instr
                    .args
                    .split(is_space)
                    .next()
                    .unwrap_or_default()
                    .to_string(),
                platform: instr.flag("platform").map(str::to_string),
                instrs: Vec::new(),
                line: lineno,
            });
            return Ok(());
        }
        match self.stages.last_mut() {
            Some(stage) => stage.instrs.push(instr),
            None if instr.keyword == "ARG" => self.global_args.push(instr),
            None => return Err(format!("line {lineno}: `{}` before FROM", instr.keyword)),
        }
        Ok(())
    }
}

fn is_name_char(c: char, first: bool) -> bool {
    c == '_' || c.is_ascii_alphabetic() || (!first && c.is_ascii_digit())
}

/// The value of a variable.
pub type Lookup<'a> = &'a dyn Fn(&str) -> Option<String>;

/// The position of the first of `stops` in `s` that is not inside quotes
/// or a nested `${...}`.
fn find_stop(s: &str, escape: char, stops: &[char]) -> Option<usize> {
    let (mut single, mut double, mut depth) = (false, false, 0usize);
    let mut it = s.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        if c == escape && !single {
            it.next();
        } else if c == '\'' && !double {
            single = !single;
        } else if c == '"' && !single {
            double = !double;
        } else if single || double {
        } else if c == '$' && matches!(it.peek(), Some((_, '{'))) {
            it.next();
            depth += 1;
        } else if depth > 0 && c == '}' {
            depth -= 1;
        } else if depth == 0 && stops.contains(&c) {
            return Some(i);
        }
    }
    None
}

/// The char boundaries of `s`, both ends included.
fn boundaries(s: &str) -> Vec<usize> {
    s.char_indices()
        .map(|(i, _)| i)
        .chain(std::iter::once(s.len()))
        .collect()
}

/// The expansion of the variables of a text: its escape character, the
/// values, and how deep in `${...}` it is (each level of `${A:-${B:-...}}`
/// is a recursion: a deep one is refused before the stack runs out).
#[derive(Clone, Copy)]
struct Expand<'a> {
    escape: char,
    lookup: Lookup<'a>,
    depth: usize,
}

impl<'a> Expand<'a> {
    fn new(escape: char, lookup: Lookup<'a>) -> Self {
        Self {
            escape,
            lookup,
            depth: 0,
        }
    }

    /// Expand the variable at the start of `s` (just after the `$`) into
    /// `out`; returns what follows it.
    fn variable<'s>(&self, s: &'s str, out: &mut String) -> Result<&'s str, String> {
        if let Some(body) = s.strip_prefix('{') {
            return self.braced(body, out);
        }
        let mut chars = s.char_indices();
        match chars.next() {
            Some((_, c)) if is_name_char(c, true) => {
                let end = s
                    .char_indices()
                    .find(|&(i, c)| !is_name_char(c, i == 0))
                    .map_or(s.len(), |(i, _)| i);
                if let Some(v) = (self.lookup)(&s[..end]) {
                    out.push_str(&v);
                }
                Ok(&s[end..])
            }
            _ => {
                out.push('$');
                Ok(s)
            }
        }
    }

    /// The word of a `${NAME...}` (`word` of `:-word`, a pattern, a
    /// replacement): its quotes and escapes taken out as the shell takes them,
    /// its variables expanded, not split.  In a `pattern` what is quoted or
    /// escaped matches itself.
    fn word(&self, mut s: &str, pattern: bool) -> Result<String, String> {
        let mut out = String::new();
        let literal = |c: char, out: &mut String| {
            if pattern && matches!(c, '*' | '?' | '[' | ']' | '\\') {
                out.push('\\');
            }
            out.push(c);
        };
        let (mut single, mut double) = (false, false);
        while let Some(c) = s.chars().next() {
            let after = &s[c.len_utf8()..];
            if c == self.escape && !single {
                if let Some(next) = after.chars().next() {
                    if !double || matches!(next, '"' | '$') || next == self.escape {
                        literal(next, &mut out);
                        s = &after[next.len_utf8()..];
                        continue;
                    }
                }
            }
            if c == '\'' && !double {
                single = !single;
            } else if c == '"' && !single {
                double = !double;
            } else if c == '$' && !single {
                let mut value = String::new();
                s = self.variable(after, &mut value)?;
                if double {
                    value.chars().for_each(|c| literal(c, &mut out));
                } else {
                    out.push_str(&value);
                }
                continue;
            } else if single || double {
                literal(c, &mut out);
            } else {
                out.push(c);
            }
            s = after;
        }
        if single || double {
            return Err("unterminated quote".into());
        }
        Ok(out)
    }

    /// `${NAME` followed by `}`, `:-`, `:+`, `:?`, `#`, `##`, `%`, `%%`, `/`,
    /// `//`, `/#` or `/%`, the text after `${` in `body`; returns what follows
    /// the closing brace.  Any other form is an error.
    fn braced<'s>(&self, body: &'s str, out: &mut String) -> Result<&'s str, String> {
        if self.depth >= MAX_NESTING {
            return Err(format!(
                "the variables of `${{{}...` are nested more than {MAX_NESTING} deep",
                body.chars().take(16).collect::<String>()
            ));
        }
        // (the words inside are one level deeper)
        let inner = Self {
            depth: self.depth + 1,
            ..*self
        };
        let name_end = body
            .char_indices()
            .find(|&(i, c)| !is_name_char(c, i == 0))
            .map_or(body.len(), |(i, _)| i);
        let (name, rest) = body.split_at(name_end);
        let bad = || {
            let shown = body.split_once('}').map_or(body, |(b, _)| b);
            format!("bad substitution in `${{{shown}}}`")
        };
        if name.is_empty() {
            return Err(bad());
        }
        let value = (self.lookup)(name).unwrap_or_default();
        let mut chars = rest.chars();
        let op = chars
            .next()
            .ok_or_else(|| format!("missing `}}` in `${{{body}`"))?;
        let after_op = chars.as_str();
        let missing = || format!("missing `}}` in `${{{body}`");
        let word_of = |text: &'s str,
                       stops: &[char],
                       pattern: bool|
         -> Result<(String, char, &'s str), String> {
            let at = find_stop(text, self.escape, stops).ok_or_else(missing)?;
            let stop = text[at..].chars().next().unwrap_or('}');
            Ok((
                inner.word(&text[..at], pattern)?,
                stop,
                &text[at + stop.len_utf8()..],
            ))
        };
        match op {
            '}' => {
                out.push_str(&value);
                Ok(after_op)
            }
            ':' => {
                let modifier = after_op.chars().next().ok_or_else(missing)?;
                if modifier == '}' {
                    return Err(bad());
                }
                let (word, _, tail) = word_of(&after_op[modifier.len_utf8()..], &['}'], false)?;
                match modifier {
                    '-' => out.push_str(if value.is_empty() { &word } else { &value }),
                    '+' => {
                        if !value.is_empty() {
                            out.push_str(&word)
                        }
                    }
                    '?' if value.is_empty() => {
                        return Err(if word.is_empty() {
                            format!("{name} is not allowed to be unset")
                        } else {
                            format!("{name}: {word}")
                        })
                    }
                    '?' => out.push_str(&value),
                    m => {
                        return Err(format!(
                            "unsupported modifier `{m}` in `${{{name}:{m}...}}`"
                        ))
                    }
                }
                Ok(tail)
            }
            '#' | '%' => {
                let greedy = after_op.starts_with(op);
                let text = if greedy { &after_op[1..] } else { after_op };
                let (pat, _, tail) = word_of(text, &['}'], true)?;
                if pat.is_empty() {
                    return Err(format!(
                        "{name}{op}: no {} to remove",
                        if op == '#' { "prefix" } else { "suffix" }
                    ));
                }
                let cuts = boundaries(&value);
                let kept = if op == '#' {
                    // (the longest prefix when greedy: the cuts from the end)
                    let matches = |&&i: &&usize| fnmatch(&pat, &value[..i]);
                    let cut = if greedy {
                        cuts.iter().rev().find(matches)
                    } else {
                        cuts.iter().find(matches)
                    };
                    cut.map_or(&value[..], |&i| &value[i..])
                } else {
                    let matches = |&&i: &&usize| fnmatch(&pat, &value[i..]);
                    let cut = if greedy {
                        cuts.iter().find(matches)
                    } else {
                        cuts.iter().rev().find(matches)
                    };
                    cut.map_or(&value[..], |&i| &value[..i])
                };
                out.push_str(kept);
                Ok(tail)
            }
            '/' => {
                let (mode, text) = match after_op.chars().next() {
                    Some(m @ ('/' | '#' | '%')) => (m, &after_op[1..]),
                    _ => ('1', after_op),
                };
                let (pat, stop, tail) = word_of(text, &['/', '}'], true)?;
                if pat.is_empty() {
                    return Err(format!("{name}/: no pattern to replace"));
                }
                let (rep, tail) = if stop == '/' {
                    let (rep, _, tail) = word_of(tail, &['}'], false)?;
                    (rep, tail)
                } else {
                    (String::new(), tail)
                };
                let cuts = boundaries(&value);
                let mut result = String::new();
                let mut at = 0;
                while at < value.len() {
                    if mode == '#' && at != 0 {
                        break;
                    }
                    let hit = cuts
                        .iter()
                        .rev()
                        .filter(|&&j| j > at && (mode != '%' || j == value.len()))
                        .find(|&&j| fnmatch(&pat, &value[at..j]));
                    match hit {
                        Some(&j) => {
                            result.push_str(&rep);
                            at = j;
                            if mode == '1' || mode == '#' || mode == '%' {
                                break;
                            }
                        }
                        None => {
                            let c = value[at..].chars().next().unwrap_or(' ');
                            result.push(c);
                            at += c.len_utf8();
                        }
                    }
                }
                result.push_str(&value[at..]);
                out.push_str(&result);
                Ok(tail)
            }
            _ => Err(bad()),
        }
    }
}

fn process_words(
    mut s: &str,
    escape: char,
    lookup: Option<Lookup<'_>>,
    split: bool,
) -> Result<Vec<String>, String> {
    let expand = lookup.map(|lookup| Expand::new(escape, lookup));
    let mut words = Vec::new();
    let mut cur = String::new();
    let (mut in_single, mut in_double, mut started) = (false, false, false);
    while let Some(c) = s.chars().next() {
        let after = &s[c.len_utf8()..];
        if split && !in_single && !in_double && is_space(c) {
            if started {
                words.push(std::mem::take(&mut cur));
            }
            started = false;
            s = after;
            continue;
        }
        started = true;
        if c == escape && !in_single {
            if let Some(next) = after.chars().next() {
                if !in_double || matches!(next, '"' | '$') || next == escape {
                    // Without splitting, quotes and escapes are kept: only
                    // `\$` is taken.
                    if !split && next != '$' {
                        cur.push(c);
                    }
                    cur.push(next);
                    s = &after[next.len_utf8()..];
                    continue;
                }
            }
        }
        if split && c == '\'' && !in_double {
            in_single = !in_single;
            s = after;
            continue;
        }
        if split && c == '"' && !in_single {
            in_double = !in_double;
            s = after;
            continue;
        }
        if c == '$' && !in_single {
            if let Some(expand) = &expand {
                s = expand.variable(after, &mut cur)?;
                continue;
            }
        }
        cur.push(c);
        s = after;
    }
    if in_single || in_double {
        return Err("unterminated quote".into());
    }
    if started || !split {
        words.push(cur);
    }
    Ok(words)
}

/// The words of `s` (quotes and escapes taken out), the variables
/// expanded.
pub fn split_words(s: &str, escape: char, lookup: Lookup<'_>) -> Result<Vec<String>, String> {
    process_words(s, escape, Some(lookup), true)
}

/// The words of `s` as a shell splits them (quotes and backslashes taken
/// out), nothing expanded.
pub fn split_quoted(s: &str) -> Result<Vec<String>, String> {
    process_words(s, '\\', None, true)
}

/// `s` with the variables expanded, not split.
pub fn expand(s: &str, escape: char, lookup: Lookup<'_>) -> Result<String, String> {
    Ok(process_words(s, escape, Some(lookup), false)?
        .pop()
        .unwrap_or_default())
}

/// Whether the shell pattern `pat` matches all of `name` (`*`, `?`,
/// `[a-z]`, `[!a]`, `\x`).  `/` is not special: the callers match one
/// component at a time.
pub fn fnmatch(pat: &str, name: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let n: Vec<char> = name.chars().collect();
    // The positions to go back to after a `*`.
    let (mut pi, mut ni) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        let step = match p.get(pi) {
            Some('*') => {
                star = Some((pi, ni));
                pi += 1;
                continue;
            }
            Some('?') => Some(1),
            Some('[') => class(&p[pi..], n[ni])
                .filter(|(m, _)| *m)
                .map(|(_, len)| len),
            Some('\\') if pi + 1 < p.len() => (p[pi + 1] == n[ni]).then_some(2),
            Some(c) => (*c == n[ni]).then_some(1),
            None => None,
        };
        match step {
            Some(len) => {
                pi += len;
                ni += 1;
            }
            None => match star {
                Some((sp, sn)) => {
                    pi = sp + 1;
                    ni = sn + 1;
                    star = Some((sp, sn + 1));
                }
                None => return false,
            },
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// Match `c` against the class at the start of `p`: whether it matches
/// and the length of the class.  `None` if it is not a class.
fn class(p: &[char], c: char) -> Option<(bool, usize)> {
    let mut i = 1;
    let negate = matches!(p.get(i), Some('!') | Some('^'));
    if negate {
        i += 1;
    }
    let mut matched = false;
    let mut first = true;
    loop {
        let lo = *p.get(i)?;
        if lo == ']' && !first {
            return Some((matched != negate, i + 1));
        }
        first = false;
        if p.get(i + 1) == Some(&'-') && p.get(i + 2).is_some_and(|h| *h != ']') {
            let hi = p[i + 2];
            matched |= lo <= c && c <= hi;
            i += 3;
        } else {
            matched |= lo == c;
            i += 1;
        }
    }
}

/// Whether a path component has glob characters.
pub fn has_glob(s: &str) -> bool {
    s.contains(['*', '?', '['])
}

/// The patterns of a `.containerignore`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ignore {
    /// The components of the pattern and whether it is negated (`!`).
    patterns: Vec<(Vec<String>, bool)>,
}

fn components(s: &str) -> Vec<String> {
    s.split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .map(str::to_string)
        .collect()
}

/// Whether the pattern components `p` match all of `s`; `**` matches any
/// number of components.  Bottom-up, so in O(|p| |s|): no backtracking.
fn match_parts(p: &[String], s: &[&str]) -> bool {
    let ns = s.len();
    // `next[j]`: the rest of the pattern after the current component
    // matches `s[j..]`.
    let mut next = vec![false; ns + 1];
    next[ns] = true;
    for comp in p.iter().rev() {
        let mut cur = vec![false; ns + 1];
        for j in (0..=ns).rev() {
            cur[j] = if comp == "**" {
                next[j] || (j < ns && cur[j + 1])
            } else {
                j < ns && next[j + 1] && fnmatch(comp, s[j])
            };
        }
        next = cur;
    }
    next[0]
}

impl Ignore {
    pub fn parse(data: &str) -> Self {
        let mut patterns = Vec::new();
        for line in data.lines() {
            let line = line.trim_matches(is_space);
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (negated, pat) = match line.strip_prefix('!') {
                Some(p) => (true, p.trim_matches(is_space)),
                None => (false, line),
            };
            let mut parts = components(pat);
            parts.dedup_by(|a, b| a == "**" && b == "**");
            if !parts.is_empty() {
                patterns.push((parts, negated));
            }
        }
        Self { patterns }
    }

    #[cfg(test)]
    pub fn count(&self) -> usize {
        self.patterns.len()
    }

    /// Whether a `!` pattern can take back something the ignored
    /// directory `dir` holds: as Docker's and buildah's, one that names a
    /// path in it (`!dir/keep*`); `!*/keep` does not reach into an ignored
    /// directory.
    pub fn may_take_back(&self, dir: &str) -> bool {
        let dir = components(dir).join("/") + "/";
        self.patterns
            .iter()
            .any(|(pat, negated)| *negated && (pat.join("/") + "/").starts_with(&dir))
    }

    /// Whether there is no pattern.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Whether `path` (relative to the context) is left out: the last
    /// pattern that matches it or one of its parents decides.
    pub fn ignored(&self, path: &str) -> bool {
        let parts: Vec<&str> = path
            .split('/')
            .filter(|c| !c.is_empty() && *c != ".")
            .collect();
        let mut ignored = false;
        for (pat, negated) in &self.patterns {
            if (1..=parts.len()).any(|k| match_parts(pat, &parts[..k])) {
                ignored = !negated;
            }
        }
        ignored
    }

    /// The patterns as lines, for a worker.
    pub fn lines(&self) -> Vec<String> {
        self.patterns
            .iter()
            .map(|(p, n)| format!("{}{}", if *n { "!" } else { "" }, p.join("/")))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_words_are_split_and_never_expanded() {
        assert_eq!(
            split_quoted(r#"-o "pid comm" $HOME a\ b"#).unwrap(),
            ["-o", "pid comm", "$HOME", "a b"]
        );
        assert!(split_quoted("'open").is_err());
    }

    #[test]
    fn test_onbuild_triggers() {
        let f = Containerfile::parse("FROM a\nONBUILD COPY --chown=1 x /y\n").unwrap();
        let i = f.trigger("COPY --chown=1 x /y", 2).unwrap();
        assert_eq!((i.keyword.as_str(), i.flag("chown")), ("COPY", Some("1")));
        assert_eq!(f.trigger(" run  echo hi ", 2).unwrap().keyword, "RUN");
        for bad in ["FROM b", "ONBUILD RUN x", "MAINTAINER me", "NOPE x"] {
            assert!(f.trigger(bad, 2).is_err(), "{bad}");
        }
        assert!(Containerfile::parse("FROM a\nONBUILD ONBUILD RUN x\n").is_err());
    }

    fn lookup(name: &str) -> Option<String> {
        match name {
            "A" => Some("alpha".into()),
            "SPACED" => Some("x y".into()),
            "EMPTY" => Some(String::new()),
            _ => None,
        }
    }

    fn words(s: &str) -> Vec<String> {
        split_words(s, '\\', &lookup).unwrap()
    }

    #[test]
    fn test_words() {
        assert_eq!(words("a b  c"), ["a", "b", "c"]);
        assert_eq!(words("KEY=\"a b\" K2='c d'"), ["KEY=a b", "K2=c d"]);
        assert_eq!(
            words("$A ${A}x \"$A\" '$A'"),
            ["alpha", "alphax", "alpha", "$A"]
        );
        assert_eq!(
            words("${MISSING:-def} ${A:-def} ${A:+set} x${MISSING:+set}y"),
            ["def", "alpha", "set", "xy"]
        );
        assert_eq!(
            words("${EMPTY:-fallback} \\$A a\\ b"),
            ["fallback", "$A", "a b"]
        );
        assert_eq!(words("$SPACED"), ["x y"]);
        assert_eq!(words("\"\" x"), ["", "x"]);
        assert!(words("   ").is_empty());
        assert_eq!(words("$ $1 cost$"), ["$", "$1", "cost$"]);
        assert_eq!(words("é$A"), ["éalpha"]);

        assert!(split_words("\"unterminated", '\\', &lookup).is_err());
        assert!(split_words("${A", '\\', &lookup).is_err());
        assert!(split_words("${EMPTY:?x}", '\\', &lookup).is_err());
        assert_eq!(words("${A:?x}"), ["alpha"]);

        assert_eq!(
            expand("/srv/$A/\"q\" \\$A", '\\', &lookup).unwrap(),
            "/srv/alpha/\"q\" $A"
        );
        // Another escape character.
        assert_eq!(
            split_words("a` b C:\\x", '`', &lookup).unwrap(),
            ["a b", "C:\\x"]
        );
    }

    fn expanded(s: &str) -> Result<String, String> {
        expand(s, '\\', &|n| match n {
            "V" => Some("hello.tar.gz".into()),
            "P" => Some("a/b/c".into()),
            "E" => Some(String::new()),
            _ => None,
        })
    }

    #[test]
    fn test_shell_style_expansions() {
        let ok = |s: &str| expanded(s).unwrap();
        assert_eq!(ok("${V%.tar.gz}"), "hello");
        assert_eq!(ok("${V%.*}"), "hello.tar");
        assert_eq!(ok("${V%%.*}"), "hello");
        assert_eq!(ok("${V#*.}"), "tar.gz");
        assert_eq!(ok("${V##*.}"), "gz");
        assert_eq!(ok("${P##*/}"), "c");
        assert_eq!(ok("${P#*/}"), "b/c");
        assert_eq!(ok("${V#nomatch}"), "hello.tar.gz");
        assert_eq!(ok("${V/tar/TAR}"), "hello.TAR.gz");
        assert_eq!(ok("${V/./_}"), "hello_tar.gz");
        assert_eq!(ok("${V//./_}"), "hello_tar_gz");
        assert_eq!(ok("${V/#hello/bye}"), "bye.tar.gz");
        assert_eq!(ok("${V/#tar/bye}"), "hello.tar.gz");
        assert_eq!(ok("${V/%gz/Z}"), "hello.tar.Z");
        assert_eq!(ok("${V/.tar}"), "hello.gz");
        assert_eq!(ok("${U:-${V%.gz}}"), "hello.tar");
        assert_eq!(ok("${E:-d}-${V:+yes}-${U:+no}x"), "d-yes-x");
        assert_eq!(ok("x${V%.tar.gz}y${U}z"), "xhelloyz");
        for bad in [
            "${V-x}", "${V%}", "${V#}", "${V/}", "${V", "${}", "${V:}", "${V.x}",
        ] {
            assert!(expanded(bad).is_err(), "{bad}");
        }
        assert_eq!(
            expanded("${V:}").unwrap_err(),
            "bad substitution in `${V:}`"
        );
        // the shell's (and BuildKit's) patterns: `*` matches a `/`, the
        // whole value and the empty string are candidates
        assert_eq!(ok("${P%%/*}"), "a");
        assert_eq!(ok("${P%/*}"), "a/b");
        assert_eq!(ok("${P/*\\//X}"), "Xc");
        assert_eq!(ok("${V##*}"), "");
        assert_eq!(ok("${V%*}"), "hello.tar.gz");
        assert_eq!(ok("${V#hello.tar.g}"), "z");
        // escapes, quotes and classes in the patterns and the words
        assert_eq!(ok("${P//\\//_}"), "a_b_c");
        assert_eq!(ok("${V//[.]/-}"), "hello-tar-gz");
        assert_eq!(ok("${V/t?r/X}"), "hello.X.gz");
        assert_eq!(ok("${V//\\*/x}"), "hello.tar.gz");
        assert_eq!(ok("${U:-'a}b'}"), "a}b");
        assert_eq!(ok("${U:-\"x y\"}"), "x y");
        assert_eq!(ok("\\${V%.gz}"), "${V%.gz}");
        assert_eq!(ok("${V/a/${U}}"), "hello.tr.gz");
        assert_eq!(ok("${E%x}${U#x}"), "");
        assert_eq!(ok("${U:-a\\ b}"), "a b");
        assert_eq!(ok("${V/\"a\"/Q}"), "hello.tQr.gz");
        assert_eq!(ok("${V/\"*\"/Q}"), "hello.tar.gz");
        assert_eq!(ok("${V/'.'*/}"), "hello");
        assert_eq!(ok("${U:-\"$V\"}"), "hello.tar.gz");
        assert!(expanded("${U:-\"x}").is_err());
        // a nesting deep enough to run out of stack is refused
        let deep = format!("{}z{}", "${U:-".repeat(10_000), "}".repeat(10_000));
        assert!(expanded(&deep)
            .unwrap_err()
            .contains("nested more than 64 deep"));
        let fine = format!("{}z{}", "${U:-".repeat(60), "}".repeat(60));
        assert_eq!(ok(&fine), "z");
        // the limit is the depth of one nesting: 64 levels are fine, 65
        // are not, and side by side the levels do not add up
        let nested = |n: usize| format!("{}z{}", "${U:-".repeat(n), "}".repeat(n));
        assert_eq!(ok(&nested(64)), "z");
        assert!(expanded(&nested(65))
            .unwrap_err()
            .contains("nested more than 64 deep"));
        assert_eq!(ok(&nested(64).repeat(3)), "zzz");
        assert_eq!(ok(&"${U:-${U:-a}}".repeat(100)), "a".repeat(100));
        // a refused one leaves nothing behind for the next
        assert!(expanded(&nested(65)).is_err());
        assert_eq!(ok(&nested(64)), "z");
        // the scan direction of `#`, `##`, `%` and `%%` over characters of
        // more than one byte
        let m = |s: &str| expand(s, '\\', &|n| (n == "M").then(|| "äx.äy.äz".to_string())).unwrap();
        assert_eq!(m("${M#*.}"), "äy.äz");
        assert_eq!(m("${M##*.}"), "äz");
        assert_eq!(m("${M%.*}"), "äx.äy");
        assert_eq!(m("${M%%.*}"), "äx");
        assert_eq!(m("${M#ä}"), "x.äy.äz");
        assert_eq!(m("${M%z}"), "äx.äy.ä");
        assert_eq!(m("${M##ä*ä}"), "z");
        assert_eq!(m("${M%%ä*ä}"), "äx.äy.äz");
        assert_eq!(m("${M#ä*ä}"), "y.äz");
        assert_eq!(m("${M%ä*ä}"), "äx.äy.äz");
    }

    #[test]
    fn test_continuations_bom_and_empty_lines() {
        let f = Containerfile::parse("\u{feff}FROM a\nRUN echo hello\\\n   world\n").unwrap();
        assert_eq!(f.stages[0].instrs[0].args, "echo hello   world");
        let f = Containerfile::parse("FROM a\nRUN echo a \\\n\n  # c\n   \n&& echo b\nENV X=1\n")
            .unwrap();
        let s = &f.stages[0];
        assert_eq!(s.instrs.len(), 2);
        assert_eq!(s.instrs[0].args, "echo a && echo b");
        assert_eq!(s.instrs[1].keyword, "ENV");
        // Windows line endings, also in a here-document
        let f = Containerfile::parse(
            "\u{feff}FROM a\r\nRUN echo a\\\r\n  b\r\nRUN <<EOF\r\necho c\r\nEOF\r\n",
        )
        .unwrap();
        let s = &f.stages[0];
        assert_eq!(s.instrs[0].args, "echo a  b");
        assert_eq!(s.instrs[1].heredocs[0].body, "echo c\n");
    }

    #[test]
    fn test_parse() {
        let file = "# syntax=docker/dockerfile:1\n\
                    ARG BASE=alpine\n\
                    FROM $BASE AS Build\n  \
                    # indented comment\n\
                    RUN echo a \\\n  \
                    # comment inside the continuation\n  \
                    && echo b\n\
                    COPY --from=other --chown=1:2 a b /dst/\n\
                    run [\"/bin/sh\", \"-c\", \"true\"]\n\
                    CMD [not json\n\
                    \n\
                    FROM --platform=linux/arm64 scratch\n\
                    ENV A=1\n";
        let f = Containerfile::parse(file).unwrap();
        assert_eq!(f.global_args.len(), 1);
        assert_eq!(f.global_args[0].args, "BASE=alpine");
        assert_eq!(f.stages.len(), 2);
        let s = &f.stages[0];
        assert_eq!(
            (s.base.as_str(), s.name.as_deref()),
            ("$BASE", Some("Build"))
        );
        assert_eq!(s.instrs.len(), 4);
        assert_eq!((s.instrs[0].keyword.as_str(), s.instrs[0].line), ("RUN", 5));
        assert_eq!(s.instrs[0].args, "echo a   && echo b");
        assert!(s.instrs[0].json.is_none());
        assert_eq!(s.instrs[1].keyword, "COPY");
        assert_eq!(s.instrs[1].flags, ["--from=other", "--chown=1:2"]);
        assert_eq!(s.instrs[1].flag("chown"), Some("1:2"));
        assert_eq!(s.instrs[1].args, "a b /dst/");
        assert_eq!(
            s.instrs[1].text(),
            "COPY --from=other --chown=1:2 a b /dst/"
        );
        assert_eq!(s.instrs[2].keyword, "RUN");
        assert_eq!(s.instrs[2].json.as_ref().map(Vec::len), Some(3));
        assert_eq!(s.instrs[3].keyword, "CMD");
        assert!(s.instrs[3].json.is_none());
        let t = &f.stages[1];
        assert_eq!((t.name.as_deref(), t.base.as_str()), (None, "scratch"));
        assert_eq!(t.platform.as_deref(), Some("linux/arm64"));
        assert_eq!(t.instrs.len(), 1);

        for bad in [
            "RUN true\n",
            "FROM a\nBOGUS x\n",
            "ARG X\n",
            "FROM a b\n",
            "FROM a AS\n",
            "FROM --bogus=1 a\n",
            "",
            "# escape=x\nFROM a\n",
        ] {
            assert!(Containerfile::parse(bad).is_err(), "accepted: {bad}");
        }

        let f = Containerfile::parse("# escape=`\nFROM a\nRUN dir `\n  c:\\\n").unwrap();
        assert_eq!(f.escape, '`');
        assert_eq!(f.stages[0].instrs[0].args, "dir   c:\\");
    }

    #[test]
    fn here_documents_follow_their_instruction() {
        let file = "FROM a\n\
                    RUN <<EOF\n\
                    # not a comment\n\
                    \n\
                    echo $HOME\n\
                    EOF\n\
                    RUN cat <<-\"A\" > /x && cat 3<<'B' \\\n  \
                    && true\n\
                    \tone\n\
                    \tA\n\
                    two\n\
                    B\n\
                    COPY --chmod=755 <<s1 <<s2 /dst/\n\
                    x\n\
                    s1\n\
                    y\n\
                    s2\n\
                    RUN [\"echo\", \"<<EOF\"]\n\
                    RUN echo '<<EOF' \"<<X\" <<<word\n\
                    ENV A=<<EOF\n";
        let f = Containerfile::parse(file).unwrap();
        let s = &f.stages[0].instrs;
        assert_eq!(s.len(), 6);
        assert_eq!(s[0].args, "<<EOF");
        assert_eq!(s[0].heredocs.len(), 1);
        let h = &s[0].heredocs[0];
        assert_eq!((h.name.as_str(), h.chomp, h.expand), ("EOF", false, true));
        assert_eq!(h.body, "# not a comment\n\necho $HOME\n");
        assert_eq!(s[0].only_heredoc(), Some(h));
        assert_eq!(
            s[0].raw_text(),
            "RUN <<EOF\n# not a comment\n\necho $HOME\nEOF"
        );
        assert_eq!(s[1].line, 7);
        assert_eq!(s[1].args, "cat <<-\"A\" > /x && cat 3<<'B'   && true");
        let names: Vec<_> = s[1]
            .heredocs
            .iter()
            .map(|h| (h.name.as_str(), h.chomp, h.expand))
            .collect();
        assert_eq!(names, [("A", true, false), ("B", false, false)]);
        assert_eq!(s[1].heredocs[0].body, "\tone\n");
        assert_eq!(s[1].heredocs[0].content(), "one\n");
        assert_eq!(s[1].only_heredoc(), None);
        assert_eq!(s[2].keyword, "COPY");
        assert_eq!(
            s[2].heredoc_of("<<s2").map(|h| h.body.as_str()),
            Some("y\n")
        );
        assert!(s[2].heredoc_of("<<s3").is_none());
        assert!(s[3].heredocs.is_empty() && s[3].json.is_some());
        assert!(s[4].heredocs.is_empty());
        assert_eq!(s[5].keyword, "ENV");
        assert!(s[5].heredocs.is_empty());
        assert_eq!(f.stages[0].instrs.len(), 6);

        // (a delimiter names one file of the step's own directory)
        let f =
            Containerfile::parse("FROM a\nCOPY <<.. <<a/b <<. /d/\nx\n..\ny\na/b\nz\n.\n").unwrap();
        let names: Vec<_> = f.stages[0].instrs[0]
            .heredocs
            .iter()
            .map(Heredoc::file_name)
            .collect();
        assert_eq!(names, ["__", "a_b", "_"]);

        let e = Containerfile::parse("FROM a\nRUN <<EOF\nno end\n").unwrap_err();
        assert!(e.contains("here-document `EOF` has no end"), "{e}");
        for (w, want) in [
            ("<<EOF", Some(("EOF", false, true))),
            ("<<-EOF", Some(("EOF", true, true))),
            ("<<'E F'", None),
            ("<<\"E\"", Some(("E", false, false))),
            ("12<<X", Some(("X", false, true))),
            ("<<", None),
            ("<<<x", None),
            ("x<<y", None),
        ] {
            let got = heredoc_marker(w);
            assert_eq!(
                got.as_ref().map(|(n, c, e)| (n.as_str(), *c, *e)),
                want,
                "{w}"
            );
        }
    }

    #[test]
    fn test_flags() {
        let f = Containerfile::parse("FROM a\nCOPY --chmod=644 --link x y\n").unwrap();
        let i = &f.stages[0].instrs[0];
        assert_eq!(i.flag("chmod"), Some("644"));
        assert!(i.check_flags(&["chmod", "link"]).is_ok());
        assert!(i.check_flags(&["chmod"]).is_err());
    }

    #[test]
    fn test_boolean_and_repeated_flags() {
        let f = Containerfile::parse(
            "FROM a\nCOPY --parents --exclude=*.log --exclude=b x y/\nCOPY --parents=false x y\nCOPY --parents=maybe x y\nCOPY x y\n",
        )
        .unwrap();
        let i = &f.stages[0].instrs;
        assert_eq!(i[0].flag_bool("parents"), Ok(true));
        assert_eq!(i[0].flag_values("exclude"), ["*.log", "b"]);
        assert_eq!(i[1].flag_bool("parents"), Ok(false));
        assert!(i[2].flag_bool("parents").is_err());
        assert_eq!(i[3].flag_bool("parents"), Ok(false));
        assert!(i[3].flag_values("exclude").is_empty());
    }

    #[test]
    fn test_fnmatch() {
        assert!(fnmatch("*.log", "a.log"));
        assert!(!fnmatch("*.log", "a.log2"));
        assert!(fnmatch("secret?", "secret1"));
        assert!(!fnmatch("secret?", "secret12"));
        assert!(fnmatch("[a-c]x", "bx"));
        assert!(!fnmatch("[!a-c]x", "bx"));
        assert!(fnmatch("[]]", "]"));
        assert!(fnmatch("a*b*c", "aXXbYYc"));
        assert!(fnmatch("\\*", "*"));
        assert!(!fnmatch("\\*", "x"));
        assert!(fnmatch("*", ""));
        assert!(!fnmatch("[a", "a"));
    }

    #[test]
    fn test_ignore() {
        let ig = Ignore::parse(
            "# comment\n\
             /build\n\
             *.log\n\
             **/*.tmp\n\
             !keep.tmp\n\
             docs/**/secret?\n\
             ./node_modules/\n",
        );
        assert_eq!(ig.count(), 6);
        assert!(ig.ignored("build"));
        assert!(ig.ignored("build/out/x"));
        assert!(!ig.ignored("src/build"));
        assert!(ig.ignored("a.log"));
        assert!(!ig.ignored("dir/a.log"));
        assert!(ig.ignored("x.tmp"));
        assert!(ig.ignored("a/b/x.tmp"));
        assert!(!ig.ignored("keep.tmp"));
        assert!(ig.ignored("a/keep.tmp"));
        assert!(ig.ignored("docs/secret1"));
        assert!(ig.ignored("docs/a/b/secret2"));
        assert!(!ig.ignored("docs/a/secret12"));
        assert!(ig.ignored("node_modules/pkg/index.js"));
        assert!(!ig.ignored("Containerfile"));
        assert_eq!(Ignore::parse(&ig.lines().join("\n")), ig);

        // Many `**` and a long path do not take exponential time.
        let ig = Ignore::parse(&format!("{}x", "**/a*/".repeat(30)));
        let path = vec!["a"; 60].join("/");
        let start = std::time::Instant::now();
        assert!(!ig.ignored(&path));
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
        assert!(Ignore::parse("**/**/**/b").ignored("a/a/b"));
        let ignore = Ignore::parse("dir\nother\n!dir/keep*\n!*/sub1*");
        assert!(ignore.may_take_back("dir"));
        assert!(!ignore.may_take_back("other"));
        assert!(!ignore.may_take_back("di"));
    }
}
