// SPDX-License-Identifier: Apache-2.0
//! One request as a handler sees it.

use super::error::{ApiError, ApiResult, Kind};
use crate::engine::Engine;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Method};
use hyper::upgrade::OnUpgrade;
use serde::de::DeserializeOwned;
use velarx_proto::godecode;

/// Largest JSON request body.
pub const MAX_JSON_BODY: usize = 16 * 1024 * 1024;

pub struct Call {
    pub engine: Engine,
    pub method: Method,
    pub kind: Kind,
    /// `/libpod` route (as opposed to the Docker compatible one).
    pub libpod: bool,
    /// The `major.minor` of the version in the path.
    pub version: Option<(u32, u32)>,
    /// The `{}` and `{*}` parts of the path, decoded.
    pub params: Vec<String>,
    pub query: Vec<(String, String)>,
    /// The path and query of the request, for the error messages.
    pub target: String,
    pub headers: HeaderMap,
    /// In a mutex so that a `&Call` can be held across an await.
    body: Option<std::sync::Mutex<Body>>,
    upgrade: Option<OnUpgrade>,
    hold: Option<Hold>,
    /// The connection of the client
    pub peer: Option<PeerFd>,
    /// The unix socket the request came in on
    pub socket: Option<LocalSocket>,
}

/// The most of a request body that nobody read that is read and thrown
/// away.
const MAX_DISCARDED_BODY: usize = 64 * 1024 * 1024;

/// A request answered before its body was read (a refused parameter, no
/// route) leaves the body to the connection, which closes when the body
/// is dropped unread: the client, still writing, gets a reset and loses
/// the answer.  The rest of the body is read and thrown away, up to a
/// bound, while the answer goes out.
pub(super) fn discard(body: Body) {
    use axum::body::HttpBody;
    use futures::StreamExt;
    // (a call made outside a runtime has no connection behind it)
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    if body.is_end_stream() {
        return;
    }
    runtime.spawn(async move {
        let mut chunks = body.into_data_stream();
        let mut left = MAX_DISCARDED_BODY;
        while let Some(Ok(chunk)) = chunks.next().await {
            match left.checked_sub(chunk.len()) {
                Some(rest) => left = rest,
                None => return,
            }
        }
    });
}

impl Drop for Call {
    fn drop(&mut self) {
        discard(self.take_body());
    }
}

/// A descriptor of the connection of the client, of its own (put in the
/// request by the server): the connection can be taken over and served
/// after the request, and its hang up watched with this.
#[derive(Clone)]
pub struct PeerFd(pub std::sync::Arc<std::os::fd::OwnedFd>);

/// The path of the unix socket the request came in on.
#[derive(Clone)]
pub struct LocalSocket(pub std::sync::Arc<std::path::PathBuf>);

/// Keeps the frontend from leaving while it lives (it is put in the
/// request by the server, and lasts as long as a connection taken over).
#[derive(Clone)]
pub struct Hold(pub std::sync::Arc<dyn std::any::Any + Send + Sync>);

impl Call {
    pub(super) fn new(
        engine: Engine,
        method: Method,
        headers: HeaderMap,
        body: Body,
        upgrade: Option<OnUpgrade>,
        hold: Option<Hold>,
    ) -> Self {
        Self {
            engine,
            method,
            kind: Kind::None,
            libpod: false,
            version: None,
            params: Vec::new(),
            query: Vec::new(),
            target: String::new(),
            headers,
            body: Some(std::sync::Mutex::new(body)),
            upgrade,
            hold,
            peer: None,
            socket: None,
        }
    }

    pub fn head(&self) -> bool {
        self.method == Method::HEAD
    }

    /// The version of the path is at least `major.minor` (no version: the
    /// current one).
    pub fn at_least(&self, major: u32, minor: u32) -> bool {
        match self.version {
            None => true,
            Some((a, b)) => a > major || (a == major && b >= minor),
        }
    }

    pub fn param(&self, i: usize) -> &str {
        self.params.get(i).map(String::as_str).unwrap_or("")
    }

    /// A query parameter.  podman's decoder (gorilla/schema) matches the
    /// names without regard to case, and its clients send the names of
    /// some options in lower case (`alltags` for `allTags`): an exact name
    /// wins, else one that differs in case.
    pub fn q(&self, name: &str) -> Option<&str> {
        query_value(&self.query, name)
    }

    pub fn q_all(&self, name: &str) -> Vec<&str> {
        self.query
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub fn q_bool(&self, name: &str, default: bool) -> ApiResult<bool> {
        match self.q(name) {
            None | Some("") => Ok(default),
            Some(v) => parse_bool(v).ok_or_else(|| self.bad_parameter(name)),
        }
    }

    /// A query parameter that asks for what velarx does not have is an
    /// error (501), not ignored: `names` with a value (a boolean must be
    /// true).  The names are those of podman's schema; clients send them
    /// in any case.
    pub fn refuse_params(&self, names: &[&str]) -> ApiResult<()> {
        for name in names {
            let given = self.q_all(name).iter().any(|v| match parse_bool(v) {
                Some(b) => b,
                None => !v.is_empty(),
            });
            if given {
                return Err(ApiError::not_implemented(format!(
                    "the parameter `{name}` is not supported"
                )));
            }
        }
        Ok(())
    }

    /// [`Call::refuse_params`] for parameters that are not booleans: any
    /// value that is not empty (0 is one).
    pub fn refuse_set(&self, names: &[&str]) -> ApiResult<()> {
        match names
            .iter()
            .find(|n| self.q_all(n).iter().any(|v| !v.is_empty()))
        {
            Some(name) => Err(ApiError::not_implemented(format!(
                "the parameter `{name}` is not supported"
            ))),
            None => Ok(()),
        }
    }

    /// podman's error for a query parameter its schema decoder cannot
    /// convert (a 400; some handlers say 500).
    pub fn bad_parameter(&self, name: &str) -> ApiError {
        let cause = format!("schema: error converting value for {name:?}");
        ApiError::bad_request(format!(
            "failed to parse parameters for {}: {cause}",
            self.target
        ))
        .with_cause(cause)
    }

    /// A boolean of a route's decoder: libpod's is strict (Go's ParseBool),
    /// the Docker routes' takes any word but "", "0", "no", "false" and
    /// "none" (case and spaces aside) as true.  The last value counts.
    pub fn q_flag(&self, name: &str) -> ApiResult<bool> {
        let Some(v) = self.q_all(name).last().copied() else {
            return Ok(false);
        };
        if self.libpod {
            return match v {
                "" => Ok(false),
                v => parse_bool(v).ok_or_else(|| self.bad_parameter(name)),
            };
        }
        let v = v.trim().to_lowercase();
        Ok(!matches!(v.as_str(), "" | "0" | "no" | "false" | "none"))
    }

    /// A `*uint` of podman's schema: none if the parameter is not given,
    /// zero if it is empty, else a decimal number that is not negative
    /// (`-1` is a 400, as podman's).
    pub fn q_uint(&self, name: &str) -> ApiResult<Option<u64>> {
        match self.q_all(name).last().copied() {
            None => Ok(None),
            Some("") => Ok(Some(0)),
            Some(v) if v.bytes().all(|b| b.is_ascii_digit()) => v
                .parse::<u64>()
                .map(Some)
                .map_err(|_| self.bad_parameter(name)),
            Some(_) => Err(self.bad_parameter(name)),
        }
    }

    /// An `int` of podman's schema (Go's ParseInt): none if the parameter
    /// is not given, zero if it is empty.
    pub fn q_int(&self, name: &str) -> ApiResult<Option<i64>> {
        match self.q_all(name).last().copied() {
            None => Ok(None),
            Some("") => Ok(Some(0)),
            Some(v) => v
                .parse::<i64>()
                .map(Some)
                .map_err(|_| self.bad_parameter(name)),
        }
    }

    pub fn q_i64(&self, name: &str, default: i64) -> ApiResult<i64> {
        match self.q(name) {
            None | Some("") => Ok(default),
            // (-1 as an unsigned number is the largest one)
            Some(v) => v
                .parse::<i128>()
                .map(|n| n.clamp(i64::MIN.into(), i64::MAX.into()) as i64)
                .map_err(|_| self.bad_parameter(name)),
        }
    }

    /// The `filters` parameter: each key with its values (the Docker clients
    /// also send `{"key": {"value": true}}`).
    pub fn filters(&self) -> ApiResult<Filters> {
        match self.q("filters") {
            None | Some("") => Ok(Filters::default()),
            Some(s) => Filters::parse(s),
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// The client asks to take over the connection (`Upgrade: tcp`).
    pub fn wants_upgrade(&self) -> bool {
        self.upgrade.is_some()
            && self
                .header("upgrade")
                .is_some_and(|v| v.eq_ignore_ascii_case("tcp"))
            && self.header("connection").is_some_and(|v| {
                v.split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
            })
    }

    pub fn take_hold(&mut self) -> Option<Hold> {
        self.hold.take()
    }

    pub fn take_upgrade(&mut self) -> Option<OnUpgrade> {
        self.upgrade.take()
    }

    pub fn take_body(&mut self) -> Body {
        match self.body.take() {
            Some(b) => b.into_inner().unwrap_or_else(|p| p.into_inner()),
            None => Body::empty(),
        }
    }

    /// The credentials of the client: `X-Registry-Auth` (and podman's
    /// `tlsVerify` aside, nothing else of the request reaches a registry).
    pub fn registry_access(&self) -> ApiResult<velarx_registry::auth::RegistryAccess> {
        match self.header("x-registry-auth") {
            Some(h) => velarx_registry::auth::RegistryAccess::from_registry_auth(h)
                .map_err(ApiError::bad_request),
            None => Ok(Default::default()),
        }
    }

    /// A parameter of the query that is set (not empty).
    pub fn q_set(&self, name: &str) -> Option<String> {
        self.q(name).filter(|v| !v.is_empty()).map(str::to_string)
    }

    /// The whole body, at most `limit` bytes.
    pub async fn body_bytes(&mut self, limit: usize) -> ApiResult<Bytes> {
        axum::body::to_bytes(self.take_body(), limit)
            .await
            .map_err(|e| ApiError::bad_request(format!("read the request body: {e}")))
    }

    /// The JSON body, `None` when it is empty.
    pub async fn json_value(&mut self) -> ApiResult<Option<serde_json::Value>> {
        let b = self.body_bytes(MAX_JSON_BODY).await?;
        if b.iter().all(u8::is_ascii_whitespace) {
            return Ok(None);
        }
        Ok(Some(godecode::first_value(&b)?))
    }

    pub async fn json<T: DeserializeOwned>(&mut self) -> ApiResult<T> {
        let b = self.body_bytes(MAX_JSON_BODY).await?;
        Ok(godecode::from_slice(&b)?)
    }

    /// The JSON body, or the default of the type when it is empty.
    pub async fn json_or_default<T: DeserializeOwned + Default>(&mut self) -> ApiResult<T> {
        let b = self.body_bytes(MAX_JSON_BODY).await?;
        if b.iter().all(u8::is_ascii_whitespace) {
            return Ok(T::default());
        }
        Ok(godecode::from_slice(&b)?)
    }

    pub(super) fn set_route(&mut self, kind: Kind, libpod: bool, version: Option<(u32, u32)>) {
        self.kind = kind;
        self.libpod = libpod;
        self.version = version;
    }
}

/// Whether a JSON value sets anything (the clients send empty objects and
/// zero values for what they do not use).
pub fn has_value(v: &serde_json::Value) -> bool {
    use serde_json::Value;
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|n| n != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => a.iter().any(has_value),
        Value::Object(o) => o.values().any(has_value),
    }
}

/// An option of a body that velarx does not have, given: 501 naming it.
pub fn refuse_field(name: &str, value: &serde_json::Value) -> ApiResult<()> {
    if has_value(value) {
        return Err(ApiError::not_implemented(format!(
            "`{name}` is not supported"
        )));
    }
    Ok(())
}

/// Go's strconv.ParseBool.
/// The annotations of a query, `KEY=VALUE` each.
pub fn annotations<'a>(
    words: impl IntoIterator<Item = &'a str>,
) -> ApiResult<std::collections::BTreeMap<String, String>> {
    words
        .into_iter()
        .map(|a| {
            a.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .ok_or_else(|| {
                    ApiError::bad_request(format!("invalid annotation {a:?}: KEY=VALUE"))
                })
        })
        .collect()
}

pub use velarx_proto::godecode::parse_bool;

/// Query filters: key to values.
#[derive(Debug, Default, Clone)]
pub struct Filters(pub Vec<(String, Vec<String>)>);

impl Filters {
    /// The `filters` of a query; podman's handlers fail with a 500 and the
    /// error of Go's JSON decoder as the cause (the pods' with a 400).
    pub fn parse(s: &str) -> ApiResult<Self> {
        let invalid = |cause: String| {
            ApiError::internal(format!("failed to parse filters: {cause}")).with_cause(cause)
        };
        let v: serde_json::Value =
            serde_json::from_str(s).map_err(|e| invalid(godecode::go_error(s.as_bytes(), &e)))?;
        let obj = v.as_object().ok_or_else(|| {
            invalid("json: cannot unmarshal into Go value of type map[string][]string".into())
        })?;
        let mut out = Vec::new();
        for (k, v) in obj {
            let values = match v {
                serde_json::Value::Array(a) => a
                    .iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect(),
                serde_json::Value::Object(o) => o
                    .iter()
                    .filter(|(_, v)| v.as_bool().unwrap_or(true))
                    .map(|(k, _)| k.clone())
                    .collect(),
                serde_json::Value::String(s) => vec![s.clone()],
                _ => Vec::new(),
            };
            out.push((k.clone(), values));
        }
        Ok(Self(out))
    }

    /// The filters an image prune takes (`label`, `label!`, `until`; Docker's
    /// `dangling` is read by the handler); any other is an error, whether
    /// or not there is an image.
    pub fn image_prune(&self) -> ApiResult<Filters> {
        if let Some(k) = self
            .keys()
            .find(|k| !matches!(*k, "label" | "label!" | "until" | "dangling"))
        {
            return Err(ApiError::internal(format!("invalid filter {k:?}")));
        }
        Ok(Filters(
            self.0
                .iter()
                .filter(|(k, _)| matches!(k.as_str(), "label" | "label!" | "until"))
                .cloned()
                .collect(),
        ))
    }

    pub fn get(&self, key: &str) -> &[String] {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_slice())
            .unwrap_or(&[])
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|(k, _)| k.as_str())
    }
}

/// Query string to decoded pairs.
pub fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (decode(k, true), decode(v, true))
        })
        .collect()
}

/// Percent decoding; with `plus`, `+` is a space (query strings).
pub fn decode(s: &str, plus: bool) -> String {
    let s = if plus && s.contains('+') {
        std::borrow::Cow::Owned(s.replace('+', " "))
    } else {
        std::borrow::Cow::Borrowed(s)
    };
    match percent_encoding::percent_decode_str(&s).decode_utf8() {
        Ok(d) => d.into_owned(),
        Err(_) => s.into_owned(),
    }
}

/// The value of the query parameter `name`: an exact name first, else
/// one that differs in case.
fn query_value<'a>(query: &'a [(String, String)], name: &str) -> Option<&'a str> {
    query
        .iter()
        .find(|(k, _)| k == name)
        .or_else(|| query.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)))
        .map(|(_, v)| v.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_is_what_urlencoding_decoded() {
        assert_eq!(decode("a%20b%2Fc%3Ad%40e%7E", false), "a b/c:d@e~");
        assert_eq!(decode("a+b%2B", false), "a+b+");
        assert_eq!(decode("a+b%2B", true), "a b+");
        assert_eq!(decode("%C3%A9", false), "é");
        // not UTF-8, or not an escape: the text as it came
        assert_eq!(decode("%FF%20", false), "%FF%20");
        assert_eq!(decode("100%", false), "100%");
        assert_eq!(decode("%zz", false), "%zz");
    }

    #[test]
    fn query_names_match_without_case() {
        let q = parse_query("alltags=true&T=1&t=2");
        assert_eq!(query_value(&q, "allTags"), Some("true"));
        assert_eq!(query_value(&q, "t"), Some("2"));
        assert_eq!(query_value(&q, "T"), Some("1"));
        assert_eq!(query_value(&q, "none"), None);
    }

    #[test]
    fn query_decoding() {
        let q = parse_query("a=1&b=x%20y&c=p+q&flag&names=a&names=b");
        assert_eq!(q[0], ("a".into(), "1".into()));
        assert_eq!(q[1], ("b".into(), "x y".into()));
        assert_eq!(q[2], ("c".into(), "p q".into()));
        assert_eq!(q[3], ("flag".into(), "".into()));
        assert_eq!(q.len(), 6);
    }

    #[test]
    fn removal_numbers_as_podman_reads_them() {
        let call = |q: &str, libpod: bool| {
            let mut c = Call::new(
                crate::engine::Engine::new(std::path::Path::new("/nonexistent")),
                Method::GET,
                HeaderMap::new(),
                Body::empty(),
                None,
                None,
            );
            c.libpod = libpod;
            c.target = format!("/x?{q}");
            c.query = parse_query(q);
            c
        };
        let c = call("timeout=7&t=-1&e=&p=%2B5&n=-1", true);
        assert_eq!(c.q_uint("timeout").unwrap(), Some(7));
        assert_eq!(c.q_uint("none").unwrap(), None);
        assert_eq!(c.q_uint("e").unwrap(), Some(0));
        assert_eq!(c.q_int("t").unwrap(), Some(-1));
        for bad in ["n", "p"] {
            let e = c.q_uint(bad).unwrap_err();
            assert_eq!(e.status.as_u16(), 400);
            assert!(e
                .message
                .contains(&format!("error converting value for \"{bad}\"")));
        }
        assert!(call("force=yes", true).q_flag("force").is_err());
        assert!(call("force=yes", false).q_flag("force").unwrap());
        assert!(!call("force=No", false).q_flag("force").unwrap());
        assert!(!call("force=", true).q_flag("force").unwrap());
        assert!(call("force=T", true).q_flag("force").unwrap());
    }

    #[test]
    fn bools() {
        assert_eq!(parse_bool("True"), Some(true));
        assert_eq!(parse_bool("0"), Some(false));
        assert_eq!(parse_bool("yes"), None);
    }

    #[test]
    fn filters_shapes() {
        let f = Filters::parse(r#"{"a":["x","y"],"b":{"z":true,"w":false},"c":"s"}"#).unwrap();
        assert_eq!(f.get("a"), ["x", "y"]);
        assert_eq!(f.get("b"), ["z"]);
        assert_eq!(f.get("c"), ["s"]);
        assert!(f.get("none").is_empty());
        assert!(Filters::parse("[1]").is_err());
    }
}
