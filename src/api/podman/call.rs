// SPDX-License-Identifier: Apache-2.0
//! What the shaping of the engine shares of podman's requests: filters,
//! Go's booleans, JSON bodies.

use super::error::{ApiError, ApiResult};
use velarx_proto::godecode;

/// Largest JSON request body.
pub const MAX_JSON_BODY: usize = 16 * 1024 * 1024;

/// The JSON of a body, `None` when it is empty.
pub fn json_value_of(b: &[u8]) -> ApiResult<Option<serde_json::Value>> {
    if b.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    Ok(Some(godecode::first_value(b)?))
}

pub use velarx_proto::godecode::parse_bool;

/// podman's label match: `KEY` is a label that is there, `KEY=VALUE` one
/// with that value.
pub fn label_matches<'a>(
    labels: impl IntoIterator<Item = (&'a String, &'a String)>,
    spec: &str,
) -> bool {
    let (k, v) = spec
        .split_once('=')
        .map_or((spec, None), |(k, v)| (k, Some(v)));
    labels
        .into_iter()
        .any(|(lk, lv)| lk == k && v.is_none_or(|v| v == lv))
}

/// podman's FilterID: a prefix of the id when WANT is hexadecimal, else a
/// regular expression found anywhere in the id.
pub fn id_matches(id: &str, want: &str) -> bool {
    if want.bytes().all(|b| b.is_ascii_hexdigit()) {
        return id.starts_with(&want.to_ascii_lowercase());
    }
    regex_lite::Regex::new(want).is_ok_and(|r| r.is_match(id))
}

/// Query filters: key to values.
#[derive(Debug, Default, Clone)]
pub struct Filters(pub Vec<(String, Vec<String>)>);

impl Filters {
    /// The `--filter KEY=VALUE` options of a command, by key; one without
    /// a `=` is refused (podman's words), it would select nothing or all.
    pub fn of_args(args: &[String]) -> ApiResult<Self> {
        let mut grouped: Vec<(String, Vec<String>)> = Vec::new();
        for f in args {
            if let Some(message) = crate::client::filter_without_value(std::slice::from_ref(f)) {
                return Err(ApiError::internal(message));
            }
            let (k, v) = f.split_once('=').unwrap_or((f, ""));
            match grouped.iter_mut().find(|(key, _)| key == k) {
                Some((_, values)) => values.push(v.to_string()),
                None => grouped.push((k.to_string(), vec![v.to_string()])),
            }
        }
        Ok(Self(grouped))
    }

    /// The `until` of a prune: one time, which parses (podman's words); a
    /// prune that ignored it would remove everything.
    pub fn check_prune_until(&self) -> ApiResult<()> {
        match self.get("until") {
            [] => Ok(()),
            [u] if super::events::parse_since(u).is_some() => Ok(()),
            [u] => Err(ApiError::internal(format!(
                "failed to parse value as time or duration: {u:?}"
            ))),
            _ => Err(ApiError::internal(
                "specify exactly one timestamp for until",
            )),
        }
    }

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
    /// `dangling` is read by the handler), as `key=value`; any other is
    /// an error, whether or not there is an image.
    pub fn image_prune(&self) -> ApiResult<Vec<String>> {
        if let Some(k) = self
            .keys()
            .find(|k| !matches!(*k, "label" | "label!" | "until" | "dangling"))
        {
            return Err(ApiError::bad_request(format!("invalid filter {k:?}")));
        }
        Ok(self
            .0
            .iter()
            .filter(|(k, _)| matches!(k.as_str(), "label" | "label!" | "until"))
            .flat_map(|(k, vs)| vs.iter().map(move |v| format!("{k}={v}")))
            .collect())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// podman's label match, whatever map the labels are in: `KEY` is a
    /// label that is there (any value, the empty one too), `KEY=VALUE` one
    /// with that value; a value may hold `=`.
    #[test]
    fn a_label_matches_by_key_or_by_key_and_value() {
        let labels: std::collections::BTreeMap<String, String> =
            [("a", "1"), ("e", ""), ("x", "y=z")]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
        for (spec, want) in [
            ("a", true),
            ("a=1", true),
            ("a=2", false),
            ("e", true),
            ("e=", true),
            ("x=y=z", true),
            ("x=y", false),
            ("b", false),
            ("1", false),
        ] {
            assert_eq!(label_matches(&labels, spec), want, "{spec}");
        }
    }

    #[test]
    fn an_image_prune_takes_its_filters_only() {
        let f = |j: &str| Filters::parse(j).unwrap();
        assert_eq!(
            f(r#"{"label":["a=b"],"until":["1h"],"dangling":["false"]}"#)
                .image_prune()
                .unwrap(),
            ["label=a=b", "until=1h"]
        );
        assert!(f(r#"{"bogus":["1"]}"#).image_prune().is_err());
    }

    /// A prune's filters that would select all or nothing are refused.
    #[test]
    fn the_filters_of_a_prune_are_checked() {
        let args =
            |a: &[&str]| Filters::of_args(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        let e = args(&["label"]).unwrap_err();
        assert!(
            e.to_string()
                .contains("filter input must be in the form of filter=value: label is invalid"),
            "{e}"
        );
        assert!(args(&["label=", "until=1h"])
            .unwrap()
            .check_prune_until()
            .is_ok());
        let e = args(&["until=garbage"])
            .unwrap()
            .check_prune_until()
            .unwrap_err();
        assert!(
            e.to_string()
                .contains(r#"failed to parse value as time or duration: "garbage""#),
            "{e}"
        );
        let e = args(&["until=1h", "until=2h"])
            .unwrap()
            .check_prune_until()
            .unwrap_err();
        assert!(
            e.to_string()
                .contains("specify exactly one timestamp for until"),
            "{e}"
        );
    }
}
