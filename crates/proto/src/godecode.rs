// SPDX-License-Identifier: Apache-2.0
//! Request bodies decoded the way podman's handlers decode them, with Go's
//! `json.NewDecoder(r.Body).Decode(&v)`: the names of the members of an
//! object match the fields of a struct without regard to case when no name
//! matches exactly, and what follows the first JSON value is ignored.

use serde::de::{
    self, DeserializeOwned, DeserializeSeed, Deserializer, IntoDeserializer, MapAccess, SeqAccess,
    Visitor,
};
use serde_json::{Map, Value};

/// A field the Go clients encode as `null` when it is empty.
pub fn nullable<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: serde::Deserialize<'de> + Default,
{
    Ok(<Option<T> as serde::Deserialize>::deserialize(d)?.unwrap_or_default())
}

/// Go's strconv.ParseBool.
pub fn parse_bool(v: &str) -> Option<bool> {
    match v {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Some(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Some(false),
        _ => None,
    }
}

/// The first JSON value of `b` as a `T`.
pub fn from_slice<T: DeserializeOwned>(b: &[u8]) -> Result<T, serde_json::Error> {
    T::deserialize(GoValue(first_value(b)?))
}

/// The first JSON value of `b`; an empty body is an error, as for Go.
pub fn first_value(b: &[u8]) -> Result<Value, serde_json::Error> {
    match serde_json::Deserializer::from_slice(b)
        .into_iter::<Value>()
        .next()
    {
        Some(v) => v,
        None => Err(de::Error::custom("EOF")),
    }
}

/// The message of Go's JSON decoder for the error `e` of decoding `input`,
/// for the clients that match it: the two that podman's handlers give for
/// bad filters, else serde's.
pub fn go_error(input: &[u8], e: &serde_json::Error) -> String {
    if e.is_eof() {
        return "unexpected end of JSON input".into();
    }
    // serde counts lines and columns from 1, in bytes
    let line_start = input
        .split(|&b| b == b'\n')
        .take(e.line().saturating_sub(1))
        .map(|l| l.len() + 1)
        .sum::<usize>();
    let at = input
        .get(line_start + e.column().saturating_sub(1))
        .copied();
    match at {
        Some(c) if e.is_syntax() && e.to_string().starts_with("expected value") => {
            format!(
                "invalid character {:?} looking for beginning of value",
                c as char
            )
        }
        _ => e.to_string(),
    }
}

/// A `Value` that gives the members of its objects to the fields of a
/// struct like Go does, and so do its elements.
pub struct GoValue(pub Value);

/// Rename the members of `map` to the field of `fields` they match without
/// case, unless they match one exactly.
fn match_fields(map: Map<String, Value>, fields: &[&str]) -> Map<String, Value> {
    if map.keys().all(|k| fields.contains(&k.as_str())) {
        return map;
    }
    let mut out = Map::new();
    for (k, v) in map {
        let name = if fields.contains(&k.as_str()) {
            k
        } else {
            match fields.iter().find(|f| f.eq_ignore_ascii_case(&k)) {
                Some(f) => f.to_string(),
                None => k,
            }
        };
        // Go keeps the last of the members that match the same field.
        out.insert(name, v);
    }
    out
}

struct GoMap {
    iter: serde_json::map::IntoIter,
    value: Option<Value>,
}

impl<'de> MapAccess<'de> for GoMap {
    type Error = serde_json::Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Self::Error> {
        match self.iter.next() {
            Some((k, v)) => {
                self.value = Some(v);
                seed.deserialize(k.into_deserializer()).map(Some)
            }
            None => Ok(None),
        }
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> Result<V::Value, Self::Error> {
        match self.value.take() {
            Some(v) => seed.deserialize(GoValue(v)),
            None => Err(de::Error::custom("a value without a key")),
        }
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.iter.len())
    }
}

struct GoSeq(std::vec::IntoIter<Value>);

impl<'de> SeqAccess<'de> for GoSeq {
    type Error = serde_json::Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Self::Error> {
        match self.0.next() {
            Some(v) => seed.deserialize(GoValue(v)).map(Some),
            None => Ok(None),
        }
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.0.len())
    }
}

fn visit_map<'de, V: Visitor<'de>>(
    map: Map<String, Value>,
    visitor: V,
) -> Result<V::Value, serde_json::Error> {
    visitor.visit_map(GoMap {
        iter: map.into_iter(),
        value: None,
    })
}

impl<'de> Deserializer<'de> for GoValue {
    type Error = serde_json::Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            Value::Object(map) => visit_map(map, visitor),
            Value::Array(a) => visitor.visit_seq(GoSeq(a.into_iter())),
            v => v.deserialize_any(visitor),
        }
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            Value::Null => visitor.visit_none(),
            v => visitor.visit_some(GoValue(v)),
        }
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        match self.0 {
            Value::Object(map) => visit_map(match_fields(map, fields), visitor),
            v => GoValue(v).deserialize_any(visitor),
        }
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.0.deserialize_enum(name, variants, visitor)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_unit()
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf unit unit_struct seq tuple tuple_struct map identifier
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::collections::HashMap;

    /// Go's ParseBool: three spellings of each case, not any mix of case
    /// (the build route lower-cased the value before).
    #[test]
    fn a_bool_is_read_as_go_reads_it() {
        for t in ["1", "t", "T", "true", "TRUE", "True"] {
            assert_eq!(parse_bool(t), Some(true), "{t}");
        }
        for f in ["0", "f", "F", "false", "FALSE", "False"] {
            assert_eq!(parse_bool(f), Some(false), "{f}");
        }
        for bad in ["tRUE", "yes", "", " true", "2"] {
            assert_eq!(parse_bool(bad), None, "{bad}");
        }
    }

    #[derive(Deserialize, Debug, PartialEq, Default)]
    struct Inner {
        #[serde(rename = "Subnet")]
        subnet: String,
    }

    #[derive(Deserialize, Debug, PartialEq, Default)]
    #[serde(default)]
    struct Outer {
        name: String,
        #[serde(rename = "Labels")]
        labels: HashMap<String, String>,
        inner: Option<Inner>,
        list: Vec<Inner>,
        count: u32,
    }

    #[test]
    fn members_match_fields_without_case() {
        let o: Outer = from_slice(
            br#"{"Name":"a","labels":{"Keep":"Case"},"Inner":{"subnet":"x"},"LIST":[{"SUBNET":"y"}],"Count":3}"#,
        )
        .unwrap();
        assert_eq!(o.name, "a");
        assert_eq!(o.labels.get("Keep").map(String::as_str), Some("Case"));
        assert_eq!(o.inner, Some(Inner { subnet: "x".into() }));
        assert_eq!(o.list, vec![Inner { subnet: "y".into() }]);
        assert_eq!(o.count, 3);
    }

    #[test]
    fn an_exact_name_wins() {
        let o: Outer = from_slice(br#"{"NAME":"no","name":"yes"}"#).unwrap();
        assert_eq!(o.name, "yes");
    }

    #[test]
    fn what_follows_the_first_value_is_ignored() {
        let o: Outer = from_slice(br#"{"name":"a"}} trailing"#).unwrap();
        assert_eq!(o.name, "a");
        assert!(from_slice::<Outer>(b"  ").is_err());
        assert!(from_slice::<Outer>(br#"{"name":"#).is_err());
    }

    #[test]
    fn errors_read_like_go() {
        let err = |s: &str| {
            let e = serde_json::from_str::<Value>(s).unwrap_err();
            go_error(s.as_bytes(), &e)
        };
        assert_eq!(
            err("garb1age}"),
            "invalid character 'g' looking for beginning of value"
        );
        assert_eq!(err("{\"label\":[\"testl"), "unexpected end of JSON input");
        assert_eq!(err(""), "unexpected end of JSON input");
        assert_eq!(
            err("{\"a\":\n x}"),
            "invalid character 'x' looking for beginning of value"
        );
    }

    #[test]
    fn types_are_still_checked() {
        assert!(from_slice::<Outer>(br#"{"count":"x"}"#).is_err());
        let v: Value = from_slice(br#"{"A":[1,{"b":null}]}"#).unwrap();
        assert_eq!(v, serde_json::json!({"A":[1,{"b":null}]}));
    }
}
