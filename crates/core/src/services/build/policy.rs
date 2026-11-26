// SPDX-License-Identifier: Apache-2.0
//! `--source-policy-file`: a BuildKit source policy for every image a build
//! takes: the bases of the stages (also when only the platforms of their
//! indexes are read, for `--all-platforms`) and the images of `COPY --from` and
//! `RUN --mount from`, named directly or through `--build-context` (a stage
//! is not an image).  The rules are tried in order and the first that matches the
//! image (`docker-image://REGISTRY/REPOSITORY:TAG`, the name written in
//! full, `latest` for none) allows it, denies it or converts it to another
//! reference; an image no rule matches is allowed.  Only what is understood
//! is accepted: a rule with a field not named here, or a `REGEX` selector,
//! is an error, never a rule that matches less than its author thinks.

use serde::Deserialize;

const IMAGE_SCHEME: &str = "docker-image://";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePolicy {
    rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    action: Action,
    selector: Selector,
    updates: Option<Updates>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
enum Action {
    Allow,
    Deny,
    Convert,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Selector {
    identifier: String,
    #[serde(default)]
    match_type: MatchType,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum MatchType {
    Exact,
    #[default]
    Wildcard,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Updates {
    identifier: String,
}

/// What the policy says of an image a build takes.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// Use the image as it is.
    Keep,
    /// Use this reference instead.
    Convert(String),
    /// The build fails: the rule that denies it.
    Deny(String),
}

impl SourcePolicy {
    /// The policy of the JSON document `text`.
    pub fn parse(text: &str) -> Result<Self, String> {
        let policy: Self = serde_json::from_str(text).map_err(|e| format!("source policy: {e}"))?;
        for (n, rule) in policy.rules.iter().enumerate() {
            if rule.selector.identifier.is_empty() {
                return Err(format!(
                    "source policy: rule {n}: selector.identifier is empty"
                ));
            }
            let target = rule.updates.as_ref().map(|u| u.identifier.as_str());
            if rule.action == Action::Convert && target.is_none_or(str::is_empty) {
                return Err(format!(
                    "source policy: rule {n}: CONVERT needs updates.identifier"
                ));
            }
        }
        Ok(policy)
    }

    /// What the policy says of the image `name`, as written in the
    /// Containerfile.
    pub fn decide(&self, name: &str) -> Decision {
        let source = match name.starts_with(IMAGE_SCHEME) {
            true => name.to_string(),
            false => format!(
                "{IMAGE_SCHEME}{}",
                super::base_name(name, "").unwrap_or_default()
            ),
        };
        for (n, rule) in self.rules.iter().enumerate() {
            let selector = &rule.selector;
            let matches = match selector.match_type {
                MatchType::Exact => selector.identifier == source,
                MatchType::Wildcard => wildcard(selector.identifier.as_bytes(), source.as_bytes()),
            };
            if !matches {
                continue;
            }
            return match (&rule.action, &rule.updates) {
                (Action::Allow, _) => Decision::Keep,
                (Action::Deny, _) => Decision::Deny(format!(
                    "matched rule {n} (selector: {:?})",
                    selector.identifier
                )),
                (Action::Convert, Some(u)) => Decision::Convert(
                    u.identifier
                        .strip_prefix(IMAGE_SCHEME)
                        .unwrap_or(&u.identifier)
                        .to_string(),
                ),
                (Action::Convert, None) => unreachable!("parse needs the target of a CONVERT"),
            };
        }
        Decision::Keep
    }
}

/// Whether `text` is `pattern`, in which `*` is any bytes and `?` one byte.
fn wildcard(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    // where the last `*` was, and the text it has taken up to
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some(b'*') => {
                star = Some((p, t));
                p += 1;
            }
            Some(&c) if c == b'?' || c == text[t] => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some((sp, st)) => {
                    star = Some((sp, st + 1));
                    p = sp + 1;
                    t = st + 1;
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|c| *c == b'*')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(rules: &str) -> SourcePolicy {
        SourcePolicy::parse(&format!(r#"{{"rules": {rules}}}"#)).unwrap()
    }

    #[test]
    fn wildcards() {
        assert!(wildcard(b"a*c", b"abbc"));
        assert!(wildcard(b"a*c", b"ac"));
        assert!(wildcard(b"a?c", b"abc"));
        assert!(!wildcard(b"a?c", b"ac"));
        assert!(wildcard(b"*", b""));
        assert!(wildcard(b"*a*b", b"xaxab"));
        assert!(!wildcard(b"a*b", b"abc"));
    }

    #[test]
    fn the_first_rule_that_matches_decides() {
        let p = policy(
            r#"[
            {"action": "ALLOW", "selector": {"identifier": "docker-image://docker.io/library/ubuntu:22.04", "matchType": "EXACT"}},
            {"action": "DENY", "selector": {"identifier": "docker-image://docker.io/library/ubuntu:*"}},
            {"action": "CONVERT", "selector": {"identifier": "docker-image://docker.io/library/alpine:latest"},
             "updates": {"identifier": "docker-image://docker.io/library/alpine@sha256:abcd"}}
        ]"#,
        );
        assert_eq!(p.decide("ubuntu:22.04"), Decision::Keep);
        assert!(matches!(p.decide("ubuntu:24.04"), Decision::Deny(_)));
        assert_eq!(
            p.decide("alpine"),
            Decision::Convert("docker.io/library/alpine@sha256:abcd".into())
        );
        assert_eq!(
            p.decide("docker-image://docker.io/library/alpine:latest"),
            p.decide("alpine:latest")
        );
        assert_eq!(p.decide("fedora"), Decision::Keep);
    }

    #[test]
    fn what_is_not_understood_is_refused() {
        for bad in [
            r#"{"rules": [{"action": "NOPE", "selector": {"identifier": "x"}}]}"#,
            r#"{"rules": [{"action": "DENY", "selector": {"identifier": ""}}]}"#,
            r#"{"rules": [{"action": "DENY", "selector": {"identifier": "x", "matchType": "REGEX"}}]}"#,
            r#"{"rules": [{"action": "CONVERT", "selector": {"identifier": "x"}}]}"#,
            r#"{"rules": [{"action": "DENY", "selector": {"identifier": "x", "constraint": 1}}]}"#,
            r#"{"rule": []}"#,
            "[]",
        ] {
            assert!(SourcePolicy::parse(bad).is_err(), "{bad}");
        }
        assert!(SourcePolicy::parse(r#"{"rules": []}"#).is_ok());
    }
}
