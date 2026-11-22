// SPDX-License-Identifier: Apache-2.0
use super::*;

/// The name without the registry when it has one (`localhost/a:b` to
/// `a:b`, `docker.io/library/a` to `a`).
pub(super) fn familiar_name(name: &str) -> &str {
    if let Some(rest) = name.strip_prefix("docker.io/library/") {
        return rest;
    }
    match name.split_once('/') {
        Some((first, rest)) if velarx_base::reference::is_registry_domain(first) => rest,
        _ => name,
    }
}

/// fnmatch with `*` and `?`.
pub(super) fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// The reference filter: `pattern` (with or without tag) against a name.
pub(super) fn reference_match(name: &str, pattern: &str) -> bool {
    [name, familiar_name(name)].iter().any(|cand| {
        let slash = cand.rfind('/').map_or(0, |i| i + 1);
        let repo = cand[slash..].rfind(':').map(|c| &cand[..slash + c]);
        glob_match(pattern, cand) || repo.is_some_and(|r| glob_match(pattern, r))
    })
}

/// When the image `reference` was made (else stored), in seconds.
pub(super) async fn created_of(state: &AppState, reference: &str) -> ApiResult<i64> {
    let rec = resolve_image(state, reference).await?;
    Ok(View::load_required(state, rec).await?.created_ns() / 1_000_000_000)
}

/// When an image was made, else stored, in seconds (podman's `Created`).
pub(super) fn created_secs(r: &velarx_proto::workload::ImageRecord) -> i64 {
    let ns = match r.created_ns {
        0 => r.stored_ns,
        n => n,
    };
    ns / 1_000_000_000
}

/// The times of `before` and `since` (`after`) of a list, in seconds.
pub(super) struct Bounds {
    pub(super) before: Option<i64>,
    pub(super) since: Option<i64>,
}

/// `REPO[:TAG]@DIGEST` against the digests of an image (`REPO@DIGEST`):
/// podman looks the image up by it, so it is not a pattern, a tag in it is
/// dropped and the registry may be left out.
pub(super) fn digest_reference_match<'a>(
    repo_digests: impl Iterator<Item = &'a str>,
    want: &str,
) -> bool {
    let Some((name, digest)) = want.split_once('@') else {
        return false;
    };
    let slash = name.rfind('/').map_or(0, |i| i + 1);
    let name = match name[slash..].rfind(':') {
        Some(c) => &name[..slash + c],
        None => name,
    };
    let want = format!("{name}@{digest}");
    repo_digests
        .into_iter()
        .any(|d| d == want || familiar_name(d) == want)
}

/// The time of an `until` filter as libimage reads it (`timetype.GetTimestamp`):
/// a Go duration before now, a unix time, RFC 3339, or a date and time
/// without a zone or a date alone.
fn until_time(v: &str) -> Option<i64> {
    velarx_proto::time::parse_input_time(
        v,
        velarx_shape::time::now_ns(),
        velarx_proto::time::Toward::Past,
        false,
    )
}

/// A boolean filter value as Go's `strconv.ParseBool` reads it.
fn parse_filter_bool(v: &str) -> Option<bool> {
    match v {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Some(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Some(false),
        _ => None,
    }
}

/// Whether the image passes the filters, as libimage's: every value of a
/// key must pass (those of `reference` are ORed, the negated ones ANDed),
/// and every key; a key with a trailing `!` is the negated filter.
pub(super) fn filter_match(
    filters: &Filters,
    r: &velarx_proto::workload::ImageRecord,
    bounds: &Bounds,
) -> bool {
    let created = created_secs(r);
    let named = !(r.names.is_empty() && r.digest_names.is_empty());
    let dangling = !named && !r.has_children;
    let intermediate = !named && r.has_children;
    for (key, values) in &filters.0 {
        let (name, negate) = match key.strip_suffix('!') {
            Some(k) => (k, true),
            None => (key.as_str(), false),
        };
        let one = |want: &str| -> bool {
            let flag = || parse_filter_bool(want).unwrap_or(false);
            match name {
                "dangling" => flag() == dangling,
                "intermediate" => flag() == intermediate,
                "readonly" => flag() == r.read_only,
                "manifest" => flag() == r.manifest_list,
                "lazy" => flag() == r.lazy,
                // (no container of another tool is known: external is true
                // of an image no container uses)
                "containers" => match want {
                    "external" => r.containers == 0,
                    _ => (want == "true") == (r.containers > 0),
                },
                "digest" => std::iter::once(r.digest.as_str())
                    .chain(
                        r.digests
                            .iter()
                            .filter_map(|d| d.split_once('@').map(|x| x.1)),
                    )
                    .any(|d| d.starts_with(want)),
                "reference" => {
                    r.names.iter().any(|n| reference_match(n, want))
                        // (podman: the repository of a name with a digest)
                        || r.digest_names.iter().any(|n| {
                            n.split_once('@').is_some_and(|(repo, _)| reference_match(repo, want))
                        })
                        || digest_reference_match(r.digests.iter().map(String::as_str), want)
                }
                "before" => bounds.before.is_some_and(|b| created < b),
                // podman's after is since
                "since" | "after" => bounds.since.is_some_and(|b| created > b),
                "until" => {
                    until_time(want).is_some_and(|t| created.saturating_mul(1_000_000_000) < t)
                }
                "id" => r.id.starts_with(convert::strip_sha256(want)),
                "label" => {
                    let (k, v) = want
                        .split_once('=')
                        .map_or((want, None), |(k, v)| (k, Some(v)));
                    r.labels.get(k).is_some_and(|l| v.is_none_or(|v| l == v))
                }
                _ => true,
            }
        };
        // (`lazy=true` and `lazy=false`: the pulls in progress and the
        // images of the store)
        let ok = if matches!(name, "reference" | "lazy") && !negate {
            values.is_empty() || values.iter().any(|v| one(v))
        } else {
            values.iter().all(|v| one(v) != negate)
        };
        if !ok {
            return false;
        }
    }
    true
}

/// libimage's single reference filter taken as a query: a fully qualified
/// name with a tag (or digest) keeps only that name (the names of that
/// repository) of a matching image.  A short name, a pattern or a name
/// without tag keeps them all.
pub(super) fn narrow_names(names: &mut Vec<String>, pattern: &str) {
    let Some((repo, digest)) = fully_qualified(pattern) else {
        return;
    };
    names.retain(|n| {
        if digest {
            fully_qualified(n).is_some_and(|(r, _)| r == repo)
        } else {
            n == pattern
        }
    });
}

/// The repository of a fully qualified reference that has a tag or a
/// digest, and whether it has a digest.
pub(super) fn fully_qualified(r: &str) -> Option<(&str, bool)> {
    if r.contains(['*', '?', '[']) {
        return None;
    }
    let (repo, digest) = match r.split_once('@') {
        // (a tag before the digest is not the repository's)
        Some((repo, _)) => {
            let slash = repo.rfind('/').map_or(0, |i| i + 1);
            match repo[slash..].rfind(':') {
                Some(c) => (&repo[..slash + c], true),
                None => (repo, true),
            }
        }
        None => {
            let slash = r.rfind('/')?;
            let colon = r[slash..].rfind(':')? + slash;
            (&r[..colon], false)
        }
    };
    let (domain, path) = repo.split_once('/')?;
    let domain_ok = velarx_base::reference::is_registry_domain(domain);
    // docker.io/alpine is not canonical (docker.io/library/alpine is)
    let canonical = domain != "docker.io" || path.contains('/');
    (domain_ok && canonical && !path.is_empty()).then_some((repo, digest))
}

/// The filters of an image list libimage knows; another is refused with
/// its message.
pub(super) fn check_image_filters(filters: &Filters) -> ApiResult<()> {
    const KNOWN: [&str; 15] = [
        "after",
        "since",
        "before",
        "containers",
        "dangling",
        "digest",
        "id",
        "intermediate",
        "label",
        "lazy",
        "manifest",
        "readonly",
        "reference",
        "until",
        "filter",
    ];
    for (key, values) in &filters.0 {
        let name = key.trim_end_matches('!');
        if !KNOWN.contains(&name) {
            return Err(ApiError::bad_request(format!(
                "invalid image filter {key:?}: must be in the format \"filter=value or filter!=value\""
            )));
        }
        for v in values {
            let bad = match name {
                "dangling" | "intermediate" | "readonly" | "manifest" | "lazy" => {
                    // (libimage's words, with the key and the value as it
                    // says them)
                    parse_filter_bool(v).is_none().then(|| {
                        format!(
                            "non-boolean value {name:?} for {v} filter: strconv.ParseBool: parsing {v:?}: invalid syntax"
                        )
                    })
                }
                "containers" => (!matches!(v.as_str(), "true" | "false" | "external"))
                    .then(|| format!("unsupported value {v:?} for containers filter")),
                "digest" => (!v.starts_with("sha256:"))
                    .then(|| format!("invalid value {v:?} for digest filter")),
                "until" => until_time(v)
                    .is_none()
                    .then(|| format!("failed to parse value as time or duration: {v:?}")),
                _ => None,
            };
            if let Some(msg) = bad {
                return Err(ApiError::bad_request(msg));
            }
        }
        // (libimage: one value only, for these)
        if matches!(
            name,
            "dangling" | "intermediate" | "readonly" | "manifest" | "containers"
        ) && values.iter().any(|v| *v != values[0])
        {
            return Err(ApiError::bad_request(format!(
                "specifying {name:?} filter more than once with different values is not supported"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_filter_lazy_tells_the_pulls_in_progress() {
        let f = |key: &str, values: &[&str]| {
            Filters(vec![(
                key.to_string(),
                values.iter().map(|v| v.to_string()).collect(),
            )])
        };
        let bounds = Bounds {
            before: None,
            since: None,
        };
        let matches = |filters: Filters, lazy| {
            let image = velarx_proto::workload::ImageRecord {
                lazy,
                ..Default::default()
            };
            filter_match(&filters, &image, &bounds)
        };
        assert!(matches(f("lazy", &["true"]), true));
        assert!(!matches(f("lazy", &["true"]), false));
        assert!(matches(f("lazy", &["false"]), false));
        assert!(!matches(f("lazy!", &["true"]), true));
        // both values: either
        assert!(matches(f("lazy", &["true", "false"]), true));
        assert!(matches(f("lazy", &["true", "false"]), false));
        assert!(check_image_filters(&f("lazy", &["true"])).is_ok());
        assert!(check_image_filters(&f("lazy", &["maybe"])).is_err());
    }
}
