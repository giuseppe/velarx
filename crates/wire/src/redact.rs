// SPDX-License-Identifier: Apache-2.0
//! Credentials inside URLs, hidden from everything a person or a log sees:
//! the output of a build, its errors, and the history of an image (which a
//! push carries to the registry).

const HIDDEN: &str = "xxxxx";

/// The names of query parameters whose value is a credential (`%XX` of the
/// name decoded).
fn secret_param(name: &str) -> bool {
    let n = decoded(name).to_ascii_lowercase();
    matches!(n.as_str(), "sig" | "auth" | "pwd" | "jwt" | "session")
        || n.ends_with("key")
        || [
            "token",
            "secret",
            "password",
            "passwd",
            "signature",
            "credential",
            "authorization",
        ]
        .iter()
        .any(|w| n.contains(w))
}

/// `%XX` decoded, what is not valid kept as it is.
fn decoded(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        match (
            b[i],
            b.get(i + 1).copied().and_then(hex),
            b.get(i + 2).copied().and_then(hex),
        ) {
            (b'%', Some(h), Some(l)) => {
                out.push((h * 16 + l) as u8);
                i += 3;
            }
            (c, _, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One URL, from its scheme: the password of its userinfo (the whole userinfo
/// of an http(s) URL without a password, where it is a token) and the value
/// of the credential parameters of its query are replaced by `xxxxx`.
fn url(u: &str, scheme: &str) -> String {
    let (head, rest) = u.split_at(scheme.len() + 3);
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(auth_end);
    let mut out = String::with_capacity(u.len());
    out.push_str(head);
    match authority.rfind('@') {
        Some(at) => {
            let (info, host) = authority.split_at(at);
            match info.split_once(':') {
                Some((user, _)) => {
                    out.push_str(user);
                    out.push(':');
                    out.push_str(HIDDEN);
                }
                None if scheme.to_ascii_lowercase().starts_with("http") => out.push_str(HIDDEN),
                None => out.push_str(info),
            }
            out.push_str(host);
        }
        None => out.push_str(authority),
    }
    let (path, fragment) = match tail.find('#') {
        Some(i) => tail.split_at(i),
        None => (tail, ""),
    };
    match path.split_once('?') {
        Some((p, query)) => {
            out.push_str(p);
            out.push('?');
            for (i, kv) in query.split('&').enumerate() {
                if i > 0 {
                    out.push('&');
                }
                match kv.split_once('=') {
                    Some((k, _)) if secret_param(k) => {
                        out.push_str(k);
                        out.push('=');
                        out.push_str(HIDDEN);
                    }
                    _ => out.push_str(kv),
                }
            }
        }
        None => out.push_str(path),
    }
    out.push_str(fragment);
    out
}

/// `text` with the credentials of every URL in it hidden.
pub fn urls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("://") {
        let start = rest[..i]
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
            .map_or(0, |p| p + 1);
        let scheme = &rest[start..i];
        let after = i + 3;
        let end = rest[after..]
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '`' | '\\'))
            .map_or(rest.len(), |p| after + p);
        out.push_str(&rest[..start]);
        if scheme.is_empty() {
            out.push_str(&rest[start..end]);
        } else {
            out.push_str(&url(&rest[start..end], scheme));
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::urls;

    #[test]
    fn the_password_of_a_url_is_hidden() {
        assert_eq!(
            urls("ADD https://user:SECRET@host:8080/f /f"),
            "ADD https://user:xxxxx@host:8080/f /f"
        );
        assert_eq!(
            urls(r#"ADD ["https://u:p%40ss@h/f","/f"]"#),
            r#"ADD ["https://u:xxxxx@h/f","/f"]"#
        );
        assert_eq!(
            urls("https://ghp_TOKEN@github.com/o/r.git"),
            "https://xxxxx@github.com/o/r.git"
        );
        assert_eq!(urls("ssh://git@host/r.git"), "ssh://git@host/r.git");
        assert_eq!(urls("git@host:o/r.git"), "git@host:o/r.git");
    }

    #[test]
    fn credential_parameters_of_the_query_are_hidden() {
        assert_eq!(
            urls("cloning https://h/p?a=1&access_token=T0K&X-Amz-Signature=S#frag: failed"),
            "cloning https://h/p?a=1&access_token=xxxxx&X-Amz-Signature=xxxxx#frag: failed"
        );
        assert_eq!(
            urls("https://h/p?name=x&token=abc"),
            "https://h/p?name=x&token=xxxxx"
        );
    }

    #[test]
    fn edge_cases_of_userinfo_and_query() {
        // '@' and ':' in the password, an IPv6 host, an upper case scheme
        assert_eq!(
            urls("https://u:p@ss:w0rd@[::1]:8080/f"),
            "https://u:xxxxx@[::1]:8080/f"
        );
        assert_eq!(urls("HTTPS://tok@h/r.git"), "HTTPS://xxxxx@h/r.git");
        assert_eq!(urls("ftp://anonymous@h/f"), "ftp://anonymous@h/f");
        // names of every case, percent-encoded, *_key
        assert_eq!(
            urls("https://h/f?Sig=1&%74oken=2&access_key=3&X-Goog-Signature=4&sort=5"),
            "https://h/f?Sig=xxxxx&%74oken=xxxxx&access_key=xxxxx&X-Goog-Signature=xxxxx&sort=5"
        );
    }

    #[test]
    fn text_without_credentials_is_unchanged() {
        for s in [
            "RUN echo a://b",
            "ADD https://h/f?x=1 /f",
            "no url",
            "://",
            "RUN echo ://x",
            "ADD --checksum=sha256:0123 https://h/f /f",
            "git@host:o/r.git#main:sub",
        ] {
            assert_eq!(urls(s), s);
        }
        assert_eq!(urls("a: https://@h/x"), "a: https://xxxxx@h/x");
    }
}
