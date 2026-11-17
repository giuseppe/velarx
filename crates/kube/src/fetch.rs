// SPDX-License-Identifier: Apache-2.0
//! The YAML of an `http://` or `https://` address, as podman's `kube play`
//! and `kube down` read it.

use crate::yaml::MAX_SIZE;

/// Whether `arg` names a web address rather than a file.
pub fn is_url(arg: &str) -> bool {
    ["http://", "https://"].iter().any(|p| arg.starts_with(p))
}

/// The body of `url` (redirects followed), at most [`MAX_SIZE`] bytes.
pub async fn get(url: &str) -> Result<Vec<u8>, String> {
    let mut response = reqwest::get(url)
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| format!("cannot read {url}: {e}"))?;
    let mut data = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("cannot read {url}: {e}"))?
    {
        data.extend_from_slice(&chunk);
        if data.len() > MAX_SIZE {
            return Err(format!("the YAML {url} is larger than 4 MiB"));
        }
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_web_addresses_are_urls() {
        assert!(is_url("https://example.com/a.yaml"));
        assert!(is_url("http://example.com/a.yaml"));
        assert!(!is_url("./http://a.yaml"));
        assert!(!is_url("ftp://example.com/a.yaml"));
        assert!(!is_url("-"));
    }
}
