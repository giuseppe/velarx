// SPDX-License-Identifier: Apache-2.0
//! Search of registries: `registry/term` searches that
//! registry, a bare term the unqualified-search registries.  A registry is
//! asked its `/v1/search` (docker.io's is on index.docker.io), and if it has
//! none, its `/v2/_catalog` for the repositories whose name has the term.
//! What registries answer is only shown, never used.

use super::*;

/// The results of a registry when the client does not limit them.
const DEFAULT_LIMIT: usize = 25;

/// `stars`, `is-official`, `is-automated` of the filters.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SearchFilter {
    pub stars: u64,
    pub official: Option<bool>,
    pub automated: Option<bool>,
}

impl SearchFilter {
    /// `key=value` filters, as podman parses them: a bare boolean key is
    /// true, any value but `false` too.
    pub fn parse<'a>(filters: impl IntoIterator<Item = &'a str>) -> Result<Self, String> {
        let mut out = Self::default();
        for f in filters {
            let (key, value) = match f.split_once('=') {
                Some((k, v)) => (k, Some(v)),
                None => (f, None),
            };
            match key {
                "stars" => {
                    let v = value
                        .ok_or_else(|| format!("invalid filter {f:?}, should be stars=<value>"))?;
                    out.stars = v
                        .parse()
                        .map_err(|e| format!("incorrect value type for stars filter: {e}"))?;
                }
                "is-official" => out.official = Some(value != Some("false")),
                "is-automated" => out.automated = Some(value != Some("false")),
                _ => return Err(format!("invalid filter type {f:?}")),
            }
        }
        Ok(out)
    }

    fn matches(&self, r: &SearchResult) -> bool {
        r.stars >= self.stars
            && self.official.is_none_or(|o| o == r.official)
            && self.automated.is_none_or(|a| a == r.automated)
    }
}

#[derive(Debug, Clone, Default)]
pub struct SearchOptions {
    /// Results of each registry (25 if 0).
    pub limit: usize,
    /// The tags of the repository `term` names instead.
    pub list_tags: bool,
    /// None: what registries.conf says.
    pub tls_verify: Option<bool>,
    pub filter: SearchFilter,
    pub access: velarx_registry::auth::RegistryAccess,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SearchResult {
    /// The registry searched.
    pub index: String,
    /// The repository, with its registry.
    pub name: String,
    pub description: String,
    pub stars: u64,
    pub official: bool,
    pub automated: bool,
    /// With `list_tags`.
    pub tag: String,
}

/// Without the control characters a registry could send to a terminal.
fn shown(s: &str) -> String {
    s.chars()
        .map(|c| if c == '\n' { ' ' } else { c })
        .filter(|c| !c.is_control())
        .collect()
}

fn valid_registry(r: &str) -> bool {
    !r.is_empty()
        && r.len() <= 255
        && r.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
}

impl ImageService {
    /// The tags of the repository of `reference` in its registry (podman
    /// pull --all-tags).
    pub async fn repository_tags(
        &self,
        reference: &str,
        options: &PullOptions,
    ) -> ImageResult<Vec<String>> {
        let image_ref = ImageReference::parse(reference)?;
        self.check_policy(&image_ref)?;
        let client = self
            .resolver
            .with_access(&options.access)
            .with_tls_verify(options.tls_verify);
        self.tags_of(&client, &image_ref, options.tls_verify, &options.access)
            .await
    }

    /// The tags of the repository of `image_ref`: through the registry
    /// fetcher when there is one, else in a confined pull worker when the
    /// pulls are confined.
    async fn tags_of(
        &self,
        client: &Resolver,
        image_ref: &ImageReference,
        tls_verify: bool,
        access: &velarx_registry::auth::RegistryAccess,
    ) -> ImageResult<Vec<String>> {
        let repository = format!("{}/{}", image_ref.registry, image_ref.repository);
        self.remote_of(client, &repository, tls_verify, access)?
            .tags()
            .await
    }

    /// Whether the registry `host` takes the credentials of `access`
    /// (`POST /auth`): why not otherwise (`Unauthorized`: it refused them).  The registry
    /// fetcher asks it when there is one, with the credentials in the
    /// sealed memory file of the call (for a registry on the loopback, whose
    /// certificate podman does not check, with TLS verification off); else
    /// this process does.
    pub async fn login(
        &self,
        host: &str,
        access: &velarx_registry::auth::RegistryAccess,
    ) -> ImageResult<()> {
        if access.creds.is_none() {
            return Err(ImageError::Registry(
                "there are no credentials to check".into(),
            ));
        }
        let tls_verify = !velarx_base::host::is_loopback_host(host);
        self.remote_of(
            &self.resolver,
            &format!("{host}/library/login"),
            tls_verify,
            access,
        )?
        .login()
        .await
    }

    /// The registries a short name is searched in (registries.conf's
    /// `unqualified-search-registries`).
    pub fn search_registries(&self) -> Vec<String> {
        self.resolver.registries().search_registries.clone()
    }

    /// Search `term` (podman search).  The results of the registries that
    /// answered; an error if none did.
    pub async fn search(&self, term: &str, opts: &SearchOptions) -> ImageResult<Vec<SearchResult>> {
        let registries: Vec<String> = match term.split_once('/') {
            Some((r, _)) => vec![r.to_string()],
            None => self.resolver.registries().search_registries.clone(),
        };
        let term = term.split_once('/').map_or(term, |(_, t)| t);
        let mut results = Vec::new();
        let mut errors = Vec::new();
        for registry in &registries {
            match self.search_registry(registry, term, opts).await {
                Ok(r) => results.extend(r),
                Err(e) => errors.push(format!("{registry}: {e}")),
            }
        }
        if results.is_empty() && !errors.is_empty() {
            return Err(ImageError::Registry(format!(
                "searching: {}",
                errors.join("; ")
            )));
        }
        Ok(results)
    }

    async fn search_registry(
        &self,
        registry: &str,
        term: &str,
        opts: &SearchOptions,
    ) -> ImageResult<Vec<SearchResult>> {
        if !valid_registry(registry) {
            return Err(ImageError::Registry(format!(
                "invalid registry `{}`",
                printable(registry)
            )));
        }
        let mut client = self.resolver.with_access(&opts.access);
        if let Some(v) = opts.tls_verify {
            client = client.with_tls_verify(v);
        }
        let limit = if opts.limit == 0 {
            DEFAULT_LIMIT
        } else {
            opts.limit
        };
        if opts.list_tags {
            let image_ref = ImageReference::parse(&format!("{registry}/{term}"))?;
            let last = term.rsplit('/').next().unwrap_or(term);
            if last.contains(':') || term.contains('@') {
                return Err(ImageError::Registry(format!(
                    "{}: listing the tags of a repository takes no tag",
                    printable(term)
                )));
            }
            self.check_policy(&image_ref)?;
            let name = format!("{}/{}", image_ref.registry, image_ref.repository);
            let tls_verify = opts.tls_verify.unwrap_or(true);
            return Ok(self
                .tags_of(&client, &image_ref, tls_verify, &opts.access)
                .await?
                .into_iter()
                .take(limit)
                .map(|tag| SearchResult {
                    index: registry.to_string(),
                    name: name.clone(),
                    tag: shown(&tag),
                    ..Default::default()
                })
                .collect());
        }
        // The client of the registry's host, for its certificates; the
        // requests in a confined pull worker when the pulls are confined.
        let image_ref = ImageReference::parse(&format!("{registry}/search"))?;
        let docker = image_ref.registry == "docker.io";
        let tls_verify = opts.tls_verify.unwrap_or(true);
        let found: Vec<SearchResult> = self
            .remote_of(
                &client,
                &format!("{registry}/search"),
                tls_verify,
                &opts.access,
            )?
            .search(term, limit)
            .await?
            .into_iter()
            .map(|hit| SearchResult {
                index: registry.to_string(),
                name: shown(&hit.name),
                description: shown(&hit.description),
                stars: hit.stars,
                official: hit.official,
                automated: hit.automated,
                tag: String::new(),
            })
            .collect();
        Ok(found
            .into_iter()
            .take(limit)
            .filter(|r| opts.filter.matches(r))
            .map(|mut r| {
                r.name = if docker && !r.name.contains('/') {
                    format!("docker.io/library/{}", r.name)
                } else {
                    format!("{registry}/{}", r.name)
                };
                r
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filters_as_podman_parses_them() {
        let f = SearchFilter::parse(["stars=3", "is-official", "is-automated=false"]).unwrap();
        assert_eq!(
            f,
            SearchFilter {
                stars: 3,
                official: Some(true),
                automated: Some(false)
            }
        );
        assert!(SearchFilter::parse(["stars"]).is_err());
        assert!(SearchFilter::parse(["stars=x"]).is_err());
        assert!(SearchFilter::parse(["label=x"]).is_err());
        let r = SearchResult {
            stars: 5,
            official: true,
            ..Default::default()
        };
        assert!(f.matches(&r));
        assert!(!SearchFilter::parse(["stars=6"]).unwrap().matches(&r));
        assert!(!SearchFilter::parse(["is-official=false"])
            .unwrap()
            .matches(&r));
    }

    #[test]
    fn test_registry_answers_are_shown_without_controls() {
        assert_eq!(shown("a\nb\x1b[31mc"), "a b[31mc");
        assert!(valid_registry("localhost:5000"));
        assert!(!valid_registry("a/b"));
        assert!(!valid_registry(""));
    }
}
