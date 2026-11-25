// SPDX-License-Identifier: Apache-2.0
//! The credentials a request of the registry fetcher carries.

use velarx_registry::auth::RegistryAccess;
use velarx_registry::target::Resolver;
use velarx_types::{ImageError, ImageReference, ImageResult};

/// What a command brings to the fetcher for the requests about `name`
/// (`registry/repository`, with a tag or digest if it has).  With TLS
/// verification off for a registry that registries.conf does not mark
/// insecure, the fetcher makes the requests on the asker's word and sends
/// no credentials but the ones of the call, so the stored ones for the
/// registry go with it; this process opens no connection to the registry
/// either way.  With `mirrors` the endpoints are the mirrors and then the
/// registry; a push asks without them, as it never contacts a mirror.
pub fn access_for(
    client: &Resolver,
    name: &str,
    tls_verify: bool,
    access: &RegistryAccess,
    mirrors: bool,
) -> ImageResult<RegistryAccess> {
    if tls_verify || access.creds.is_some() || client.registries().is_insecure(name) {
        return Ok(access.clone());
    }
    with_stored(
        &velarx_registry::AuthConfig::load()?,
        client,
        name,
        access,
        mirrors,
    )
}

/// `access` with the credentials `stored` has for each endpoint of `name`
/// (the mirrors if `mirrors`, then the registry, after the rules of
/// registries.conf), when `access` has none for it.  Each is keyed by the
/// repository the endpoint is asked for.  A credential stored under a
/// namespace key used to be exported under the key of the whole host, so
/// within the request it was the credential of every repository of the
/// host.
pub fn with_stored(
    stored: &velarx_registry::AuthConfig,
    client: &Resolver,
    name: &str,
    access: &RegistryAccess,
    mirrors: bool,
) -> ImageResult<RegistryAccess> {
    let mut access = access.clone();
    let reference = ImageReference::parse(name)?;
    let endpoints = client.config().endpoints(
        &reference.registry,
        &reference.repository,
        reference.digest.as_ref(),
        mirrors,
    )?;
    let stored = stored.with_access(&access);
    for e in endpoints {
        if let Some(creds) = stored
            .lookup_for(e.command_line, &e.host, &e.repository)
            .map_err(ImageError::Invalid)?
        {
            access
                .auths
                .entry(format!("{}/{}", e.host, e.repository))
                .or_insert(creds);
        }
    }
    Ok(access)
}

/// What the pusher of an external scheme is given for `destination`
/// (`SCHEME://...`): `access` (`--creds`, the certificates) and the
/// credentials under exactly its key, `SCHEME://AUTHORITY`: the one the
/// client sent, or else the one of the auth files of this process.  Never
/// the credentials of a registry the text may be taken for, whether TLS is
/// verified or not.
pub fn access_for_transport(
    destination: &str,
    access: &RegistryAccess,
) -> ImageResult<RegistryAccess> {
    let key =
        velarx_types::transport::ImageLocation::credential_key(destination).ok_or_else(|| {
            ImageError::Invalid(format!(
                "`{destination}` is not a destination of a transport"
            ))
        })?;
    let key = velarx_registry::auth::normalize_auth_key(&key);
    let mut out = RegistryAccess {
        creds: access.creds.clone(),
        certs: access.certs.clone(),
        ..Default::default()
    };
    if let Some(c) = access.auths.get(&key) {
        out.auths.insert(key, c.clone());
    } else if access.creds.is_none() {
        out.auths = velarx_registry::AuthConfig::load()?
            .export_exact(&key)
            .map_err(ImageError::Invalid)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_registry::target::TransportConfig;
    use velarx_registry::{AuthConfig, Credentials};

    fn resolver(registries: &str) -> Resolver {
        let config = TransportConfig {
            registries: velarx_registry::config::RegistriesConfig::parse(registries).unwrap(),
            certs_dirs: Vec::new(),
            tls_verify: false,
        };
        Resolver::with_config(config, AuthConfig::default())
    }

    fn user(access: &RegistryAccess, key: &str) -> Option<String> {
        access.auths.get(key).map(|c| c.username.clone())
    }

    #[test]
    fn a_push_exports_no_mirror_credential_and_a_pull_does() {
        let client = resolver(
            "[[registry]]\nprefix = \"r.test\"\nlocation = \"r.test\"\n\
             [[registry.mirror]]\nlocation = \"m.test\"\n",
        );
        let stored = AuthConfig::from_credentials([
            ("r.test", Credentials::basic("reg", "p")),
            ("m.test", Credentials::basic("mir", "p")),
        ]);
        let none = RegistryAccess::default();

        let pull = with_stored(&stored, &client, "r.test/a/b", &none, true).unwrap();
        assert_eq!(user(&pull, "m.test/a/b").as_deref(), Some("mir"));
        assert_eq!(user(&pull, "r.test/a/b").as_deref(), Some("reg"));

        let push = with_stored(&stored, &client, "r.test/a/b", &none, false).unwrap();
        assert_eq!(user(&push, "m.test/a/b"), None);
        assert_eq!(user(&push, "r.test/a/b").as_deref(), Some("reg"));
    }

    #[test]
    fn the_names_of_the_hub_find_its_credential() {
        let client = resolver("");
        let none = RegistryAccess::default();
        // a key in Docker's URL form is the host `docker.io` as well
        for key in ["docker.io", "https://index.docker.io/v1/"] {
            let stored = AuthConfig::from_credentials([(key, Credentials::basic("hub", "p"))]);
            for host in ["docker.io", "index.docker.io", "registry-1.docker.io"] {
                let name = format!("{host}/library/x");
                let got = with_stored(&stored, &client, &name, &none, true).unwrap();
                assert_eq!(got.auths.len(), 1, "{key} for {name}");
                assert_eq!(got.auths.values().next().unwrap().username, "hub");
            }
        }
    }
}
