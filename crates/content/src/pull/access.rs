// SPDX-License-Identifier: Apache-2.0
//! The credentials a request of the registry fetcher carries.

use velarx_registry::auth::RegistryAccess;
use velarx_registry::target::Resolver;
use velarx_types::{ImageError, ImageResult};

/// What a command brings to the fetcher for the requests about
/// `name` (`registry/repository`).  With TLS verification off for a registry
/// that registries.conf does not mark insecure, the fetcher makes the
/// requests on the asker's word and sends no credentials but the ones of the
/// call, so the stored ones for the registry go with it; this process opens
/// no connection to the registry either way.
pub fn access_for(
    client: &Resolver,
    name: &str,
    tls_verify: bool,
    access: &RegistryAccess,
) -> ImageResult<RegistryAccess> {
    if tls_verify || access.creds.is_some() || client.registries().is_insecure(name) {
        return Ok(access.clone());
    }
    with_stored(&velarx_registry::AuthConfig::load()?, name, access)
}

/// `access` with the credentials `stored` has for `name`, when it has none
/// for the registry.
pub fn with_stored(
    stored: &velarx_registry::AuthConfig,
    name: &str,
    access: &RegistryAccess,
) -> ImageResult<RegistryAccess> {
    let mut access = access.clone();
    let (registry, repository) = name.split_once('/').unwrap_or((name, ""));
    if let Some(creds) = stored
        .with_access(&access)
        .lookup(registry, repository)
        .map_err(ImageError::Invalid)?
    {
        access.auths.entry(registry.to_string()).or_insert(creds);
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
