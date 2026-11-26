// SPDX-License-Identifier: Apache-2.0
//! The credentials a request of the registry fetcher carries.

use velarx_registry::auth::RegistryAccess;
use velarx_types::{ImageError, ImageResult};

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
