// SPDX-License-Identifier: Apache-2.0
//! The formats of the archives `save` writes (the writing is a push to a
//! path: [`crate::dir_push`]).

use velarx_types::{ImageError, ImageResult};

/// Refuse the archive format `format` unless it is `oci-archive`: the
/// Docker archive is not written.
pub fn check_format(format: &str) -> ImageResult<()> {
    velarx_types::docker::refuse_format_name(format)?;
    if format == "oci-archive" {
        Ok(())
    } else {
        Err(ImageError::Invalid(format!(
            "unknown archive format `{}`",
            velarx_types::printable(format)
        )))
    }
}
