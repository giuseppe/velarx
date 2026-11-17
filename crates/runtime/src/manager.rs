// SPDX-License-Identifier: Apache-2.0
//! Which systemd manager the containers of this process belong to, and
//! whether it answers.

use std::path::Path;

/// Whether this process talks to the system's manager (root), not the
/// user's.
pub fn system_manager() -> Result<bool, velarx_base::ids::IdsError> {
    velarx_base::ids::rootful()
}

/// Whether a scope can be asked of the manager: the private socket
/// of the system's manager (root) or of the user's, in its runtime
/// directory (which is not the bus the runtime uses for the scope of the
/// container).
pub fn scope_manager_answers() -> Result<bool, velarx_base::ids::IdsError> {
    if system_manager()? {
        return Ok(Path::new("/run/systemd/private").exists());
    }
    Ok(std::env::var_os("XDG_RUNTIME_DIR")
        .is_some_and(|d| Path::new(&d).join("systemd/private").exists()))
}
