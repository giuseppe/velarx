// SPDX-License-Identifier: Apache-2.0
//! The configuration of the registries, in the formats of podman's files
//! and in velarx's directories:
//! - `/etc/velarx/registries.conf` - Registry mirrors, search order, insecure registries
//! - `/etc/velarx/registries.d/` - Per-registry signature verification settings
//! - `${XDG_RUNTIME_DIR}/velarx/auth/auth.json` / `~/.docker/config.json` - Authentication

pub mod auth;
#[cfg(feature = "net")]
pub mod body;
pub mod certs;
#[cfg(feature = "net")]
pub mod client;
pub mod config;
pub mod helper;
#[cfg(feature = "engine")]
pub mod hints;
#[cfg(feature = "net")]
pub(crate) mod netpolicy;
#[cfg(feature = "engine")]
pub mod speed;
#[cfg(feature = "engine")]
pub mod target;
#[cfg(feature = "net")]
pub mod transport;

pub use auth::{AuthConfig, Credentials};
pub use config::RegistriesConfig;

pub use velarx_base::conf::read_config_file;
