// SPDX-License-Identifier: Apache-2.0
//! How a pull or a commit makes its files durable (`[storage] sync`).

/// The `[storage] sync` setting: how a pull or a commit makes its files
/// durable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyncMode {
    #[default]
    Syncfs,
    None,
}

impl std::fmt::Display for SyncMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Syncfs => "syncfs",
            Self::None => "none",
        })
    }
}
