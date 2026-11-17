// SPDX-License-Identifier: Apache-2.0
//! `velarx-client`: the command line of velarx, as a client of the API
//! server; what needs the engine it leaves to `velarx`.

fn main() -> anyhow::Result<()> {
    let startup = velarx_sys::fd::Startup::take().expect("main is the first to take it");
    velarx_base::buildinfo::set(env!("VELARX_GIT_COMMIT"), env!("VELARX_BUILD_TIME"));
    velarx::cli::commands::main(&startup)
}
