// SPDX-License-Identifier: Apache-2.0
fn main() {
    let startup = velarx_sys::fd::Startup::take().expect("main is the first to take it");
    let mut args = std::env::args_os().skip(1);
    if let (Some(a), None) = (args.next(), args.next()) {
        if a == "--version" || a == "-V" {
            println!(
                "velarx-monitor {} ({})",
                env!("CARGO_PKG_VERSION"),
                env!("VELARX_GIT_COMMIT")
            );
            return;
        }
    }
    std::process::exit(velarx_runtime::monitor::main(&startup));
}
