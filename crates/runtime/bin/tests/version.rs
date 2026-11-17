// SPDX-License-Identifier: Apache-2.0
//! `--version` of velarx-monitor names the commit it was built from.  This
//! test also makes `cargo test` build the binary, which the tests of the
//! package `velarx` start.

use std::process::Command;

fn version(flag: &str) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_velarx-monitor"))
        .arg(flag)
        .output()
        .unwrap();
    assert!(out.status.success(), "{flag}: {:?}", out.status);
    assert!(out.stderr.is_empty(), "{flag}: {:?}", out.stderr);
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn velarx_monitor() {
    let expected = format!(
        "velarx-monitor {} ({})\n",
        env!("CARGO_PKG_VERSION"),
        env!("VELARX_GIT_COMMIT")
    );
    assert_eq!(version("--version"), expected);
    assert_eq!(version("-V"), expected);
}
