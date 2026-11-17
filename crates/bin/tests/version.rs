// SPDX-License-Identifier: Apache-2.0
//! `--version` of every binary names the commit it was built from.  These
//! tests also make `cargo test` build the binaries, which the tests of the
//! package `velarx` start (the worker).

use std::process::Command;

fn version(exe: &str, flag: &str) -> String {
    let out = Command::new(exe).arg(flag).output().unwrap();
    assert!(out.status.success(), "{exe} {flag}: {:?}", out.status);
    assert!(out.stderr.is_empty(), "{exe} {flag}: {:?}", out.stderr);
    String::from_utf8(out.stdout).unwrap()
}

fn expected(name: &str) -> String {
    format!(
        "{name} {} ({})\n",
        env!("CARGO_PKG_VERSION"),
        env!("VELARX_GIT_COMMIT")
    )
}

#[test]
fn commit_is_known_or_explicitly_unknown() {
    let commit = env!("VELARX_GIT_COMMIT");
    assert!(!commit.is_empty() && !commit.contains(char::is_whitespace));
}

#[test]
fn velarx() {
    assert_eq!(
        version(env!("CARGO_BIN_EXE_velarx"), "--version"),
        expected("velarx version")
    );
}

#[test]
fn velarx_client() {
    assert_eq!(
        version(env!("CARGO_BIN_EXE_velarx-client"), "--version"),
        expected("velarx version")
    );
}
