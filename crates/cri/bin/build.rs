// SPDX-License-Identifier: Apache-2.0
//! The commit and the time of the build (`--version`).

include!("../../base/build-support/version.rs");

fn main() {
    let dir = std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    for line in directives(std::path::Path::new(&dir), &|k| std::env::var(k).ok()) {
        println!("{line}");
    }
}
