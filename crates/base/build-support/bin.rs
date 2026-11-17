// SPDX-License-Identifier: Apache-2.0
//! The build script of the packages that make binaries (`crates/bin`, and
//! the one of each frontend): the commit and the time of the build
//! (`--version`) and the link arguments of the binaries.  The libraries
//! have no build script that reads the repository: a commit, a checkout or
//! a rebase then relinks these small packages and nothing else.
//!
//! The binaries are linked as non-PIE executables: without the relocations
//! of a position independent executable they are about 0.7 MB smaller (the
//! proc macros and the build scripts are not binaries of these packages).

include!("version.rs");

fn main() {
    println!("cargo:rustc-link-arg-bins=-no-pie");
    let dir = std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    for line in directives(std::path::Path::new(&dir), &|k| std::env::var(k).ok()) {
        println!("{line}");
    }
}
