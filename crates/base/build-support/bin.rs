// SPDX-License-Identifier: Apache-2.0
//! The build script of the packages that make binaries (`crates/bin`, and
//! the one of each frontend): the commit and the time of the build
//! (`--version`) and the link arguments of the binaries.  The libraries
//! have no build script that reads the repository: a commit, a checkout or
//! a rebase then relinks these small packages and nothing else.
//!
//! The binaries are position independent executables (the default of rustc
//! on Linux), so the address space of the engine and of its helpers is
//! randomized.  Their relative relocations are packed (`DT_RELR`), which
//! costs no size over a non-PIE link; it needs glibc 2.36 at run time and a
//! linker that supports it (GNU ld 2.38, lld, mold).  The argument is given
//! here, not in a `RUSTFLAGS`, which a builder's environment replaces.

include!("version.rs");

fn main() {
    println!("cargo:rustc-link-arg-bins=-Wl,-z,pack-relative-relocs");
    let dir = std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    for line in directives(std::path::Path::new(&dir), &|k| std::env::var(k).ok()) {
        println!("{line}");
    }
}
