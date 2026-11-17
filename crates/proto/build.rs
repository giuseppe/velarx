// SPDX-License-Identifier: Apache-2.0
//! The digest of the interface: the FNV-1a (64 bits) of the text of the
//! definition the engine serves (`interfaces/org.velarx.Engine.varlink`,
//! generated from the engine's service and kept current by its test, which
//! also checks the client side against it).  Only a change of the
//! interface changes it, and a client in another language computes it from
//! the file it was made from (interfaces/org.velarx.Engine.varlink).  An engine and a frontend
//! of different ones refuse each other at connect.

const SOURCES: [&str; 1] = ["../../interfaces/org.velarx.Engine.varlink"];

/// The interfaces that the services answer `GetInterfaceDescription` for
/// from their file (`src/interfaces.rs`), and whether the text is kept
/// compressed: the one of the engine is, and only the engine has the
/// decompression in its binary already; the small ones are served by
/// binaries that would grow by it.
const SERVED: [(&str, bool); 5] = [
    ("org.velarx.Engine", true),
    ("org.velarx.Fetcher", false),
    ("org.velarx.Pusher", false),
    ("org.velarx.Registry", false),
    ("org.velarx.Store", false),
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // FNV-1a, 64 bits, over the files in this order: not for security, only
    // to tell one interface from another
    let mut hash: u64 = 0xcbf29ce484222325;
    for path in SOURCES {
        println!("cargo:rerun-if-changed={path}");
        let source = std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"));
        for byte in source {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    println!("cargo:rustc-env=VELARX_INTERFACE_DIGEST={hash:016x}");
    embed_descriptions();
}

/// The text of each served interface as a service sends it (the file
/// without the comment that opens it and the empty line after it); the big
/// one compressed: a service keeps these, not the descriptors of its types.
fn embed_descriptions() {
    use std::io::Write;

    let out = std::env::var("OUT_DIR").expect("OUT_DIR");
    let mut table = String::new();
    for (name, compressed) in SERVED {
        let path = format!("../../interfaces/{name}.varlink");
        println!("cargo:rerun-if-changed={path}");
        let file = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let (_, text) = file
            .split_once("\n\n")
            .unwrap_or_else(|| panic!("{path}: no empty line after the opening comment"));
        let text = text.strip_suffix('\n').unwrap_or(text);
        let constant = name.rsplit('.').next().unwrap().to_uppercase();
        let target = format!("{out}/{name}.txt");
        if compressed {
            let mut z = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
            z.write_all(text.as_bytes()).expect("compress");
            std::fs::write(&target, z.finish().expect("compress"))
                .unwrap_or_else(|e| panic!("{target}: {e}"));
            table.push_str(&format!(
                "const {constant}: &[u8] = include_bytes!({target:?});\n"
            ));
        } else {
            std::fs::write(&target, text).unwrap_or_else(|e| panic!("{target}: {e}"));
            table.push_str(&format!(
                "const {constant}: &str = include_str!({target:?});\n"
            ));
        }
    }
    std::fs::write(format!("{out}/interfaces.rs"), table).expect("interfaces.rs");
}
