// SPDX-License-Identifier: Apache-2.0
//! The gRPC code of the CRI, from the vendored runtime.v1 proto (needs
//! `protoc`). The `debug_redact` option, which protoc older than 3.20 does
//! not know, is dropped from the copy that is compiled.

fn main() {
    let src = "proto/runtime/v1/api.proto";
    println!("cargo:rerun-if-changed={src}");
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"))
        .join("proto/runtime/v1");
    std::fs::create_dir_all(&out).expect("creating the proto directory");
    let text = std::fs::read_to_string(src)
        .expect("reading the CRI proto")
        .replace(" [debug_redact = true]", "");
    // The library depends on the copy: rewriting it unchanged would make
    // cargo recompile the library at every build.
    let copy = out.join("api.proto");
    if std::fs::read_to_string(&copy).ok().as_deref() != Some(text.as_str()) {
        std::fs::write(&copy, text).expect("writing the CRI proto");
    }
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(
            &[out.join("api.proto")],
            &[out.parent().unwrap().parent().unwrap()],
        )
        .expect("compiling the CRI proto needs protoc (protobuf-compiler)");
}
