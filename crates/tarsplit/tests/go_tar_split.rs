// SPDX-License-Identifier: Apache-2.0
//! The format against the Go tool it comes from.
//!
//! The fixtures are tar-splits written by `github.com/vbatts/tar-split`
//! (`asm.NewInputTarStream` with `storage.NewJSONPacker`) from two archives
//! made by GNU tar, one with GNU long names and one with PAX records, of a
//! directory, two regular files, an empty one, a FIFO, a hard link, a
//! symbolic link, a long name and a name that is not ASCII.  The digests of
//! the archives were taken with `sha256sum`.  Nothing here is made by the
//! code under test: the replay must give the archives back, and recording
//! them must give the Go tool's lines.

use base64::Engine;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{self, Read};
use velarx_tarsplit::{decoder, tar::TarReader, Contents, Entries, Recorder, Replay, MAX_SIZE};

struct Files(HashMap<&'static str, &'static [u8]>);

impl Contents for Files {
    fn open(&mut self, name: &str, size: u64) -> io::Result<Box<dyn Read + Send>> {
        let data = self.0[name];
        assert_eq!(data.len() as u64, size, "{name}");
        Ok(Box::new(data))
    }
}

fn files() -> Files {
    Files(HashMap::from([
        ("d/a", &b"hello"[..]),
        (
            "d/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            &b"long name\n"[..],
        ),
        ("d/\u{fc}n\u{ef}code", "\u{fc}n\u{ef}".as_bytes()),
    ]))
}

/// The Go tool writes the end of the archive and what follows it as two
/// segments; the recorder writes one.  The lines of the Go tool with the
/// segments at their end joined.
fn joined_tail(go: &str) -> String {
    let mut lines: Vec<String> = go.lines().map(str::to_string).collect();
    let segment = |line: &str| -> Option<Vec<u8>> {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        (v["type"] == 2).then(|| {
            base64::engine::general_purpose::STANDARD
                .decode(v["payload"].as_str().unwrap())
                .unwrap()
        })
    };
    while lines.len() >= 2 {
        let n = lines.len();
        let (Some(mut a), Some(b)) = (segment(&lines[n - 2]), segment(&lines[n - 1])) else {
            break;
        };
        a.extend(b);
        lines.truncate(n - 2);
        lines.push(format!(
            "{{\"type\":2,\"payload\":\"{}\",\"position\":{}}}",
            base64::engine::general_purpose::STANDARD.encode(&a),
            n - 2
        ));
    }
    lines.iter().map(|l| format!("{l}\n")).collect()
}

fn check(go: &str, sha256: &str) {
    // the replay of the Go tool's tar-split is the archive
    let mut archive = Vec::new();
    Replay::new(Entries::new(io::Cursor::new(go)), files())
        .read_to_end(&mut archive)
        .unwrap();
    assert_eq!(hex(&Sha256::digest(&archive)), sha256);

    // and the recording of the archive is the Go tool's tar-split
    let mut reader = TarReader::with_sink(&archive[..], Recorder::new().unwrap());
    while reader.next_entry().unwrap().is_some() {
        io::copy(&mut reader, &mut io::sink()).unwrap();
    }
    let (_, recorder) = reader.finish().unwrap();
    let mut recorded = String::new();
    decoder(recorder.finish().unwrap().compressed, MAX_SIZE)
        .unwrap()
        .read_to_string(&mut recorded)
        .unwrap();
    assert_eq!(recorded, joined_tail(go));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn a_go_tar_split_of_gnu_long_names() {
    check(
        include_str!("fixtures/gnu.tarsplit"),
        "57e232e47b33c9df5892ae088e99b838ff8415cf521b014c811873612480ea91",
    );
}

#[test]
fn a_go_tar_split_of_pax_records() {
    check(
        include_str!("fixtures/pax.tarsplit"),
        "5c28a54b02585d52e43a85b6c34f85faaa261ba9469a9cc68da5fcb029f7afc8",
    );
}
