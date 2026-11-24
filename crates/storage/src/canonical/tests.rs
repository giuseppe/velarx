// SPDX-License-Identifier: Apache-2.0
//! Each rule has a test with the exact bytes the rule gives, written by
//! hand here and not taken from the generator.

use super::*;
use sha2::{Digest, Sha256};
use velarx_types::digest::parse_toc_fsverity;

const DIR: TocEntryType = TocEntryType::Dir;
const REG: TocEntryType = TocEntryType::Reg;

fn entry(name: &str, kind: TocEntryType) -> TocEntry {
    TocEntry {
        mode: if kind == DIR { 0o755 } else { 0o644 },
        ..TocEntry::new(name.to_string(), kind)
    }
}

fn file(name: &str, size: u64) -> TocEntry {
    let mut e = entry(name, REG);
    e.size = size;
    e
}

fn timed(mut e: TocEntry, t: &str) -> TocEntry {
    e.mod_time = Some(t.to_string());
    e
}

fn xattr(mut e: TocEntry, name: &str, value: &[u8]) -> TocEntry {
    e.xattrs.insert(
        name.to_string(),
        base64::engine::general_purpose::STANDARD.encode(value),
    );
    e
}

fn content(e: &TocEntry, out: &mut dyn Write) -> io::Result<()> {
    out.write_all(&vec![b'x'; e.size as usize])
}

fn tar(entries: &[TocEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    write(entries, &mut out, content).unwrap();
    assert_eq!(out.len() as u64, stream_size(entries).unwrap());
    out
}

/// The tar of the entries, which the validator accepts.
fn canonical(entries: &[TocEntry]) -> Vec<u8> {
    let out = tar(entries);
    validate_tar(&out[..]).unwrap_or_else(|e| panic!("{e}"));
    out
}

/// A header block with the fields as literal bytes: numbers are the digits
/// (the NUL after them is added), the checksum is made here.
#[allow(clippy::too_many_arguments)]
fn header(
    name: &[u8],
    mode: &str,
    uid: &str,
    gid: &str,
    size: &str,
    mtime: &str,
    typ: u8,
    link: &[u8],
    device: Option<(&str, &str)>,
) -> Vec<u8> {
    let mut b = vec![0u8; 512];
    let mut put = |at: usize, v: &[u8]| b[at..at + v.len()].copy_from_slice(v);
    put(0, name);
    put(100, format!("{mode}\0").as_bytes());
    put(108, format!("{uid}\0").as_bytes());
    put(116, format!("{gid}\0").as_bytes());
    put(124, format!("{size}\0").as_bytes());
    put(136, format!("{mtime}\0").as_bytes());
    put(148, b"        ");
    put(156, &[typ]);
    put(157, link);
    put(257, b"ustar\x0000");
    if let Some((major, minor)) = device {
        put(329, format!("{major}\0").as_bytes());
        put(337, format!("{minor}\0").as_bytes());
    }
    let sum: u32 = b.iter().map(|&c| u32::from(c)).sum();
    b[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    b
}

fn padded(mut v: Vec<u8>) -> Vec<u8> {
    v.resize(v.len().next_multiple_of(512), 0);
    v
}

/// The `x` entry of the records.
fn pax(base: &[u8], records: &[u8]) -> Vec<u8> {
    let mut name = b"PaxHeaders.0/".to_vec();
    name.extend_from_slice(base);
    let mut v = header(
        &name,
        "0000644",
        "0000000",
        "0000000",
        &format!("{:011o}", records.len()),
        "00000000000",
        b'x',
        b"",
        None,
    );
    v.extend(padded(records.to_vec()));
    v
}

const MARKER_RECORD: &[u8] = b"27 comment=canonical-tar=1\n";

/// The first entry of every stream: the root.
fn root() -> Vec<u8> {
    let mut v = pax(b".", MARKER_RECORD);
    v.extend(header(
        b"./",
        "0000755",
        "0000000",
        "0000000",
        "00000000000",
        "00000000000",
        b'5',
        b"",
        None,
    ));
    v
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

const END: &[u8] = &[0; 1024];

#[test]
fn an_empty_layer_is_the_two_zero_blocks() {
    let out = canonical(&[]);
    assert_eq!(out, END);
    assert_eq!(
        hex::encode(Sha256::digest(&out)),
        "5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"
    );
}

#[test]
fn the_first_entry_has_the_marker_even_when_nothing_else_needs_a_pax_header() {
    let out = canonical(&[entry("./", DIR)]);
    assert_eq!(out, cat(&[&root(), END]));
    // the marker is a `comment` record, 27 bytes with its length
    assert_eq!(&out[512..539], MARKER_RECORD);
}

#[test]
fn only_the_first_entry_has_the_marker() {
    let mut f = file("./f", 3);
    f.mode = 0o600;
    let out = canonical(&[entry("./", DIR), f]);
    let h = header(
        b"./f",
        "0000600",
        "0000000",
        "0000000",
        "00000000003",
        "00000000000",
        b'0',
        b"",
        None,
    );
    assert_eq!(out, cat(&[&root(), &h, &padded(b"xxx".to_vec()), END]));
}

#[test]
fn a_file_first_gets_the_marker_and_a_layer_without_root_has_none() {
    let out = canonical(&[file("./a", 0), file("./b", 0)]);
    let h = |n: &[u8]| {
        header(
            n,
            "0000644",
            "0000000",
            "0000000",
            "00000000000",
            "00000000000",
            b'0',
            b"",
            None,
        )
    };
    assert_eq!(
        out,
        cat(&[&pax(b"a", MARKER_RECORD), &h(b"./a"), &h(b"./b"), END])
    );
}

#[test]
fn numbers_are_padded_octal_and_the_mode_keeps_the_special_bits() {
    let mut e = file("./su", 0);
    e.mode = 0o7777;
    e.uid = 1000;
    e.gid = 2_097_151;
    let out = tar(&[entry("./", DIR), e]);
    let h = header(
        b"./su",
        "0007777",
        "0001750",
        "7777777",
        "00000000000",
        "00000000000",
        b'0',
        b"",
        None,
    );
    assert_eq!(out, cat(&[&root(), &h, END]));
}

#[test]
fn the_checksum_is_six_digits_a_nul_and_a_space() {
    let out = canonical(&[entry("./", DIR)]);
    let h = &out[1024..1536];
    assert_eq!(h[154..156], *b"\0 ");
    assert!(h[148..154].iter().all(|b| (b'0'..=b'7').contains(b)));
    let sum: u32 = h
        .iter()
        .enumerate()
        .map(|(i, &b)| u32::from(if (148..156).contains(&i) { b' ' } else { b }))
        .sum();
    assert_eq!(
        u32::from_str_radix(std::str::from_utf8(&h[148..154]).unwrap(), 8).unwrap(),
        sum
    );
}

#[test]
fn a_path_of_100_bytes_is_in_the_name_and_one_of_101_is_a_pax_record() {
    let p100 = format!("./{}", "a".repeat(98));
    let p101 = format!("./{}", "b".repeat(99));
    let out = canonical(&[entry("./", DIR), file(&p100, 0), file(&p101, 0)]);
    let plain = header(
        p100.as_bytes(),
        "0000644",
        "0000000",
        "0000000",
        "00000000000",
        "00000000000",
        b'0',
        b"",
        None,
    );
    // the length counts itself: `path=`, 101 bytes, the space and the
    // newline are 108, and its 3 digits
    let record = format!("111 path={p101}\n");
    assert_eq!(record.len(), 111);
    let long = cat(&[
        &pax(&[b'b'; 87], record.as_bytes()),
        &header(
            &p101.as_bytes()[..100],
            "0000644",
            "0000000",
            "0000000",
            "00000000000",
            "00000000000",
            b'0',
            b"",
            None,
        ),
    ]);
    assert_eq!(out, cat(&[&root(), &plain, &long, END]));
}

#[test]
fn the_pax_header_of_a_directory_is_named_after_its_last_component() {
    let long = format!("./{}/", "d".repeat(150));
    let out = canonical(&[entry("./", DIR), entry(&long, DIR)]);
    let record = format!("163 path={long}\n");
    assert_eq!(record.len(), 163);
    let x = pax(&[b'd'; 87], record.as_bytes());
    let h = header(
        &long.as_bytes()[..100],
        "0000755",
        "0000000",
        "0000000",
        "00000000000",
        "00000000000",
        b'5',
        b"",
        None,
    );
    assert_eq!(out, cat(&[&root(), &x, &h, END]));
}

#[test]
fn the_name_is_cut_inside_a_character_when_it_has_to() {
    // 98 bytes then a two byte character: the cut is between its bytes
    let name = format!("./{}é", "a".repeat(97));
    assert_eq!(name.len(), 101);
    let out = canonical(&[entry("./", DIR), file(&name, 0)]);
    let record = format!("111 path={name}\n");
    assert_eq!(record.len(), 111);
    let x = pax(&[b'a'; 87], record.as_bytes());
    let h = header(
        &name.as_bytes()[..100],
        "0000644",
        "0000000",
        "0000000",
        "00000000000",
        "00000000000",
        b'0',
        b"",
        None,
    );
    assert_eq!(h[99], 0xc3);
    assert_eq!(out, cat(&[&root(), &x, &h, END]));
}

#[test]
fn ids_of_2_pow_21_and_more_are_pax_records_and_their_fields_are_zero() {
    let mut a = file("./a", 0);
    (a.uid, a.gid) = (2_097_151, 2_097_152);
    let mut b = file("./b", 0);
    (b.uid, b.gid) = (u32::MAX, 0);
    let out = canonical(&[entry("./", DIR), a, b]);
    let ha = header(
        b"./a",
        "0000644",
        "7777777",
        "0000000",
        "00000000000",
        "00000000000",
        b'0',
        b"",
        None,
    );
    let hb = header(
        b"./b",
        "0000644",
        "0000000",
        "0000000",
        "00000000000",
        "00000000000",
        b'0',
        b"",
        None,
    );
    assert_eq!(
        out,
        cat(&[
            &root(),
            &pax(b"a", b"15 gid=2097152\n"),
            &ha,
            &pax(b"b", b"18 uid=4294967295\n"),
            &hb,
            END
        ])
    );
}

fn fields(e: &TocEntry) -> Fields {
    Fields::of(e).unwrap()
}

#[test]
fn a_size_of_8_pow_11_is_a_pax_record_and_less_is_not() {
    for (size, records, field) in [
        (0o77_777_777_777u64, "", "77777777777"),
        (0o100_000_000_000, "19 size=8589934592\n", "00000000000"),
    ] {
        let mut out = Vec::new();
        headers(&fields(&file("./big", size)), false, &mut out).unwrap();
        let h = header(
            b"./big",
            "0000644",
            "0000000",
            "0000000",
            field,
            "00000000000",
            b'0',
            b"",
            None,
        );
        let expected = if records.is_empty() {
            h
        } else {
            cat(&[&pax(b"big", records.as_bytes()), &h])
        };
        assert_eq!(out, expected, "{size}");
    }
}

#[test]
fn the_time_is_in_the_field_or_a_pax_record_by_its_value() {
    let t = |s: &str| {
        let mut out = Vec::new();
        headers(&fields(&timed(file("./t", 0), s)), false, &mut out).unwrap();
        out
    };
    let h = |mtime: &str| {
        header(
            b"./t",
            "0000644",
            "0000000",
            "0000000",
            "00000000000",
            mtime,
            b'0',
            b"",
            None,
        )
    };
    // whole seconds in range: the field only
    assert_eq!(t("1970-01-01T00:00:00Z"), h("00000000000"));
    assert_eq!(t("2023-11-14T22:13:20Z"), h("14524770400"));
    // the last second the field holds, 8^11-1 = 8589934591
    assert_eq!(t("2242-03-16T12:56:31Z"), h("77777777777"));
    // nanoseconds: a record, and the seconds in the field
    assert_eq!(
        t("2023-11-14T22:13:20.5Z"),
        cat(&[&pax(b"t", b"22 mtime=1700000000.5\n"), &h("14524770400")])
    );
    // 5 ns and 0.5 s are not the same
    assert_eq!(
        t("1970-01-01T00:00:00.000000005Z"),
        cat(&[&pax(b"t", b"21 mtime=0.000000005\n"), &h("00000000000")])
    );
    assert_eq!(
        t("1970-01-01T00:00:00.5Z"),
        cat(&[&pax(b"t", b"13 mtime=0.5\n"), &h("00000000000")])
    );
    assert_eq!(
        t("1970-01-01T00:00:00.123456789Z"),
        cat(&[&pax(b"t", b"21 mtime=0.123456789\n"), &h("00000000000")])
    );
    // 8^11 seconds: a record, the field is 0
    assert_eq!(
        t("2242-03-16T12:56:32Z"),
        cat(&[&pax(b"t", b"20 mtime=8589934592\n"), &h("00000000000")])
    );
    // before 1970: the instant with a sign, the field is 0
    assert_eq!(
        t("1969-12-31T23:59:59Z"),
        cat(&[&pax(b"t", b"12 mtime=-1\n"), &h("00000000000")])
    );
    assert_eq!(
        t("1969-12-31T23:59:58.5Z"),
        cat(&[&pax(b"t", b"14 mtime=-1.5\n"), &h("00000000000")])
    );
    assert_eq!(
        t("1969-12-31T23:59:59.75Z"),
        cat(&[&pax(b"t", b"15 mtime=-0.25\n"), &h("00000000000")])
    );
}

#[test]
fn the_records_are_in_their_order_and_the_xattrs_are_sorted_by_key() {
    let long = format!("./{}", "p".repeat(120));
    let mut e = timed(file(&long, 0), "2023-11-14T22:13:20.5Z");
    e.uid = 5_000_000;
    e.gid = 6_000_000;
    let e = xattr(e, "user.b", b"2");
    let e = xattr(e, "security.capability", b"1");
    let e = xattr(e, "user.a", b"3");
    let out = canonical(&[e]);
    let mut records = Vec::new();
    for r in [
        "comment=canonical-tar=1".to_string(),
        format!("path={long}"),
        "uid=5000000".to_string(),
        "gid=6000000".to_string(),
        "mtime=1700000000.5".to_string(),
        "SCHILY.xattr.security.capability=1".to_string(),
        "SCHILY.xattr.user.a=3".to_string(),
        "SCHILY.xattr.user.b=2".to_string(),
    ] {
        let rest = r.len() + 2;
        let len = if (rest + 2).to_string().len() == 2 {
            rest + 2
        } else {
            rest + 3
        };
        records.extend(format!("{len} {r}\n").bytes());
    }
    let h = header(
        &long.as_bytes()[..100],
        "0000644",
        "0000000",
        "0000000",
        "00000000000",
        "14524770400",
        b'0',
        b"",
        None,
    );
    assert_eq!(out, cat(&[&pax(&[b'p'; 87], &records), &h, END]));
}

#[test]
fn an_xattr_value_is_raw_bytes() {
    let e = xattr(file("./x", 0), "user.k", b"a\0b\nc");
    let mut out = Vec::new();
    headers(&fields(&e), false, &mut out).unwrap();
    let record = b"29 SCHILY.xattr.user.k=a\0b\nc\n";
    assert_eq!(record.len(), 29);
    assert_eq!(&out[512..512 + record.len()], record);
}

#[test]
fn links_and_special_files_have_their_type_link_and_device_fields() {
    let mut sym = entry("./s", TocEntryType::Symlink);
    sym.link_name = Some("../t".into());
    sym.mode = 0o777;
    let mut long = entry("./l", TocEntryType::Symlink);
    let target = "t".repeat(101);
    long.link_name = Some(target.clone());
    long.mode = 0o777;
    let mut chr = entry("./c", TocEntryType::Char);
    (chr.dev_major, chr.dev_minor) = (Some(1), Some(3));
    let mut blk = entry("./b", TocEntryType::Block);
    (blk.dev_major, blk.dev_minor) = (Some(8), Some(2_097_151));
    let fifo = entry("./f", TocEntryType::Fifo);
    let out = canonical(&[blk, chr, fifo, long, sym]);
    let h = |n: &[u8], mode: &str, typ: u8, link: &[u8], dev| {
        header(
            n,
            mode,
            "0000000",
            "0000000",
            "00000000000",
            "00000000000",
            typ,
            link,
            dev,
        )
    };
    let record = format!("115 linkpath={target}\n");
    assert_eq!(record.len(), 115);
    assert_eq!(
        out,
        cat(&[
            &pax(b"b", MARKER_RECORD),
            &h(b"./b", "0000644", b'4', b"", Some(("0000010", "7777777"))),
            &h(b"./c", "0000644", b'3', b"", Some(("0000001", "0000003"))),
            &h(b"./f", "0000644", b'6', b"", None),
            &pax(b"l", record.as_bytes()),
            &h(b"./l", "0000777", b'2', &target.as_bytes()[..100], None),
            &h(b"./s", "0000777", b'2', b"../t", None),
            END
        ])
    );
}

#[test]
fn a_hard_link_is_a_header_of_its_own_with_the_target_in_the_link_name() {
    let t = "2023-11-14T22:13:20Z";
    let mut a = timed(file("./a", 3), t);
    a.mode = 0o755;
    let mut b = timed(entry("./b", TocEntryType::Hardlink), t);
    b.mode = 0o755;
    b.link_name = Some("./a".into());
    let out = tar(&[a, b]);
    let mk = |n: &[u8], size: &str, typ: u8, link: &[u8]| {
        header(
            n,
            "0000755",
            "0000000",
            "0000000",
            size,
            "14524770400",
            typ,
            link,
            None,
        )
    };
    assert_eq!(
        out,
        cat(&[
            &pax(b"a", MARKER_RECORD),
            &mk(b"./a", "00000000003", b'0', b""),
            &padded(b"xxx".to_vec()),
            &mk(b"./b", "00000000000", b'1', b"./a"),
            END
        ])
    );
}

#[test]
fn a_whiteout_is_an_empty_regular_file_of_fixed_metadata() {
    let out = canonical(&[
        entry("./", DIR),
        entry("./d/", DIR),
        file("./d/.wh..wh..opq", 0),
        file("./d/.wh.gone", 0),
        file("./d/real", 0),
    ]);
    let h = |n: &[u8], mode: &str, typ: u8| {
        header(
            n,
            mode,
            "0000000",
            "0000000",
            "00000000000",
            "00000000000",
            typ,
            b"",
            None,
        )
    };
    assert_eq!(
        out,
        cat(&[
            &root(),
            &h(b"./d/", "0000755", b'5'),
            &h(b"./d/.wh..wh..opq", "0000644", b'0'),
            &h(b"./d/.wh.gone", "0000644", b'0'),
            &h(b"./d/real", "0000644", b'0'),
            END
        ])
    );
}

#[test]
fn the_content_is_padded_with_zeros_to_a_block() {
    for size in [1u64, 511, 512, 513] {
        let out = tar(&[file("./f", size)]);
        let blocks = size.div_ceil(512) as usize;
        assert_eq!(out.len(), 1024 + 512 + blocks * 512 + 1024, "{size}");
        assert!(out[1536 + size as usize..out.len() - 1024]
            .iter()
            .all(|&b| b == 0));
    }
}

#[test]
fn a_content_of_the_wrong_length_is_an_error() {
    for n in [2usize, 4] {
        let r = write(&[file("./f", 3)], Vec::new(), |_, out| {
            out.write_all(&vec![0; n])
        });
        assert!(r.is_err(), "{n}");
    }
}

#[test]
fn the_chunks_of_a_file_are_not_entries_of_the_tar() {
    let mut f = file("./f", 10);
    f.chunk_size = 4;
    let mut c = entry("./f", TocEntryType::Chunk);
    (c.chunk_offset, c.chunk_size) = (4, 6);
    let with = tar(&[f.clone(), c]);
    assert_eq!(with, tar(&[f]));
}

fn rejected(entries: &[TocEntry]) -> String {
    validate(entries).unwrap_err().to_string()
}

fn ok(entries: &[TocEntry]) {
    validate(entries).unwrap_or_else(|e| panic!("{e}"));
}

fn with_content(name: &str, size: u64) -> TocEntry {
    let mut e = file(name, size);
    e.fsverity = Some(
        crate::to_toc(&crate::fsverity_digest_of(
            velarx_types::digest::Algorithm::Sha256,
            b"x",
        ))
        .unwrap(),
    );
    (e.offset, e.end_offset) = (10, 20);
    e
}

#[test]
fn the_names_are_canonical_paths() {
    ok(&[entry("./", DIR), entry("./a/", DIR), file("./a/b", 0)]);
    for (name, kind) in [
        ("a", REG),
        ("/a", REG),
        ("../a", REG),
        (".", DIR),
        ("", REG),
        ("./a/", REG),
        ("./a", DIR),
        ("././a", REG),
        ("./a//b", REG),
        ("./a/./b", REG),
        ("./a/../b", REG),
        (".//", DIR),
        ("./a\0b", REG),
    ] {
        assert!(validate(&[entry(name, kind)]).is_err(), "{name:?}");
    }
}

#[test]
fn the_order_is_the_one_of_the_components_and_not_of_the_strings() {
    // `-` sorts before `/` as a byte, but ./a/b is in ./a
    ok(&[entry("./a/", DIR), file("./a/b", 0), file("./a-c", 0)]);
    let e = rejected(&[entry("./a/", DIR), file("./a-c", 0), file("./a/b", 0)]);
    assert!(e.contains("sorts before"), "{e}");
    ok(&[
        file("./a", 0),
        file("./b", 0),
        file("./b.c", 0),
        file("./ba", 0),
    ]);
    assert!(rejected(&[file("./b", 0), file("./a", 0)]).contains("entry 1 `./a`"));
    // a path once
    assert!(rejected(&[file("./a", 0), file("./a", 0)]).contains("twice"));
    assert!(rejected(&[file("./a", 0), entry("./a/", DIR)]).contains("twice"));
    // a name with a byte above 0x7f sorts as the byte
    ok(&[file("./z", 0), file("./é", 0)]);
    assert!(validate(&[file("./é", 0), file("./z", 0)]).is_err());
}

#[test]
fn the_root_is_first_and_a_directory() {
    ok(&[entry("./", DIR), file("./a", 0)]);
    assert!(validate(&[file("./a", 0), entry("./", DIR)]).is_err());
    assert!(validate(&[file("./", 0)]).is_err());
    // the layer without a root is valid and has no synthesized ancestors
    ok(&[file("./usr/bin/sh", 0)]);
}

#[test]
fn a_hard_link_is_to_an_earlier_file_with_its_metadata() {
    let t = "2023-11-14T22:13:20.25Z";
    let target = {
        let mut f = timed(file("./a", 0), t);
        f.uid = 7;
        f
    };
    let link = |name: &str, to: &str| {
        let mut l = timed(entry(name, TocEntryType::Hardlink), t);
        l.uid = 7;
        l.link_name = Some(to.into());
        l
    };
    ok(&[target.clone(), link("./b", "./a")]);
    ok(&[target.clone(), link("./b", "./a"), link("./c", "./a")]);
    // later, or itself, or missing
    assert!(validate(&[link("./a", "./b"), file("./b", 0)]).is_err());
    assert!(validate(&[link("./a", "./a")]).is_err());
    assert!(validate(&[target.clone(), link("./b", "./zz")]).is_err());
    // a link to a link, to a directory, to a path that is not canonical
    assert!(validate(&[target.clone(), link("./b", "./a"), link("./c", "./b")]).is_err());
    assert!(validate(&[entry("./d/", DIR), link("./e", "./d/")]).is_err());
    assert!(validate(&[entry("./d/", DIR), link("./e", "./d")]).is_err());
    assert!(validate(&[target.clone(), link("./b", "a")]).is_err());
    // the metadata of the target
    for change in [
        |l: &mut TocEntry| l.mode = 0o600,
        |l: &mut TocEntry| l.uid = 8,
        |l: &mut TocEntry| l.gid = 1,
        |l: &mut TocEntry| l.mod_time = None,
        |l: &mut TocEntry| l.mod_time = Some("2023-11-14T22:13:20.26Z".into()),
    ] {
        let mut l = link("./b", "./a");
        change(&mut l);
        assert!(validate(&[target.clone(), l]).is_err());
    }
    // no xattrs and no size
    let l = xattr(link("./b", "./a"), "user.k", b"v");
    assert!(validate(&[target.clone(), l]).is_err());
    let mut l = link("./b", "./a");
    l.size = 1;
    assert!(validate(&[target, l]).is_err());
}

#[test]
fn a_whiteout_has_fixed_metadata_and_is_a_regular_file() {
    ok(&[file("./.wh..wh..opq", 0), file("./.wh.a", 0)]);
    ok(&[timed(file("./.wh.a", 0), "1970-01-01T00:00:00Z")]);
    for change in [
        |e: &mut TocEntry| e.mode = 0o755,
        |e: &mut TocEntry| e.mode = 0,
        |e: &mut TocEntry| e.uid = 1,
        |e: &mut TocEntry| e.gid = 1,
        |e: &mut TocEntry| e.mod_time = Some("2000-01-01T00:00:00Z".into()),
        |e: &mut TocEntry| e.size = 1,
        |e: &mut TocEntry| {
            e.xattrs.insert("user.k".into(), String::new());
        },
        |e: &mut TocEntry| e.entry_type = TocEntryType::Fifo,
    ] {
        let mut e = file("./.wh.a", 0);
        change(&mut e);
        assert!(validate(&[e]).is_err());
    }
    let mut d = entry("./.wh.d/", DIR);
    d.mode = 0o644;
    assert!(validate(&[d]).is_err());
    // a file that only looks like one
    ok(&[file("./.whx", 0), file("./a.wh.b", 0)]);
}

#[test]
fn the_character_device_0_0_and_the_overlay_xattrs_are_refused() {
    let mut c = entry("./c", TocEntryType::Char);
    (c.dev_major, c.dev_minor) = (Some(0), Some(0));
    assert!(rejected(&[c.clone()]).contains("whiteout"));
    (c.dev_major, c.dev_minor) = (Some(0), Some(1));
    ok(&[c]);
    let mut b = entry("./b", TocEntryType::Block);
    (b.dev_major, b.dev_minor) = (Some(0), Some(0));
    ok(&[b]);
    for name in [
        "trusted.overlay.opaque",
        "user.overlay.redirect",
        "trusted.overlay.x",
    ] {
        assert!(
            validate(&[xattr(file("./a", 0), name, b"y")]).is_err(),
            "{name}"
        );
    }
    ok(&[xattr(file("./a", 0), "security.overlay.x", b"y")]);
    ok(&[xattr(file("./a", 0), "user.overlaid", b"y")]);
}

#[test]
fn the_limits_of_xattrs_devices_times_and_modes() {
    let long = format!("user.{}", "n".repeat(250));
    ok(&[xattr(file("./a", 0), &long, b"")]);
    assert!(validate(&[xattr(file("./a", 0), &format!("{long}n"), b"")]).is_err());
    assert!(validate(&[xattr(file("./a", 0), "user.a=b", b"")]).is_err());
    assert!(validate(&[xattr(file("./a", 0), "", b"")]).is_err());
    ok(&[xattr(file("./a", 0), "user.k", &vec![1; 65536])]);
    assert!(validate(&[xattr(file("./a", 0), "user.k", &vec![1; 65537])]).is_err());
    let mut bad = file("./a", 0);
    bad.xattrs.insert("user.k".into(), "not base64!".into());
    assert!(validate(&[bad]).is_err());

    let mut d = entry("./d", TocEntryType::Block);
    (d.dev_major, d.dev_minor) = (Some(1), Some(2_097_151));
    ok(&[d.clone()]);
    d.dev_minor = Some(2_097_152);
    assert!(validate(&[d]).is_err());
    let mut f = file("./f", 0);
    f.dev_major = Some(1);
    assert!(validate(&[f]).is_err());

    ok(&[timed(file("./a", 0), "0001-01-01T00:00:00Z")]);
    ok(&[timed(file("./a", 0), "9999-12-31T23:59:59.999999999Z")]);
    ok(&[timed(file("./a", 0), "2023-11-14T23:13:20+01:00")]);
    assert!(validate(&[timed(file("./a", 0), "yesterday")]).is_err());
    assert!(validate(&[timed(file("./a", 0), "0000-12-31T23:59:59Z")]).is_err());

    let mut m = file("./a", 0);
    m.mode = 0o10000;
    assert!(validate(&[m]).is_err());
    let mut s = entry("./s", TocEntryType::Symlink);
    assert!(validate(&[s.clone()]).is_err());
    s.link_name = Some(String::new());
    assert!(validate(&[s.clone()]).is_err());
    s.link_name = Some("x".into());
    ok(&[s]);
    let mut r = file("./r", 0);
    r.link_name = Some("x".into());
    assert!(validate(&[r]).is_err());
    let mut dsize = entry("./d/", DIR);
    dsize.size = 1;
    assert!(validate(&[dsize]).is_err());
}

#[test]
fn a_file_with_content_needs_its_digest_its_place_and_its_chunks() {
    ok(&[with_content("./f", 10)]);
    let mut e = with_content("./f", 10);
    e.fsverity = None;
    assert!(rejected(&[e]).contains("fs-verity"));
    let mut e = with_content("./f", 10);
    e.end_offset = e.offset;
    assert!(validate(&[e]).is_err());

    let chunk = |off: u64, size: u64| {
        let mut c = entry("./f", TocEntryType::Chunk);
        (c.chunk_offset, c.chunk_size) = (off, size);
        c
    };
    let mut f = with_content("./f", 10);
    f.chunk_size = 4;
    ok(&[f.clone(), chunk(4, 6)]);
    ok(&[f.clone(), chunk(4, 2), chunk(6, 4)]);
    assert!(validate(&[f.clone()]).is_err());
    assert!(validate(&[f.clone(), chunk(4, 5)]).is_err());
    assert!(validate(&[f.clone(), chunk(4, 7)]).is_err());
    assert!(validate(&[f.clone(), chunk(5, 5)]).is_err());
    assert!(validate(&[f.clone(), chunk(4, 0)]).is_err());
    // a chunk of another file, of a file without content, or first
    let mut other = chunk(4, 6);
    other.name = "./g".into();
    assert!(validate(&[f.clone(), other]).is_err());
    assert!(validate(&[chunk(4, 6)]).is_err());
    assert!(validate(&[entry("./", DIR), chunk(0, 1)]).is_err());
    assert!(validate(&[file("./e", 0), chunk(0, 1)]).is_err());
    let mut after = file("./g", 0);
    after.name = "./g".into();
    assert!(validate(&[f.clone(), chunk(4, 6), after, chunk(10, 1)]).is_err());
    // the file is not covered when its chunks stop short
    let mut g = with_content("./f", 10);
    g.chunk_size = 11;
    assert!(validate(&[g]).is_err());
}

#[test]
fn the_error_names_the_entry() {
    let e = validate(&[file("./a", 0), file("./b", 0), file("b", 0)]).unwrap_err();
    assert_eq!((e.index, e.name.as_str()), (2, "b"));
    assert!(e.to_string().ends_with("(entry 2 `b`)"), "{e}");
}

// What a reader of a tar says of a stream that is not canonical.

fn not_canonical(bytes: &[u8]) -> String {
    validate_tar(bytes).unwrap_err().to_string()
}

#[test]
fn a_tar_of_the_wrong_ending_is_not_canonical() {
    let good = canonical(&[entry("./", DIR), file("./a", 3)]);
    // one zero block, data after, nothing at all, cut
    assert!(not_canonical(&good[..good.len() - 512]).contains("ends"));
    let mut more = good.clone();
    more.extend_from_slice(&[0; 512]);
    assert!(not_canonical(&more).contains("after"));
    let mut tenk = good.clone();
    tenk.resize(10240, 0);
    assert!(not_canonical(&tenk).contains("after"));
    assert!(not_canonical(b"").contains("ends"));
    let mut dirty = good.clone();
    let n = dirty.len();
    dirty[n - 1] = 1;
    assert!(validate_tar(&dirty[..]).is_err());
}

#[test]
fn a_tar_without_the_marker_or_with_another_form_is_not_canonical() {
    let good = canonical(&[entry("./", DIR)]);
    // without the x header of the marker
    assert!(validate_tar(&cat(&[&good[1024..], END])[..]).is_err());
    // the form of the checksum of 7 digits and a NUL
    let mut seven = good.clone();
    let sum = &mut seven[1024 + 148..1024 + 156];
    sum.copy_from_slice(&[sum[0], sum[1], sum[2], sum[3], sum[4], sum[5], 0, 0]);
    assert!(validate_tar(&seven[..]).is_err());
    // GNU magic
    let mut gnu = good.clone();
    gnu[1024 + 257..1024 + 265].copy_from_slice(b"ustar  \0");
    assert!(validate_tar(&gnu[..]).is_err());
    // the marker as a global header
    let mut global = good.clone();
    global[156] = b'g';
    assert!(validate_tar(&global[..]).is_err());
}

#[test]
fn every_byte_of_the_headers_and_the_padding_is_fixed() {
    let mut e = timed(file("./some/file", 5), "2023-11-14T22:13:20.5Z");
    e.uid = 3_000_000;
    let link = {
        let mut l = timed(
            entry("./some/link", TocEntryType::Symlink),
            "2023-11-14T22:13:20.5Z",
        );
        l.link_name = Some("file".into());
        l
    };
    let entries = [entry("./", DIR), e, link, entry("./z/", DIR)];
    let good = canonical(&entries);
    // the bytes that are content or the values of records may change into
    // another canonical stream: the others never
    let mut free = vec![false; good.len()];
    let mut at = 0;
    for e in tar_entries(&entries) {
        let f = fields(e);
        let mut head = Vec::new();
        headers(&f, at == 0, &mut head).unwrap();
        if head[156] == b'x' {
            let n =
                usize::from_str_radix(std::str::from_utf8(&head[124..135]).unwrap(), 8).unwrap();
            free[at + 512..at + 512 + n].fill(true);
        }
        let end = at + head.len();
        free[end..end + f.size as usize].fill(true);
        at = end + f.size.next_multiple_of(512) as usize;
    }
    let mut tried = 0;
    for i in (0..good.len()).filter(|&i| !free[i]) {
        let mut bad = good.clone();
        bad[i] ^= 0x01;
        assert!(validate_tar(&bad[..]).is_err(), "byte {i} is not fixed");
        tried += 1;
    }
    assert!(tried > 3000, "{tried}");
}

#[test]
fn a_header_that_names_more_than_the_rules_allow_is_not_canonical() {
    let mut out = canonical(&[entry("./", DIR), file("./a", 0)]);
    // make the name field not UTF-8 and the checksum right
    out[1536 + 2] = 0xff;
    let sum: u32 = out[1536..2048]
        .iter()
        .enumerate()
        .map(|(i, &b)| u32::from(if (148..156).contains(&i) { b' ' } else { b }))
        .sum();
    out[1536 + 148..1536 + 156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    assert!(not_canonical(&out).contains("UTF-8"));
}

/// `number` reads a field with spaces around the digits, or in base 256; the
/// check of the headers refuses what the writer would spell otherwise.
#[test]
fn a_number_the_writer_never_spells_is_refused() {
    let good = canonical(&[entry("./", DIR), file("./a", 0)]);
    validate_tar(&good[..]).unwrap();
    assert_eq!(&good[1536 + 100..1536 + 108], b"0000644\0");
    for spelling in [
        b" 000644\0",
        b"000644 \0",
        b"0000644 ",
        b"\x80\0\0\0\0\0\x01\xa4",
    ] {
        let mut bad = good.clone();
        bad[1536 + 100..1536 + 108].copy_from_slice(spelling);
        let sum: u32 = bad[1536..2048]
            .iter()
            .enumerate()
            .map(|(i, &b)| u32::from(if (148..156).contains(&i) { b' ' } else { b }))
            .sum();
        bad[1536 + 148..1536 + 156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        let e = not_canonical(&bad);
        assert!(e.contains("the headers are not what the rules make"), "{e}");
    }
}

#[test]
fn a_pax_record_the_rules_never_write_is_refused() {
    let stream = |extra: &[u8]| {
        cat(&[
            &pax(b"a", &cat(&[MARKER_RECORD, extra])),
            &header(
                b"./a",
                "0000644",
                "0000000",
                "0000000",
                "00000000000",
                "00000000000",
                b'0',
                b"",
                None,
            ),
            END,
        ])
    };
    validate_tar(&stream(b"")[..]).unwrap();
    for record in [
        "13 atime=1.5\n",
        "13 uname=bob\n",
        "26 comment=something=else\n",
        "13 charset=a\n",
    ] {
        let e = not_canonical(&stream(record.as_bytes()));
        assert!(e.contains("is not allowed"), "{record}: {e}");
    }
}

/// `pax_time` reads a time the writer never spells (an empty fraction, more
/// than nine digits of it); the check of the headers refuses it all the same.
#[test]
fn a_time_the_writer_never_spells_is_refused() {
    let stream = |record: &[u8]| {
        cat(&[
            &pax(b"a", &cat(&[MARKER_RECORD, record])),
            &header(
                b"./a",
                "0000644",
                "0000000",
                "0000000",
                "00000000000",
                "00000000000",
                b'0',
                b"",
                None,
            ),
            END,
        ])
    };
    validate_tar(&stream(b"12 mtime=-1\n")[..]).unwrap();
    for record in ["13 mtime=-1.\n", "23 mtime=-1.0000000000\n"] {
        let e = not_canonical(&stream(record.as_bytes()));
        assert!(e.contains("the headers are not what the rules make"), "{e}");
    }
}

#[test]
fn the_pax_records_of_an_entry_are_at_most_1_mib() {
    // 16 values of 64 KiB and their keys are more than 1 MiB
    let big = (0..16).fold(file("./a", 0), |e, i| {
        xattr(e, &format!("user.{i:03}"), &[0; 65536])
    });
    assert!(rejected(std::slice::from_ref(&big)).contains("PAX records"));
    let mut small = big;
    small.xattrs.retain(|k, _| k.as_str() < "user.015");
    ok(&[small]);
    // a reader refuses records that large before it reads them
    let mut x = pax(b"a", b"");
    x[124..135].copy_from_slice(format!("{:011o}", MAX_PAX_DATA + 1).as_bytes());
    assert!(not_canonical(&x).contains("too large"));
}

#[test]
fn an_entry_has_at_most_1024_xattrs_and_a_path_4096_bytes() {
    let many = |n: usize| {
        (0..n).fold(file("./a", 0), |e, i| {
            xattr(e, &format!("user.{i:04}"), b"v")
        })
    };
    ok(&[many(1024)]);
    assert!(rejected(&[many(1025)]).contains("more than 1024 xattrs"));
    ok(&[file(&format!("./{}", "a".repeat(4094)), 0)]);
    assert!(rejected(&[file(&format!("./{}", "a".repeat(4095)), 0)]).contains("4096 bytes"));
}

#[test]
fn the_tar_has_the_entries_of_the_table() {
    let entries = [
        entry("./", DIR),
        entry("./a/", DIR),
        file("./a/b", 700),
        timed(file("./a-c", 3), "2001-02-03T04:05:06.789Z"),
    ];
    let out = canonical(&entries);
    let mut archive = ::tar::Archive::new(&out[..]);
    let seen: Vec<_> = archive
        .entries()
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (
                e.path().unwrap().to_string_lossy().into_owned(),
                e.header().size().unwrap(),
                e.header().mode().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            ("./".to_string(), 0, 0o755),
            ("./a/".to_string(), 0, 0o755),
            ("./a/b".to_string(), 700, 0o644),
            ("./a-c".to_string(), 3, 0o644),
        ]
    );
}

#[test]
fn the_reader_gives_the_bytes_write_makes() {
    let entries = vec![
        entry("./", DIR),
        file("./a", 700),
        file("./b", 512),
        entry("./c", REG),
        file("./d", 1),
    ];
    let toc = std::sync::Arc::new(crate::Toc {
        version: crate::TOC_VERSION_CANONICAL,
        entries: entries.clone(),
        tar_split_digest: None,
    });
    assert!(toc.is_canonical());
    for chunk in [1, 7, 512, 100_000] {
        let mut r = reader(toc.clone(), |e| {
            Ok(Box::new(io::Cursor::new(vec![b'x'; e.size as usize])))
        });
        let mut got = Vec::new();
        let mut buf = vec![0; chunk];
        loop {
            let n = r.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, tar(&entries), "reads of {chunk}");
    }
    let mut short = reader(toc, |_| Ok(Box::new(io::Cursor::new(vec![b'x'; 3]))));
    assert!(short.read_to_end(&mut Vec::new()).is_err());
}

#[test]
fn the_skeleton_is_the_tar_with_the_sizes_in_place_of_the_contents() {
    let entries = vec![
        entry("./", DIR),
        file("./a", 700),
        entry("./c", REG),
        file("./d", 513),
    ];
    let mut parts: Vec<(usize, Vec<u8>)> = Vec::new();
    skeleton(&entries, |i, b| match parts.last_mut() {
        Some((j, bytes)) if *j == i => bytes.extend_from_slice(b),
        _ => parts.push((i, b.to_vec())),
    })
    .unwrap();
    assert_eq!(
        parts.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
        [0, 1, 2, 3, 4]
    );
    let all: Vec<u8> = parts.into_iter().flat_map(|(_, b)| b).collect();
    // the tar with each content cut out and its size there
    let full = tar(&entries);
    let mut expected = Vec::new();
    let mut at = 0;
    for e in entries.iter().filter(|e| e.size > 0) {
        let head = super::header(e, false).unwrap().len();
        let before = full[at..]
            .windows(head)
            .position(|w| w == &super::header(e, false).unwrap()[..])
            .unwrap();
        expected.extend_from_slice(&full[at..at + before + head]);
        expected.extend_from_slice(&e.size.to_le_bytes());
        at += before + head + e.size.next_multiple_of(512) as usize;
        expected.extend(vec![0; padding(e.size)]);
    }
    expected.extend_from_slice(&full[at..]);
    assert_eq!(all, expected);
}

#[test]
fn a_tar_larger_than_a_u64_has_no_size() {
    let big = |name: &str| file(name, u64::MAX - 600);
    assert!(stream_size(&[big("./a")]).is_err());
    let half = |name: &str| file(name, u64::MAX / 2);
    assert!(stream_size(&[half("./a")]).is_ok());
    assert!(stream_size(&[half("./a"), half("./b")]).is_err());
}

fn verified(name: &str, size: u64, offset: u64) -> TocEntry {
    let mut e = file(name, size);
    e.fsverity = parse_toc_fsverity(&format!("sha256-12:{}", "ab".repeat(32)));
    e.offset = offset;
    e.end_offset = offset + 1;
    e
}

#[test]
fn a_digest_has_one_size() {
    // the same content under two names, with other modes: a table
    let mut b = verified("./b", 10, 1);
    b.mode = 0o755;
    assert!(validate(&[verified("./a", 10, 1), b]).is_ok());
    // two sizes for one digest
    let e = validate(&[verified("./a", 10, 1), verified("./b", 11, 1)]).unwrap_err();
    assert!(e.to_string().contains("two sizes: 10 and 11"), "{e}");
    assert_eq!(e.index, 1);
    // the same size seen through other chunks is fine, the sum is not
    let mut a = verified("./a", 10, 1);
    a.chunk_size = 4;
    let mut chunk = entry("./a", TocEntryType::Chunk);
    chunk.chunk_offset = 4;
    chunk.chunk_size = 6;
    assert!(validate(&[a.clone(), chunk.clone()]).is_ok());
    chunk.chunk_size = 7;
    assert!(validate(&[a, chunk]).is_err());
}

#[test]
fn a_table_whose_tar_does_not_fit_is_refused() {
    let big = |name: &str, size: u64| {
        let mut e = verified(name, size, 1);
        e.fsverity =
            parse_toc_fsverity(&format!("sha256-12:{}", name.len().to_string().repeat(64)));
        e.digest = None;
        e
    };
    // one file of 2^64-1 bytes, or two of 2^63 bytes, or one that only the
    // padding and the headers make too large
    for table in [
        vec![big("./a", u64::MAX)],
        vec![big("./a", u64::MAX - 1023)],
        vec![big("./a", 1 << 63), big("./bb", 1 << 63)],
    ] {
        let e = validate(&table).unwrap_err();
        assert!(e.to_string().contains("tar is larger"), "{e}");
        assert_eq!(e.index, table.len() - 1);
        assert!(stream_size(&table).is_err());
    }
    // a table that fits has a size, and the bound is the size
    let table = [big("./a", 1 << 40)];
    validate(&table).unwrap();
    let size = stream_size(&table).unwrap();
    validate_within(&table, size).unwrap();
    assert!(validate_within(&table, size - 1).is_err());
}

#[test]
fn what_validate_accepts_has_a_tar() {
    // sizes near the limits of a u64 and of the fields of a header
    let sizes = [
        0,
        1,
        511,
        512,
        MAX_OCTAL_11,
        MAX_OCTAL_11 + 1,
        1 << 40,
        1 << 62,
        (1 << 63) - 1,
        1 << 63,
        u64::MAX - 1023,
        u64::MAX - 511,
        u64::MAX - 1,
        u64::MAX,
    ];
    let mut seed = 0x2545_f491_4f6c_dd1d_u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..3000 {
        let n = 1 + next() % 4;
        let table: Vec<TocEntry> = (0..n)
            .map(|i| {
                let size = match next() % 3 {
                    0 => sizes[(next() % sizes.len() as u64) as usize],
                    1 => u64::MAX - next() % 4096,
                    _ => next() >> (next() % 64),
                };
                let mut e = verified(&format!("./f{i}"), size, 1);
                e.fsverity = parse_toc_fsverity(&format!("sha256-12:{:064x}", i));
                e
            })
            .collect();
        let max = [u64::MAX, 1 << 63, 1 << 40][(next() % 3) as usize];
        if validate_within(&table, max).is_ok() {
            let size = stream_size(&table).unwrap();
            assert!(size <= max);
        }
    }
}

// The walk of the edges: tables of one to three entries over the values at
// the edges of every field.  For each table:
//
// * `validate_entries(T)` holds exactly when `validate_tar(write(T))` does.
//   For a table the headers give back as it is this is nearly the same
//   check twice (`validate_tar` decodes, writes the headers again and runs
//   the checker on the same fields): what it tests is the layout `write`
//   makes of the headers, the contents and the padding.
// * What does not repeat the checker: the headers read back by a decoder
//   of this test give the fields; a table that is accepted is one whose
//   headers read back as it is; the length `stream_size` gives is the
//   bytes of `write`, of `reader` and, with the contents in place of their
//   sizes, of `skeleton`; the tar of a table that is refused and is still
//   accepted by `validate_tar` is the tar of another table the rules
//   accept.

/// A name of `len` bytes with the `./` and for a directory its `/`, with a
/// `/` in the middle when `split`.
fn named(len: usize, split: bool, dir: bool) -> String {
    let mut name = format!("./{}", "a".repeat(len - 2));
    if split {
        name.replace_range(len / 2..len / 2 + 1, "/");
    }
    if dir {
        name.replace_range(len - 1.., "/");
    }
    name
}

/// What a name or a target can be at the edges of the 100 bytes of the
/// header and beyond them: the cut is inside a character, and 155 bytes
/// is where a ustar prefix would end.
fn edge_names(dir: bool) -> Vec<String> {
    let mut v = Vec::new();
    for len in [99, 100, 101, 155, 156, 257] {
        for split in [false, true] {
            v.push(named(len, split, dir));
        }
    }
    if !dir {
        v.push(format!("./{}é", "a".repeat(97)));
    }
    // the last component the name of an `x` header is cut to, and the
    // longest path there is
    for len in [87, 88] {
        v.push(format!(
            "./{}{}",
            "a".repeat(len),
            if dir { "/" } else { "" }
        ));
    }
    for len in [MAX_PATH, MAX_PATH + 1] {
        v.push(named(len, false, dir));
    }
    v
}

const EDGE_IDS: [u32; 4] = [MAX_ID_FIELD, MAX_ID_FIELD + 1, MAX_ID_FIELD + 2, u32::MAX];
const EDGE_MODES: [u32; 7] = [
    0,
    0o644,
    0o7777,
    0o10000,
    0o7_777_777,
    0o10_000_000,
    u32::MAX,
];
const EDGE_SIZES: [u64; 5] = [0, 1, 511, 512, 513];
const BIG_SIZES: [u64; 2] = [MAX_OCTAL_11, MAX_OCTAL_11 + 1];
const EDGE_SECS: [i64; 8] = [
    -1,
    0,
    1,
    MAX_OCTAL_11 as i64,
    MAX_OCTAL_11 as i64 + 1,
    FIRST_TIME,
    FIRST_TIME - 1,
    LAST_TIME,
];
const EDGE_NANOS: [u32; 3] = [0, 1, 500_000_000];
const EDGE_DEVICES: [(u32, u32); 7] = [
    (0, 1),
    (1, 0),
    (MAX_DEVICE, 0),
    (0, MAX_DEVICE),
    (MAX_DEVICE, MAX_DEVICE),
    (MAX_DEVICE + 1, 0),
    (0, MAX_DEVICE + 1),
];

fn at(secs: i64, nanos: u32) -> String {
    chrono::DateTime::from_timestamp(secs, nanos)
        .unwrap()
        .to_rfc3339()
}

/// The entry of a kind that has every field in the rules.
fn plain(kind: TocEntryType) -> TocEntry {
    let name = if kind == DIR { "./e/" } else { "./e" };
    let mut e = entry(name, kind);
    match kind {
        TocEntryType::Symlink => e.link_name = Some("t".into()),
        TocEntryType::Char | TocEntryType::Block => (e.dev_major, e.dev_minor) = (Some(1), Some(2)),
        _ => {}
    }
    e
}

/// `plain` and then each field alone at each of its edges, and what the
/// rules refuse at them.
fn varied(kind: TocEntryType) -> Vec<TocEntry> {
    let mut v = vec![plain(kind)];
    let mut vary = |f: &dyn Fn(&mut TocEntry)| {
        let mut e = plain(kind);
        f(&mut e);
        v.push(e);
    };
    for n in edge_names(kind == DIR) {
        vary(&|e| e.name = n.clone());
    }
    for id in EDGE_IDS {
        vary(&|e| e.uid = id);
        vary(&|e| e.gid = id);
    }
    for m in EDGE_MODES {
        vary(&|e| e.mode = m);
    }
    for s in EDGE_SIZES {
        vary(&|e| e.size = s);
    }
    vary(&|e| e.size = 1);
    for secs in EDGE_SECS {
        for nanos in EDGE_NANOS {
            vary(&|e| e.mod_time = Some(at(secs, nanos)));
        }
    }
    vary(&|e| e.mod_time = Some(at(LAST_TIME + 1, 0)));
    vary(&|e| e.mod_time = Some("not a time".into()));
    for d in EDGE_DEVICES.into_iter().chain([(0, 0)]) {
        vary(&|e| (e.dev_major, e.dev_minor) = (Some(d.0), Some(d.1)));
    }
    vary(&|e| e.dev_major = Some(1));
    // the length of a PAX record that has one digit more than a value
    // shorter by one byte: 99 and 100, 999 and 1000
    for n in [74, 75, 76, 973, 974, 975] {
        vary(&|e| *e = xattr(e.clone(), "user.a", &vec![b'v'; n]));
    }
    for x in [
        &[][..],
        &[("user.a", &b""[..])],
        &[("user.a", b"v"), ("user.b", b"\n\0\xff")],
        &[("user.a=b", b"v")],
        &[("", b"v")],
        &[("trusted.overlay.x", b"v")],
    ] {
        vary(&|e| {
            for (k, val) in x {
                *e = xattr(e.clone(), k, val);
            }
        });
    }
    for l in ["", "a\0b"] {
        vary(&|e| e.link_name = Some(l.into()));
    }
    vary(&|e| e.link_name = Some("t".into()));
    if kind == TocEntryType::Symlink {
        for l in edge_names(false) {
            vary(&|e| e.link_name = Some(l.clone()));
        }
    }
    v
}

/// What `headers` gives back when it is read as the stream does.
fn read_back(head: &[u8]) -> Result<Fields, String> {
    let (pax, block) = if head[156] == b'x' {
        let size = header_number(&head[124..136], "the size")? as usize;
        let end = BLOCK + size.next_multiple_of(BLOCK);
        (parse_pax(&head[BLOCK..BLOCK + size])?, &head[end..])
    } else {
        (Pax::default(), head)
    };
    decode(block.try_into().expect("one block"), &pax)
}

/// The entries of a canonical tar as its headers say them, the contents
/// skipped.
fn decode_tar(tar: &[u8]) -> Vec<Fields> {
    let mut entries = Vec::new();
    let mut at = 0;
    while tar[at..at + BLOCK] != [0; BLOCK] {
        let end = if tar[at + 156] == b'x' {
            let size = header_number(&tar[at + 124..at + 136], "the size").unwrap() as usize;
            at + 2 * BLOCK + size.next_multiple_of(BLOCK)
        } else {
            at + BLOCK
        };
        let f = read_back(&tar[at..end]).unwrap();
        at = end + f.size.next_multiple_of(BLOCK as u64) as usize;
        entries.push(f);
    }
    entries
}

/// The entry of a table of contents that has the fields.
fn entry_of(f: &Fields) -> TocEntry {
    let mut e = TocEntry::new(f.name.clone(), f.kind);
    (e.mode, e.uid, e.gid, e.size) = (f.mode, f.uid, f.gid, f.size);
    e.link_name = f.link.clone();
    e.mod_time = Some(at(f.mtime.0, f.mtime.1));
    (e.dev_major, e.dev_minor) = (Some(f.device.0), Some(f.device.1));
    for (k, v) in &f.xattrs {
        e = xattr(e, k, v);
    }
    e
}

/// The bytes a reader gives, counted.
struct Counting<R>(R, u64);

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.0.read(buf)?;
        self.1 += n as u64;
        Ok(n)
    }
}

fn zeros_reader(entries: &[TocEntry]) -> impl Read + Send {
    let toc = std::sync::Arc::new(crate::Toc {
        version: crate::TOC_VERSION_CANONICAL,
        entries: entries.to_vec(),
        tar_split_digest: None,
    });
    reader(toc, |e| Ok(Box::new(io::repeat(0).take(e.size))))
}

/// The bytes of the tar by the parts of `skeleton`, with each content of
/// its size in place of the 8 bytes of it.
fn skeleton_size(entries: &[TocEntry]) -> u64 {
    let mut n = 0;
    skeleton(entries, |_, b| n += b.len() as u64).unwrap();
    let content = |e: &&TocEntry| e.size > 0 && e.entry_type == REG;
    let contents: Vec<u64> = tar_entries(entries)
        .filter(content)
        .map(|e| e.size)
        .collect();
    n - 8 * contents.len() as u64 + contents.iter().sum::<u64>()
}

#[derive(Default)]
struct Walk {
    tables: usize,
    faithful: usize,
    aliased: usize,
    accepted: usize,
}

impl Walk {
    fn table(&mut self, t: &[TocEntry]) {
        self.tables += 1;
        let what = || {
            t.iter()
                .map(|e| format!("{e:?}"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let accepted = validate_entries(t).is_ok();
        let Ok(size) = stream_size(t) else {
            // a time that is not RFC 3339 or a number too wide for its field
            // has no header: no function gives bytes, and the rules refuse it
            assert!(!accepted, "{}", what());
            assert!(write(t, io::sink(), |_, _| Ok(())).is_err(), "{}", what());
            return;
        };
        assert_eq!(skeleton_size(t), size, "skeleton of\n{}", what());
        let small = t.iter().all(|e| e.size < 1 << 20);
        let mut tar = Vec::new();
        let ok = if small {
            write(t, &mut tar, |e, o| o.write_all(&vec![0; e.size as usize])).unwrap();
            let mut streamed = Vec::new();
            zeros_reader(t).read_to_end(&mut streamed).unwrap();
            assert_eq!(tar, streamed, "reader of\n{}", what());
            assert_eq!(tar.len() as u64, size, "write of\n{}", what());
            validate_tar(&tar[..]).is_ok()
        } else {
            let mut counted = Counting(zeros_reader(t), 0);
            let ok = validate_tar(&mut counted).is_ok();
            if ok {
                assert_eq!(counted.1, size, "reader of\n{}", what());
            }
            ok
        };
        // what the headers give back is the entry, or the table is refused
        // (the headers do not tell two entries apart that the rules refuse:
        // see `the_tar_of_a_refused_table_can_be_the_tar_of_another`)
        let faithful = t
            .iter()
            .enumerate()
            .all(|(i, e)| read_back(&super::header(e, i == 0).unwrap()).as_ref() == Ok(&fields(e)));
        assert!(faithful || !accepted, "{}", what());
        if faithful {
            assert_eq!(
                ok,
                accepted,
                "validate_tar and validate_entries of\n{}",
                what()
            );
        }
        if !faithful && ok {
            // its tar is the canonical tar of another table, which the
            // rules accept and which has this very tar
            let other: Vec<TocEntry> = decode_tar(&tar).iter().map(entry_of).collect();
            assert!(validate_entries(&other).is_ok(), "{}", what());
            let mut again = Vec::new();
            write(&other, &mut again, |e, o| {
                o.write_all(&vec![0; e.size as usize])
            })
            .unwrap();
            assert_eq!(again, tar, "{}", what());
            self.aliased += 1;
        }
        self.faithful += usize::from(faithful);
        self.accepted += usize::from(accepted);
    }

    /// A table that has a content too large to stream: the rules accept it
    /// and `stream_size` is the length `skeleton` gives.
    fn measured(&mut self, t: &[TocEntry]) {
        self.tables += 1;
        self.accepted += 1;
        assert!(validate_entries(t).is_ok());
        assert_eq!(skeleton_size(t), stream_size(t).unwrap());
    }

    /// The entry alone, as the first, and in the middle of a table of three.
    fn positions(&mut self, e: &TocEntry) {
        let root = entry("./", DIR);
        self.table(std::slice::from_ref(e));
        self.table(&[root.clone(), e.clone()]);
        self.table(&[root, e.clone(), file("./z", 0)]);
    }

    /// The entry, and a hard link to it.
    fn linked(&mut self, e: &TocEntry, name: &str) {
        let mut l = TocEntry::new(name, TocEntryType::Hardlink);
        (l.mode, l.uid, l.gid, l.mod_time) = (e.mode, e.uid, e.gid, e.mod_time.clone());
        l.link_name = Some(e.name.clone());
        self.table(&[e.clone(), l.clone()]);
        self.table(&[entry("./", DIR), e.clone(), l]);
    }
}

#[test]
fn the_edges_of_every_field_agree_in_the_rules_the_bytes_and_the_headers() {
    let start = std::time::Instant::now();
    let mut w = Walk::default();
    let kinds = [
        REG,
        DIR,
        TocEntryType::Symlink,
        TocEntryType::Char,
        TocEntryType::Block,
        TocEntryType::Fifo,
    ];
    for kind in kinds {
        for e in varied(kind) {
            w.positions(&e);
            if kind != DIR {
                w.linked(&e, "./z");
            }
        }
    }
    // the names of the link and of what it links to
    for n in edge_names(false) {
        w.linked(&file("./e", 1), &n);
    }
    // a hard link of other metadata than its target's, to a directory
    let mut other = TocEntry::new("./z", TocEntryType::Hardlink);
    other.link_name = Some("./e".into());
    w.table(&[file("./e", 0), other.clone()]);
    other.link_name = Some("./e/".into());
    w.table(&[entry("./e/", DIR), other]);
    // every field at once, for a regular file
    for name in edge_names(false).iter().step_by(3) {
        for uid in EDGE_IDS.iter().take(3) {
            for gid in EDGE_IDS.iter().take(3) {
                for mode in [0o644, 0o7777, 0o10000] {
                    for secs in &EDGE_SECS[..5] {
                        for nanos in &EDGE_NANOS[..2] {
                            for xs in 0..3 {
                                let mut e = file(name, 0);
                                (e.uid, e.gid, e.mode) = (*uid, *gid, mode);
                                e.mod_time = Some(at(*secs, *nanos));
                                for x in 0..xs {
                                    e = xattr(e, &format!("user.x{x}"), b"v");
                                }
                                w.positions(&e);
                            }
                        }
                    }
                }
            }
        }
    }
    // the sizes of the contents
    for size in EDGE_SIZES {
        w.positions(&file("./big", size));
        w.table(&[file("./a", 513), file("./b", size)]);
    }
    // the largest are zeros read and not held: a table of one entry has
    // them streamed, the others are only measured
    for size in BIG_SIZES {
        w.table(&[file("./big", size)]);
        w.measured(&[entry("./", DIR), file("./big", size), file("./z", 513)]);
    }
    eprintln!(
        "{} tables, {} faithful, {} accepted, {} of another table, {:?}",
        w.tables,
        w.faithful,
        w.accepted,
        w.aliased,
        start.elapsed()
    );
}

// What the walk found on today's code, each pinned as it is.

#[test]
fn a_size_of_a_directory_is_no_content_for_any_function() {
    // a table that the rules refuse: the content is of regular files only,
    // in the length and in the bytes
    let mut d = entry("./d/", DIR);
    d.size = 5;
    let entries = [d];
    let mut out = Vec::new();
    write(&entries, &mut out, content).unwrap();
    let mut streamed = Vec::new();
    zeros_reader(&entries).read_to_end(&mut streamed).unwrap();
    assert_eq!(out, streamed);
    assert_eq!(skeleton_size(&entries), out.len() as u64);
    assert_eq!(stream_size(&entries).unwrap(), out.len() as u64);
    assert!(validate_entries(&entries).is_err());
}

#[test]
fn the_tar_of_a_refused_table_can_be_the_tar_of_another() {
    // The headers do not tell two tables apart when the rules refuse one:
    // a regular file with device numbers has the tar of the same file
    // without them, and the xattr `user.a=b` of the value `v` has the tar
    // of the xattr `user.a` of the value `b=v`.  `validate_tar` says yes to
    // these tars, as they are canonical, and the walk checks that the table
    // it finds in a tar is always one the rules accept.
    let mut stray = file("./e", 0);
    (stray.dev_major, stray.dev_minor) = (Some(0), Some(1));
    let equal = xattr(file("./e", 0), "user.a=b", b"v");
    for (refused, other) in [
        (stray, file("./e", 0)),
        (equal, xattr(file("./e", 0), "user.a", b"b=v")),
    ] {
        assert!(validate_entries(std::slice::from_ref(&refused)).is_err());
        assert!(validate_entries(std::slice::from_ref(&other)).is_ok());
        assert_eq!(tar(&[refused]), canonical(&[other]));
    }
}

#[test]
fn a_number_too_wide_for_its_field_is_an_error() {
    let wide = |f: &dyn Fn(&mut TocEntry)| {
        let mut e = plain(TocEntryType::Char);
        f(&mut e);
        let entries = [e];
        assert!(super::header(&entries[0], false).is_err());
        assert!(stream_size(&entries).is_err());
        assert!(write(&entries, io::sink(), content).is_err());
        assert!(zeros_reader(&entries).read_to_end(&mut Vec::new()).is_err());
        assert!(skeleton(&entries, |_, _| {}).is_err());
        assert!(validate_entries(&entries).is_err());
    };
    wide(&|e| e.mode = 0o10_000_000);
    wide(&|e| e.mode = u32::MAX);
    wide(&|e| e.dev_major = Some(MAX_DEVICE + 1));
    wide(&|e| e.dev_minor = Some(MAX_DEVICE + 1));
}

#[test]
fn a_tar_with_bytes_changed_is_checked_without_a_panic() {
    use rand::{Rng, SeedableRng};
    let mut l = TocEntry::new("./l", TocEntryType::Symlink);
    l.link_name = Some("a".repeat(120));
    let mut dev = TocEntry::new("./n", TocEntryType::Char);
    (dev.dev_major, dev.dev_minor) = (Some(1), Some(2));
    let mut big = file("./z", 3);
    (big.uid, big.mod_time) = (u32::MAX, Some("1969-12-31T23:59:58.5Z".into()));
    let seed = tar(&[
        entry("./", DIR),
        file("./a", 3),
        xattr(l, "user.k", b"v"),
        dev,
        big,
    ]);
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x7a_c0);
    for _ in 0..5_000 {
        let mut d = seed.clone();
        for _ in 0..rng.gen_range(1..4) {
            if rng.gen() {
                // a number of a header of 8 digits
                let block = rng.gen_range(0..d.len() / BLOCK) * BLOCK;
                let at = block + [100, 108, 116, 329, 337][rng.gen_range(0..5)];
                d[at..at + 8].fill(b'7');
            } else {
                let at = rng.gen_range(0..d.len());
                d[at] = if rng.gen() {
                    rng.gen()
                } else {
                    b'0' + rng.gen_range(0..8)
                };
            }
        }
        let _ = validate_tar(&d[..]);
    }
}

#[test]
fn a_mode_of_8_digits_in_a_tar_is_not_canonical() {
    // what the random test found in the debug_assert of the header: the
    // mode of the header of `./a` is 77777777
    let mut d = tar(&[entry("./", DIR), file("./a", 3)]);
    d[2 * BLOCK + 100..2 * BLOCK + 108].fill(b'7');
    assert!(not_canonical(&d).contains("does not fit"));
}
