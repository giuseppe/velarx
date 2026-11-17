// SPDX-License-Identifier: Apache-2.0
//! The statistics CRIU writes in the directory of its images, `stats-dump`
//! after a dump and `stats-restore` after a restore: a magic number, the
//! magic of the statistics, the size of the payload (little endian, 4 bytes
//! each) and a protobuf message `stats_entry` (`dump` is the field 1,
//! `restore` the field 2).  Only the fields podman reports are read, by a
//! small decoder of the wire format.

use std::io;
use std::path::Path;
use velarx_proto::workload::CriuStatistics;

pub const STATS_DUMP: &str = "stats-dump";
pub const STATS_RESTORE: &str = "stats-restore";

const IMG_SERVICE_MAGIC: u32 = 0x5510_5940;
const STATS_MAGIC: u32 = 0x5709_3306;
const HEADER: usize = 12;

fn invalid(m: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.to_string())
}

fn varint(buf: &mut &[u8]) -> io::Result<u64> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let (&b, rest) = buf
            .split_first()
            .ok_or_else(|| invalid("truncated varint"))?;
        *buf = rest;
        v |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err(invalid("varint too long"))
}

/// The fields of a message: `f` gets the number of each and its value (the
/// varint, or for a field with a length its bytes in `bytes`).
fn fields(mut buf: &[u8], mut f: impl FnMut(u64, u64, &[u8])) -> io::Result<()> {
    while !buf.is_empty() {
        let tag = varint(&mut buf)?;
        let (number, wire) = (tag >> 3, tag & 7);
        let take = |buf: &mut &[u8], n: usize| -> io::Result<()> {
            if buf.len() < n {
                return Err(invalid("truncated field"));
            }
            *buf = &buf[n..];
            Ok(())
        };
        match wire {
            0 => f(number, varint(&mut buf)?, &[]),
            2 => {
                let len = usize::try_from(varint(&mut buf)?).map_err(|_| invalid("field size"))?;
                let bytes = buf.get(..len).ok_or_else(|| invalid("truncated field"))?;
                f(number, 0, bytes);
                take(&mut buf, len)?;
            }
            1 => take(&mut buf, 8)?,
            5 => take(&mut buf, 4)?,
            _ => return Err(invalid("unknown wire type")),
        }
    }
    Ok(())
}

/// The statistics of a file of CRIU's (`STATS_DUMP` or `STATS_RESTORE`) in
/// `dir`: the numbers podman reports of it.
pub fn read(dir: &Path, file: &str) -> io::Result<CriuStatistics> {
    let buf = std::fs::read(dir.join(file))?;
    parse(&buf, file == STATS_RESTORE)
}

fn parse(buf: &[u8], restore: bool) -> io::Result<CriuStatistics> {
    let word = |at: usize| -> io::Result<u32> {
        buf.get(at..at + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or_else(|| invalid("truncated header"))
    };
    if word(0)? != IMG_SERVICE_MAGIC {
        return Err(invalid("primary magic not found"));
    }
    if word(4)? != STATS_MAGIC {
        return Err(invalid("secondary magic not found"));
    }
    let size = word(8)? as usize;
    let payload = buf
        .get(HEADER..HEADER.saturating_add(size))
        .ok_or_else(|| invalid("truncated payload"))?;
    let mut s = CriuStatistics::default();
    let mut inner = Ok(());
    fields(payload, |number, _, entry| {
        if number == if restore { 2 } else { 1 } {
            // (the fields are unsigned 32 or 64 bits: the times and the
            // counts)
            inner = fields(entry, |n, v, _| {
                if restore {
                    match n {
                        1 => s.pages_compared = v,
                        2 => s.pages_skipped_cow = v,
                        3 => s.forking_time = v as u32,
                        4 => s.restore_time = v as u32,
                        5 => s.pages_restored = v,
                        _ => {}
                    }
                } else {
                    match n {
                        1 => s.freezing_time = v as u32,
                        2 => s.frozen_time = v as u32,
                        3 => s.memdump_time = v as u32,
                        4 => s.memwrite_time = v as u32,
                        5 => s.pages_scanned = v,
                        7 => s.pages_written = v,
                        _ => {}
                    }
                }
            });
        }
    })?;
    inner.map(|()| s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A statistics file with `message` as its entry number `entry`.
    fn file(entry: u64, message: &[u8]) -> Vec<u8> {
        let mut payload = vec![((entry << 3) | 2) as u8, message.len() as u8];
        payload.extend_from_slice(message);
        let mut v = Vec::new();
        v.extend_from_slice(&IMG_SERVICE_MAGIC.to_le_bytes());
        v.extend_from_slice(&STATS_MAGIC.to_le_bytes());
        v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        v.extend_from_slice(&payload);
        v
    }

    /// The files CRIU 4.2 wrote for a container of this host (podman showed
    /// the same numbers for them).
    const REAL_DUMP: [u8; 46] = [
        0x40, 0x59, 0x10, 0x55, 0x06, 0x33, 0x09, 0x57, 0x22, 0x00, 0x00, 0x00, 0x0a, 0x20, 0x08,
        0xe8, 0x02, 0x10, 0xe1, 0xa6, 0x03, 0x18, 0x87, 0x04, 0x20, 0x41, 0x28, 0x36, 0x30, 0x00,
        0x38, 0x23, 0x40, 0x00, 0x48, 0x00, 0x50, 0x08, 0x58, 0x08, 0x60, 0x00, 0x68, 0x00, 0x70,
        0x00,
    ];
    const REAL_RESTORE: [u8; 27] = [
        0x40, 0x59, 0x10, 0x55, 0x06, 0x33, 0x09, 0x57, 0x0f, 0x00, 0x00, 0x00, 0x12, 0x0d, 0x08,
        0x00, 0x10, 0x00, 0x18, 0xbe, 0x01, 0x20, 0xb0, 0xc9, 0x01, 0x28, 0x23,
    ];

    #[test]
    fn the_files_of_criu_are_read() {
        let d = parse(&REAL_DUMP, false).unwrap();
        assert_eq!(
            (
                d.freezing_time,
                d.frozen_time,
                d.memdump_time,
                d.memwrite_time,
                d.pages_scanned,
                d.pages_written
            ),
            (360, 54113, 519, 65, 54, 35)
        );
        let r = parse(&REAL_RESTORE, true).unwrap();
        assert_eq!(
            (
                r.forking_time,
                r.restore_time,
                r.pages_restored,
                r.pages_compared
            ),
            (190, 25776, 35, 0)
        );
        // from a directory, by the name of the file
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(STATS_DUMP), REAL_DUMP).unwrap();
        assert_eq!(read(dir.path(), STATS_DUMP).unwrap(), d);
        assert!(read(dir.path(), STATS_RESTORE).is_err());
    }

    #[test]
    fn a_dump_is_read_by_field_number() {
        // freezing 383, frozen 58214 (a two byte varint and a three byte
        // one), scanned 55, skipped 0, written 35, an unknown fixed32
        let message = [
            0x08, 0xff, 0x02, 0x10, 0xe6, 0xc6, 0x03, 0x28, 55, 0x30, 0, 0x38, 35, 0x85, 0x01, 1,
            2, 3, 4,
        ];
        let s = parse(&file(1, &message), false).unwrap();
        assert_eq!(
            (
                s.freezing_time,
                s.frozen_time,
                s.pages_scanned,
                s.pages_written
            ),
            (383, 58214, 55, 35)
        );
        assert_eq!(s.memdump_time, 0);
        // (the restore half is not asked of a dump)
        assert_eq!(s.pages_restored, 0);
        assert_eq!(
            serde_json::to_string(&s).unwrap(),
            r#"{"freezing_time":383,"frozen_time":58214,"pages_scanned":55,"pages_written":35}"#
        );
    }

    #[test]
    fn a_restore_is_read_and_a_bad_file_is_refused() {
        let message = [
            0x08, 0, 0x10, 0, 0x18, 0xd7, 0x01, 0x20, 0xa0, 0x02, 0x28, 36,
        ];
        let s = parse(&file(2, &message), true).unwrap();
        assert_eq!(
            (
                s.forking_time,
                s.restore_time,
                s.pages_restored,
                s.pages_compared
            ),
            (215, 288, 36, 0)
        );
        // a dump has no restore entry
        assert_eq!(
            parse(&file(1, &message), true).unwrap(),
            CriuStatistics::default()
        );
        let mut bad = file(1, &message);
        bad[0] ^= 1;
        assert!(parse(&bad, false)
            .unwrap_err()
            .to_string()
            .contains("primary"));
        bad = file(1, &message);
        bad[4] ^= 1;
        assert!(parse(&bad, false)
            .unwrap_err()
            .to_string()
            .contains("secondary"));
        let short = file(1, &message);
        assert!(parse(&short[..short.len() - 3], false).is_err());
        assert!(parse(&short[..6], false).is_err());
        // a varint that does not end
        assert!(parse(&file(1, &[0x08, 0xff, 0xff]), false).is_err());
    }
}
