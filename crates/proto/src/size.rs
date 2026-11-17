// SPDX-License-Identifier: Apache-2.0
//! Sizes as Go's go-units reads them.

/// go-units' `RAMInBytes`, the size grammar of podman's flags (memory, device
/// rates, shm size): a decimal number, an optional space, an optional unit
/// `b`, `k`, `m`, `g`, `t` or `p` (any case, with an optional `i` and `b`) in
/// powers of 1024.  `Err` is Go's message for what it refuses.  (The size
/// options of `containers.conf` and of the log driver have grammars of their
/// own: `velarx_config::{parse_size, log_opt_size}`.)
pub fn ram_in_bytes(size: &str) -> Result<i64, String> {
    // (a size that does not fit saturates in the conversion: refused)
    match go_ram_in_bytes(size)? {
        i64::MAX => Err(format!("invalid size: '{size}'")),
        n => Ok(n),
    }
}

fn go_ram_in_bytes(size: &str) -> Result<i64, String> {
    let invalid = || format!("invalid size: '{size}'");
    let sep = size
        .rfind(|c: char| "0123456789. ".contains(c))
        .ok_or_else(invalid)?;
    let (num, sfx) = if size.as_bytes()[sep] != b' ' {
        (&size[..=sep], &size[sep + 1..])
    } else {
        (&size[..sep], &size[sep + 1..])
    };
    let value: f64 = num
        .parse()
        .map_err(|_| format!("strconv.ParseFloat: parsing {num:?}: invalid syntax"))?;
    if value < 0.0 {
        return Err(invalid());
    }
    if sfx.is_empty() {
        return Ok(value as i64);
    }
    let lower = sfx.to_ascii_lowercase();
    let bad = || format!("invalid suffix: '{lower}'");
    let bytes = lower.as_bytes();
    if bytes.len() > 3 {
        return Err(bad());
    }
    if bytes[0] == b'b' {
        return if bytes.len() > 1 {
            Err(bad())
        } else {
            Ok(value as i64)
        };
    }
    let shift = match bytes[0] {
        b'k' => 10,
        b'm' => 20,
        b'g' => 30,
        b't' => 40,
        b'p' => 50,
        _ => return Err(bad()),
    };
    match bytes.len() {
        2 if bytes[1] != b'b' => return Err(bad()),
        3 if &lower[1..] != "ib" => return Err(bad()),
        _ => {}
    }
    Ok((value * (1u64 << shift) as f64) as i64)
}

#[cfg(test)]
mod tests {
    use super::ram_in_bytes;

    #[test]
    fn sizes_are_ram_in_bytes() {
        assert_eq!(ram_in_bytes("512"), Ok(512));
        assert_eq!(ram_in_bytes("512b"), Ok(512));
        assert_eq!(ram_in_bytes("64k"), Ok(64 << 10));
        assert_eq!(ram_in_bytes("1.5g"), Ok(3 << 29));
        assert_eq!(ram_in_bytes("512 MiB"), Ok(512 << 20));
        assert_eq!(ram_in_bytes("2gb"), Ok(2 << 30));
        assert_eq!(ram_in_bytes("1t"), Ok(1 << 40));
        assert!(ram_in_bytes("1x").is_err());
        assert!(ram_in_bytes("1kx").is_err());
        assert!(ram_in_bytes("").is_err());
        assert!(ram_in_bytes("-1").is_err());
        assert!(ram_in_bytes("99999999999999999999t").is_err());
    }
}
