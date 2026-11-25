// SPDX-License-Identifier: Apache-2.0
//! Sizes as Go's go-units reads them: the grammar is `velarx_limit_core::parse_size`.

/// go-units' `RAMInBytes`, the size grammar of podman's flags (memory, device
/// rates, shm size): a decimal number, an optional space, an optional unit
/// `b`, `k`, `m`, `g`, `t` or `p` (any case, with an optional `i` and `b`) in
/// powers of 1024.  `Err` is Go's message for what it refuses.  (The size
/// options of `containers.conf` and of the log driver have grammars of their
/// own: `velarx_config::{parse_size, log_opt_size}`.)
pub fn ram_in_bytes(size: &str) -> Result<i64, String> {
    use velarx_limit_core::{parse_size, SizeError};
    parse_size(size.as_bytes()).map_err(|e| match e {
        SizeError::Invalid => format!("invalid size: '{size}'"),
        SizeError::Number(end) => {
            format!(
                "strconv.ParseFloat: parsing {:?}: invalid syntax",
                &size[..end]
            )
        }
        SizeError::Suffix(at) => format!("invalid suffix: '{}'", size[at..].to_ascii_lowercase()),
    })
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
