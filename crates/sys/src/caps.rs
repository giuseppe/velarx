// SPDX-License-Identifier: Apache-2.0
//! Capabilities of the process.

use std::io;

#[repr(C)]
struct Header {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct Data {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const CAP_V3: u32 = 0x2008_0522;

const CAP_SETPCAP: u32 = 8;

/// The number of the last capability the kernel has (what
/// `/proc/sys/kernel/cap_last_cap` says, found without `/proc`): the
/// bounding set is read capability by capability until the kernel answers
/// `EINVAL`.
pub fn last_cap() -> io::Result<u32> {
    let mut cap = 0u32;
    loop {
        // SAFETY: prctl with integer arguments only.
        let rc = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap as libc::c_ulong, 0, 0, 0) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            return match (e.raw_os_error(), cap) {
                (Some(libc::EINVAL), 1..) => Ok(cap - 1),
                _ => Err(e),
            };
        }
        cap += 1;
    }
}

/// Whether the process may drop capabilities from its bounding set.
fn may_drop_bounding() -> io::Result<bool> {
    let header = Header {
        version: CAP_V3,
        pid: 0,
    };
    let mut data = [Data::default(); 2];
    // SAFETY: capget writes two data structures of the layout the kernel
    // documents for version 3, both alive for the call.
    let rc = unsafe { libc::syscall(libc::SYS_capget, &header, data.as_mut_ptr()) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(data[0].effective & (1 << CAP_SETPCAP) != 0)
}

/// Take every capability but those `keep` returns true for out of the
/// bounding set.  A process without `CAP_SETPCAP` cannot drop any: what it
/// has in the set it keeps, and that is not an error (no capability can come
/// back to it with the set it has), but a process that may and cannot is.
pub fn drop_bounding_except(keep: impl Fn(u32) -> bool) -> io::Result<()> {
    let last_cap = last_cap()?;
    let may = may_drop_bounding()?;
    for cap in (0..=last_cap).filter(|&c| !keep(c)) {
        // SAFETY: prctl with integer arguments only.
        let held = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap as libc::c_ulong, 0, 0, 0) };
        if held < 0 {
            return Err(io::Error::last_os_error());
        }
        if held == 0 || !may {
            continue;
        }
        // SAFETY: prctl with integer arguments only.
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Empty the ambient set.
pub fn clear_ambient() -> io::Result<()> {
    // SAFETY: prctl with integer arguments only.
    let rc = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Give up every capability: out of the bounding set (what cannot be
/// dropped without `CAP_SETPCAP` is not an error), out of the ambient set,
/// and out of the effective, permitted and inheritable sets of the
/// process.
pub fn drop_all() -> io::Result<()> {
    drop_bounding_except(|_| false)?;
    clear_ambient()?;
    let header = Header {
        version: CAP_V3,
        pid: 0,
    };
    let data = [Data::default(); 2];
    // SAFETY: capset reads a header and two data structures of the layout
    // the kernel documents for version 3, all alive for the call.
    let rc = unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_last_capability_is_what_the_kernel_says() {
        let said: u32 = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(last_cap().unwrap(), said);
    }
}
