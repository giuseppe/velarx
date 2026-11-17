// SPDX-License-Identifier: Apache-2.0
//! Facts about the machine.

/// The processors online (`sysconf(_SC_NPROCESSORS_ONLN)`), at least 1.
pub fn online_cpus() -> i64 {
    // SAFETY: sysconf takes an integer and has no preconditions.
    unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) }.max(1)
}

/// The page size (`sysconf(_SC_PAGESIZE)`), which the C library took from
/// the aux vector at startup: no system call and no file, so it works
/// inside the sandboxes (rustix reads the aux vector lazily with
/// `prctl(PR_GET_AUXV)` and `/proc/self/auxv`, both refused once confined).
pub fn page_size() -> usize {
    // SAFETY: sysconf takes an integer and has no preconditions.
    usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap_or(4096)
}

#[cfg(test)]
mod tests {
    #[test]
    fn there_is_a_processor() {
        assert!(super::online_cpus() >= 1);
    }

    #[test]
    fn the_page_size_is_a_power_of_two() {
        assert!(super::page_size().is_power_of_two());
    }
}
