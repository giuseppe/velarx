// SPDX-License-Identifier: Apache-2.0
//! Functions of the C library that have no safe equivalent.

/// A broken-down local time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalTime {
    /// 0 to 11
    pub month: i32,
    pub day: i32,
    pub hour: i32,
    pub minute: i32,
    pub second: i32,
}

/// The local time now (`None` when the C library cannot tell).
pub fn local_time() -> Option<LocalTime> {
    // SAFETY: time with a null pointer only returns the time.
    let t = unsafe { libc::time(std::ptr::null_mut()) };
    // SAFETY: an all-zero tm is valid (null zone pointer included).
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: localtime_r reads `t` and fills `tm`, both live for the call.
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        return None;
    }
    Some(LocalTime {
        month: tm.tm_mon,
        day: tm.tm_mday,
        hour: tm.tm_hour,
        minute: tm.tm_min,
        second: tm.tm_sec,
    })
}

fn lookup_name(
    lookup: impl FnOnce(*mut libc::c_char, usize, &mut Option<String>) -> libc::c_int,
) -> Option<String> {
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut name = None;
    (lookup(buf.as_mut_ptr(), buf.len(), &mut name) == 0).then_some(name)?
}

/// The name of the user `uid`, looked up through the C library (NSS), so
/// that users that are not in `/etc/passwd` have a name too.
pub fn user_name(uid: u32) -> Option<String> {
    lookup_name(|buf, len, name| {
        let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut found = std::ptr::null_mut();
        // SAFETY: the buffer outlives the call and `pw_name` is read only
        // when the call reports an entry, while the buffer is still alive.
        unsafe {
            let rc = libc::getpwuid_r(uid, entry.as_mut_ptr(), buf, len, &mut found);
            if rc == 0 && !found.is_null() {
                *name = std::ffi::CStr::from_ptr((*found).pw_name)
                    .to_str()
                    .ok()
                    .map(str::to_string);
            }
            rc
        }
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn root_has_a_name() {
        assert_eq!(super::user_name(0).as_deref(), Some("root"));
    }

    #[test]
    fn the_local_time_is_a_time() {
        let t = super::local_time().unwrap();
        assert!((0..12).contains(&t.month) && (1..=31).contains(&t.day));
        assert!((0..24).contains(&t.hour) && (0..60).contains(&t.minute));
    }
}
