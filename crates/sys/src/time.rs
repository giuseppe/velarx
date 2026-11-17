// SPDX-License-Identifier: Apache-2.0
//! The local time of the C library.

/// A moment broken down in the local time zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTime {
    pub year: i32,
    pub month: i32,
    pub day: i32,
    pub hour: i32,
    pub minute: i32,
    pub second: i32,
    /// The abbreviation of the zone (`CET`), empty when the library has none.
    pub zone: String,
    /// Seconds east of UTC.
    pub utc_offset: i64,
}

/// `secs` since the epoch in the local time zone; `None` when the library
/// cannot convert it.
pub fn local_time(secs: i64) -> Option<LocalTime> {
    // SAFETY: localtime_r fills the tm it is given (zeroed here, valid for
    // the call); tm_zone points to a string of the C library that is copied
    // before the call returns here (or is NULL).
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        let t: libc::time_t = secs;
        if libc::localtime_r(&t, &mut tm).is_null() {
            return None;
        }
        let zone = if tm.tm_zone.is_null() {
            String::new()
        } else {
            std::ffi::CStr::from_ptr(tm.tm_zone)
                .to_string_lossy()
                .into_owned()
        };
        Some(LocalTime {
            year: tm.tm_year + 1900,
            month: tm.tm_mon + 1,
            day: tm.tm_mday,
            hour: tm.tm_hour,
            minute: tm.tm_min,
            second: tm.tm_sec,
            zone,
            utc_offset: tm.tm_gmtoff,
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_epoch_is_in_1969_or_1970() {
        let t = super::local_time(0).unwrap();
        assert!(t.year == 1969 || t.year == 1970, "{t:?}");
    }
}
