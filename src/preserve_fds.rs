// SPDX-License-Identifier: Apache-2.0
//! `run --preserve-fds N` and `--preserve-fd FD[,FD]`: descriptors of the
//! command that the container gets under the same numbers (podman's
//! semantics).  The monitor places them from 3 on, so a descriptor that was
//! not asked for between two that were is a hole, closed again before the
//! runtime starts.

use crate::cli::run::Failed;
use std::os::fd::OwnedFd;

/// What the container gets: slot `i` is the descriptor 3+i, `None` for a
/// hole.
#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    pub slots: Vec<Option<i32>>,
}

/// The descriptors that `fds` (the count) and `list` stand for.
pub fn plan(fds: u32, list: &[u32]) -> Result<Plan, Failed> {
    let mut total = fds as usize;
    for &fd in list {
        total = total.max((fd as usize).saturating_sub(2));
    }
    if total > velarx_base::spawn::MAX_PRESERVED_FDS {
        return Err(Failed {
            status: 125,
            message: format!(
                "at most {} descriptors can be passed on",
                velarx_base::spawn::MAX_PRESERVED_FDS
            ),
        });
    }
    let slots = (0..total)
        .map(|i| {
            let fd = 3 + i as u32;
            (list.is_empty() || list.contains(&fd)).then_some(fd as i32)
        })
        .collect();
    Ok(Plan { slots })
}

/// The checks that podman makes before it does anything, in its order.
/// `open` tells whether this process has the descriptor.
pub fn validate(fds: u32, list: &[u32], open: impl Fn(u32) -> bool) -> Result<(), Failed> {
    let unavailable = |fd: u32, option: &str| Failed {
        status: 125,
        message: format!(
            "file descriptor {fd} is not available - the {option} option requires that \
             file descriptors must be passed"
        ),
    };
    for &fd in list {
        if !open(fd) {
            return Err(unavailable(fd, "preserve-fd"));
        }
    }
    for fd in (3..).take(fds as usize) {
        if !open(fd) {
            return Err(unavailable(fd, "preserve-fds"));
        }
    }
    if fds != 0 && !list.is_empty() {
        return Err(Failed {
            status: 125,
            message: "cannot specify both --preserve-fds and --preserve-fd".into(),
        });
    }
    if let Some(fd) = list.iter().find(|&&fd| fd < 3) {
        return Err(Failed {
            status: 126,
            message: format!(
                "cannot preserve FD {fd}, consider using the passthrough log-driver to pass \
                 STDIO streams into the container: invalid argument"
            ),
        });
    }
    Ok(())
}

/// The descriptors to pass on, taken from this process, and the slots that
/// are holes (a `/dev/null` stands in until the monitor closes them).
pub struct Taken {
    pub fds: Vec<OwnedFd>,
    pub holes: Vec<u32>,
}

/// Check the request and take the descriptors.
///
/// The start-up token says that nothing else owns the descriptors the
/// caller passed.
pub fn take(startup: &velarx_sys::fd::Startup, fds: u32, list: &[u32]) -> Result<Taken, Failed> {
    // (what the caller passed: a descriptor this process opened since, the
    // store's connection of the namespaces, is not one; the standard streams
    // are not the token's, they are open or not, and validate refuses the
    // option that names one of them)
    validate(fds, list, |fd| match i32::try_from(fd) {
        Ok(fd) if fd < 3 => std::path::Path::new(&format!("/proc/self/fd/{fd}")).exists(),
        Ok(fd) => startup.is_inherited(fd),
        Err(_) => false,
    })?;
    let plan = plan(fds, list)?;
    let mut taken = Taken {
        fds: Vec::new(),
        holes: Vec::new(),
    };
    for (i, slot) in plan.slots.iter().enumerate() {
        let fd = match slot {
            Some(fd) => startup.adopt(*fd).ok_or_else(|| Failed {
                status: 125,
                message: format!("descriptor {fd} is not open"),
            })?,
            None => {
                taken.holes.push(i as u32);
                std::fs::File::open("/dev/null")
                    .map_err(|e| Failed {
                        status: 125,
                        message: format!("cannot open /dev/null: {e}"),
                    })?
                    .into()
            }
        };
        let _ = rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC);
        taken.fds.push(fd);
    }
    Ok(taken)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slots(fds: u32, list: &[u32]) -> Vec<Option<i32>> {
        plan(fds, list).unwrap().slots
    }

    #[test]
    fn a_count_is_consecutive() {
        assert_eq!(slots(0, &[]), []);
        assert_eq!(slots(2, &[]), [Some(3), Some(4)]);
    }

    #[test]
    fn a_list_keeps_its_numbers_and_leaves_holes() {
        assert_eq!(slots(0, &[3]), [Some(3)]);
        assert_eq!(slots(0, &[6, 3]), [Some(3), None, None, Some(6)]);
    }

    #[test]
    fn too_many_are_refused() {
        assert_eq!(plan(65, &[]).unwrap_err().status, 125);
        assert!(plan(0, &[66]).is_ok());
        assert!(plan(0, &[67]).is_err());
    }

    #[test]
    fn the_checks_are_podmans_and_in_its_order() {
        let open = |fd: u32| fd < 6;
        assert!(validate(0, &[], open).is_ok());
        assert!(validate(3, &[], open).is_ok());
        assert!(validate(0, &[3, 5], open).is_ok());
        let e = validate(0, &[3, 6], open).unwrap_err();
        assert_eq!(e.status, 125);
        assert_eq!(
            e.message,
            "file descriptor 6 is not available - the preserve-fd option requires that \
             file descriptors must be passed"
        );
        let e = validate(4, &[], open).unwrap_err();
        assert_eq!(
            e.message,
            "file descriptor 6 is not available - the preserve-fds option requires that \
             file descriptors must be passed"
        );
        let e = validate(1, &[3], open).unwrap_err();
        assert_eq!(
            e.message,
            "cannot specify both --preserve-fds and --preserve-fd"
        );
        let e = validate(0, &[1], open).unwrap_err();
        assert_eq!(e.status, 126);
        assert!(e
            .message
            .starts_with("cannot preserve FD 1, consider using the passthrough"));
        // availability comes first
        assert_eq!(validate(1, &[7], open).unwrap_err().status, 125);
        assert!(validate(1, &[7], open)
            .unwrap_err()
            .message
            .contains("preserve-fd option"));
    }
}
