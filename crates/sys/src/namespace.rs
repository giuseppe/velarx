// SPDX-License-Identifier: Apache-2.0
//! Namespaces of the calling process.

use rustix::thread::UnshareFlags;
use std::io;

pub use crate::ns::unshare;

/// `unshare(flags | CLONE_NEWUSER)`, then map the user and the group the
/// process had to root of the new user namespace, as the files
/// `/proc/self/{setgroups,uid_map,gid_map}`.
pub fn unshare_user_mapped_to_root(flags: UnshareFlags) -> io::Result<()> {
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    unshare(flags | UnshareFlags::NEWUSER)?;
    for (file, text) in [
        ("/proc/self/setgroups", "deny".to_string()),
        ("/proc/self/uid_map", format!("0 {uid} 1")),
        ("/proc/self/gid_map", format!("0 {gid} 1")),
    ] {
        std::fs::write(file, text)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_process_can_leave_its_ipc_namespace_or_is_refused() {
        // (in a child: the thread is the test's, and the others of the
        // process keep what they have)
        let code = crate::process::fork_status(|| match unshare(UnshareFlags::NEWIPC) {
            Ok(()) => 0,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => 0,
            Err(_) => 1,
        })
        .unwrap();
        assert_eq!(code, 0);
    }
}
