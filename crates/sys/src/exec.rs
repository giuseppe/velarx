// SPDX-License-Identifier: Apache-2.0
//! What a command does in the child between `fork` and `exec`.

use std::os::fd::RawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;

/// Make each `(from, to)` of `places` the descriptor `to` of the program
/// `cmd` starts: `from` must be open until the command is spawned.  The
/// sources are first moved out of the way of every destination, so that
/// `[(5, 3), (3, 4)]` does what it says.  The destinations are not
/// close-on-exec; the other descriptors keep their flags.
pub fn place_fds(cmd: &mut Command, places: Vec<(RawFd, RawFd)>) {
    let out_of_the_way = places.iter().map(|p| p.1).max().map_or(0, |m| m + 1);
    let mut parked = vec![-1; places.len()];
    // SAFETY: the closure runs in the child between fork and exec and only
    // calls fcntl and dup2 (async-signal-safe) on integers, with the two
    // vectors made before the fork; it does not allocate.
    unsafe {
        cmd.pre_exec(move || {
            for (i, (from, _)) in places.iter().enumerate() {
                let p = libc::fcntl(*from, libc::F_DUPFD_CLOEXEC, out_of_the_way);
                if p < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                parked[i] = p;
            }
            for (i, (_, to)) in places.iter().enumerate() {
                if libc::dup2(parked[i], *to) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::fd::AsRawFd;

    #[test]
    fn a_descriptor_arrives_as_the_one_asked() {
        let (r, w) = std::io::pipe().unwrap();
        let mut cmd = std::process::Command::new("sh");
        cmd.args(["-c", "echo placed >&7"]);
        super::place_fds(&mut cmd, vec![(w.as_raw_fd(), 7)]);
        let mut child = cmd.spawn().unwrap();
        drop(w);
        let mut out = String::new();
        std::io::BufReader::new(r).read_to_string(&mut out).unwrap();
        assert!(child.wait().unwrap().success());
        assert_eq!(out, "placed\n");
    }
}
