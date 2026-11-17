// SPDX-License-Identifier: Apache-2.0
//! The names of the processes of velarx, as `ps -o comm`, `top` and
//! `pgrep` show them: one binary runs the server and the workers, which
//! would all be `velarx`.  The kernel keeps 15 bytes of a name.  The
//! command line of a process that has no use for the one it was started with
//! (the monitor of a container: its run directory) is written over in place
//! (`set_cmdline`).

/// Name the calling thread; called before any other thread starts, it
/// names the process (and the threads it starts inherit it).
pub fn set(name: &str) {
    let n = name.bytes().take(15).take_while(|&b| b != 0).count();
    if let Ok(name) = std::ffi::CString::new(&name.as_bytes()[..n]) {
        let _ = rustix::thread::set_name(&name);
    }
}

/// The address range of the arguments and of the environment strings of
/// this process, from fields 48 to 51 of `/proc/self/stat`.
fn argument_area() -> Option<(usize, usize, usize, usize)> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let mut f = stat[stat.rfind(')')? + 1..]
        .split_whitespace()
        .skip(45)
        .map(|v| v.parse::<usize>().ok());
    Some((f.next()??, f.next()??, f.next()??, f.next()??))
}

/// Make `/proc/PID/cmdline`, and so `ps` and `pgrep -f`, say `title`: the
/// argument strings are written over in place and, when the title is longer
/// than they are, so is the environment that follows them (the kernel reads
/// on into it when the last argument byte is not NUL, which is how sshd and
/// postgres do it).  The environment is copied to the heap first.  A title
/// that does not fit is cut.  Called first thing, before any thread starts:
/// no thread must read the environment meanwhile.
pub fn set_cmdline(title: &str) {
    let Some((arg_start, arg_end, env_start, env_end)) = argument_area() else {
        return;
    };
    // the area is the arguments and, right after them, the environment
    let end = if arg_end == env_start {
        env_end
    } else {
        arg_end
    };
    if end <= arg_start {
        return;
    }
    let vars: Vec<_> = std::env::vars_os().collect();
    velarx_sys::process::clear_environment();
    for (k, v) in vars {
        std::env::set_var(k, v);
    }
    velarx_sys::process::overwrite_memory(arg_start, end, title.as_bytes());
}

/// The name of the calling thread.
#[cfg(test)]
fn get() -> String {
    std::fs::read_to_string("/proc/thread-self/comm")
        .map(|s| s.trim_end().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_line_is_written_over_in_place() {
        velarx_base::testing::in_child(|| {
            let path = std::env::var_os("PATH");
            let cmdline = || {
                let bytes = std::fs::read("/proc/self/cmdline").unwrap();
                String::from_utf8(bytes)
                    .unwrap()
                    .trim_end_matches('\0')
                    .to_string()
            };
            set_cmdline("velarx-monitor: 0123456789ab name image");
            assert_eq!(cmdline(), "velarx-monitor: 0123456789ab name image");
            // a title longer than the arguments goes on into the environment
            let long = "x".repeat(2000);
            set_cmdline(&long);
            let now = cmdline();
            assert!(
                now.len() > 200 && now.bytes().all(|b| b == b'x'),
                "{}",
                now.len()
            );
            assert_eq!(std::env::var_os("PATH"), path, "the environment is kept");
        });
    }

    #[test]
    fn a_thread_is_named_and_the_name_is_cut_at_15_bytes() {
        std::thread::spawn(|| {
            set("velarx-test");
            assert_eq!(get(), "velarx-test");
            set("velarx-a-very-long-name");
            assert_eq!(get(), "velarx-a-very-l");
        })
        .join()
        .unwrap();
    }
}
