// SPDX-License-Identifier: Apache-2.0
//! The only `unsafe` of velarx.  Every other package forbids it (the unit
//! test `unsafe_code_is_only_in_the_sys_package` of `src/testing.rs`
//! checks it).  A function here is safe to call, small and named for what
//! it does; its `unsafe` block has the `// SAFETY:` comment that states why
//! the arguments cannot break memory safety or the ownership of a
//! descriptor.

#[cfg(feature = "seccompiler")]
pub mod allow;
pub mod caps;
pub mod catch;
pub mod confine;
pub mod connector;
pub mod exec;
pub mod fd;
pub mod ffi;
pub mod flock;
pub mod fs;
pub mod ioctl;
pub mod mmap;
pub mod mount;
pub mod namespace;
pub mod ns;
pub mod packet;
pub mod pidfd;
pub mod pipe;
pub mod probe;
pub mod process;
#[cfg(feature = "landlock")]
pub mod ruleset;
pub mod scm;
pub mod selftest;
pub mod signal;
pub mod spawn;
pub mod spawner;
pub mod statmount;
pub mod system;
pub mod time;
pub mod tty;
pub mod watch;
