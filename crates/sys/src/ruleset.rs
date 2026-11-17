// SPDX-License-Identifier: Apache-2.0
//! The one builder of the Landlock rulesets of the confined processes: the
//! fetchers' front, spawner and directory fetcher, the pull workers, the
//! peer-to-peer service and the frontends (`velarx-api`, `velarx-cri`,
//! `velarx-kube`).  They differ in what they handle, which paths they may
//! reach and with which rights, and which ports they may connect to; how a
//! ruleset is made, how a file gets the rights of files only, what a path
//! the system lacks means and how the result is judged is here, once.
//!
//! It applies to the calling thread and those it makes afterwards
//! (`restrict_self`): [`crate::confine::require_single_thread`] first.

use landlock::{
    Access, CompatLevel, Compatible, LandlockStatus, NetPort, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus, Scope,
};
pub use landlock::{AccessFs, AccessNet, BitFlags, ABI};
use std::os::fd::BorrowedFd;
use std::path::Path;

/// The newest ABI the engine knows (9: UNIX sockets looked up by name).
pub const NEWEST: ABI = ABI::V9;

/// What a process may do beneath the staging of the store that is handed to
/// it open, by the object contract: files with no name, files named with
/// `linkat`, the directories they are in, read back.  Nothing is removed.
pub fn stager_rights() -> BitFlags<AccessFs> {
    AccessFs::ReadFile
        | AccessFs::ReadDir
        | AccessFs::WriteFile
        | AccessFs::Truncate
        | AccessFs::MakeReg
        | AccessFs::MakeDir
        | AccessFs::Refer
}

/// What a process that also takes away what it staged (a fetcher that
/// removes a staged file the engine rejected) may do beneath its staging.
pub fn stager_rights_with_removal() -> BitFlags<AccessFs> {
    stager_rights() | AccessFs::RemoveFile | AccessFs::RemoveDir
}

/// How much of the ruleset must be enforced for the process to start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Must {
    /// The rights of the file system of ABI 1; the rest as far as the
    /// kernel has it
    Files,
    /// Every right asked for: a kernel that cannot enforce them refuses
    /// the process
    Everything,
}

/// What a ruleset handles: the rights it denies unless a rule gives them.
#[derive(Debug, Clone, Copy)]
pub struct Handles {
    /// The file system rights of this ABI and earlier ones
    pub abi: ABI,
    /// The TCP rights (bind, connect); none when the process does not
    /// handle TCP at all
    pub net: BitFlags<AccessNet>,
    /// The scopes: abstract UNIX sockets and signals outside the domain
    pub scopes: bool,
    pub must: Must,
}

/// What the kernel enforces of a ruleset that was restricted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Restricted {
    /// The ABI of the access rights asked for (as far as the kernel and
    /// the crate know it)
    pub abi: ABI,
    /// The ABI of the kernel when it is newer than the crate's
    pub kernel_abi: Option<i32>,
    /// Every right asked for is enforced
    pub full: bool,
}

/// A ruleset being made.
pub struct Rules {
    /// (taken while a rule is added, which consumes it)
    ruleset: Option<RulesetCreated>,
    abi: ABI,
}

fn err(e: &dyn std::fmt::Display) -> String {
    format!("landlock: {e}")
}

impl Rules {
    /// A ruleset that handles `handles`.
    pub fn new(handles: Handles) -> Result<Self, String> {
        let Handles {
            abi,
            net,
            scopes,
            must,
        } = handles;
        let scope = Scope::AbstractUnixSocket | Scope::Signal;
        let mut hard = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(ABI::V1))
            .map_err(|e| err(&e))?;
        if must == Must::Everything {
            hard = hard
                .handle_access(AccessFs::from_all(abi))
                .map_err(|e| err(&e))?;
            if !net.is_empty() {
                hard = hard.handle_access(net).map_err(|e| err(&e))?;
            }
            if scopes {
                hard = hard.scope(scope).map_err(|e| err(&e))?;
            }
        }
        let mut soft = hard
            .set_compatibility(CompatLevel::BestEffort)
            .handle_access(AccessFs::from_all(abi))
            .map_err(|e| err(&e))?;
        if !net.is_empty() {
            soft = soft.handle_access(net).map_err(|e| err(&e))?;
        }
        if scopes {
            soft = soft.scope(scope).map_err(|e| err(&e))?;
        }
        Ok(Self {
            ruleset: Some(soft.create().map_err(|e| err(&e))?),
            abi,
        })
    }

    /// A ruleset that handles the execution of files and nothing else
    /// (what a process that only has to keep another from executing
    /// anything but the programs it names needs; the process it starts
    /// reads and writes as its own rights allow).  The kernel must enforce
    /// it.
    pub fn execute_only() -> Result<Self, String> {
        let ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::Execute)
            .map_err(|e| err(&e))?
            .create()
            .map_err(|e| err(&e))?;
        Ok(Self {
            ruleset: Some(ruleset),
            abi: ABI::V1,
        })
    }

    /// `rights` on the program `exe` (open) and on the dynamic loader it
    /// asks for, which the kernel executes too.
    pub fn program(
        &mut self,
        exe: BorrowedFd<'_>,
        rights: BitFlags<AccessFs>,
    ) -> Result<(), String> {
        let rights = rights & AccessFs::from_file(self.abi);
        self.add_fs(PathBeneath::new(exe, rights))
            .map_err(|e| err(&e))?;
        if let Some(loader) = interpreter(exe) {
            let fd = PathFd::new(&loader).map_err(|e| err(&e))?;
            self.add_fs(PathBeneath::new(fd, rights))
                .map_err(|e| err(&e))?;
        }
        Ok(())
    }

    /// `rights` beneath `path`, which must exist; a file takes the rights
    /// of files only.
    pub fn beneath(&mut self, path: &Path, rights: BitFlags<AccessFs>) -> Result<(), String> {
        let named = |e: &dyn std::fmt::Display| format!("landlock: {}: {e}", path.display());
        let fd = PathFd::new(path).map_err(|e| named(&e))?;
        let rights = if path.is_dir() {
            rights
        } else {
            rights & AccessFs::from_file(self.abi)
        };
        self.add_fs(PathBeneath::new(fd, rights))
            .map_err(|e| named(&e))
    }

    /// As [`Rules::beneath`] for a path the system may not have (a library
    /// directory of another layout, a configuration file never made): what
    /// is not there cannot be used, and no rule is made for it.
    pub fn beneath_if_present(
        &mut self,
        path: &Path,
        rights: BitFlags<AccessFs>,
    ) -> Result<(), String> {
        match path.try_exists() {
            Ok(true) => self.beneath(path, rights),
            _ => Ok(()),
        }
    }

    /// `rights` beneath the directory `dir`, open (the rule is the
    /// descriptor's: what it names now, whatever the path does later).
    pub fn beneath_dir(
        &mut self,
        dir: BorrowedFd<'_>,
        rights: BitFlags<AccessFs>,
    ) -> Result<(), String> {
        self.add_fs(PathBeneath::new(dir, rights))
            .map_err(|e| err(&e))
    }

    /// `access` to the TCP port `port`.
    pub fn port(&mut self, port: u16, access: AccessNet) -> Result<(), String> {
        self.add_net(NetPort::new(port, access))
            .map_err(|e| format!("landlock: tcp port {port}: {e}"))
    }

    fn add_fs<F: std::os::fd::AsFd>(
        &mut self,
        rule: PathBeneath<F>,
    ) -> Result<(), landlock::RulesetError> {
        let ruleset = self
            .ruleset
            .take()
            .expect("the ruleset is there between calls");
        self.ruleset = Some(ruleset.add_rule(rule)?);
        Ok(())
    }

    fn add_net(&mut self, rule: NetPort) -> Result<(), landlock::RulesetError> {
        let ruleset = self
            .ruleset
            .take()
            .expect("the ruleset is there between calls");
        self.ruleset = Some(ruleset.add_rule(rule)?);
        Ok(())
    }

    /// Apply it to the calling thread and those it makes afterwards.  A
    /// kernel without Landlock, or that enforces none of it, is an error;
    /// whether all of it is enforced is [`Restricted::full`].
    pub fn restrict(self) -> Result<Restricted, String> {
        let ruleset = self.ruleset.expect("the ruleset is there between calls");
        let status = ruleset.restrict_self().map_err(|e| err(&e))?;
        let (abi, kernel_abi) = match status.landlock {
            LandlockStatus::Available {
                effective_abi,
                kernel_abi,
            } => (effective_abi, kernel_abi),
            _ => return Err("landlock is not available on this kernel".into()),
        };
        if status.ruleset == RulesetStatus::NotEnforced {
            return Err("landlock is not enforced by this kernel".into());
        }
        Ok(Restricted {
            abi,
            kernel_abi,
            full: status.ruleset == RulesetStatus::FullyEnforced,
        })
    }

    /// As [`Rules::restrict`], and an error unless every right asked for is
    /// enforced.
    pub fn restrict_fully(self, who: &str) -> Result<Restricted, String> {
        let abi = self.abi;
        let restricted = self.restrict()?;
        match restricted.full {
            true => Ok(restricted),
            false => Err(format!(
                "landlock: this kernel does not enforce all of the ruleset of {who} (ABI {} needed)",
                abi as i32
            )),
        }
    }
}

/// The dynamic loader an ELF program asks for (its `PT_INTERP`), as a real
/// path; none for a program that has none or a file that is not ELF.
fn interpreter(program: BorrowedFd<'_>) -> Option<std::path::PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::FileExt;
    let f = crate::fd::reopen_read_only(&program).ok()?;
    let mut head = [0u8; 64];
    f.read_exact_at(&mut head, 0).ok()?;
    if &head[..4] != b"\x7fELF" || head[4] != 2 || head[5] != 1 {
        return None;
    }
    let u16_at = |b: &[u8], o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
    let u64_at = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().expect("8 bytes"));
    let (phoff, phentsize, phnum) = (
        u64_at(&head, 0x20),
        u16_at(&head, 0x36),
        u16_at(&head, 0x38),
    );
    for i in 0..u64::from(phnum.min(64)) {
        let mut ph = [0u8; 56];
        f.read_exact_at(&mut ph, phoff + i * u64::from(phentsize))
            .ok()?;
        if u32::from_le_bytes([ph[0], ph[1], ph[2], ph[3]]) == 3 {
            let (off, size) = (u64_at(&ph, 8), u64_at(&ph, 32).min(4096));
            let mut name = vec![0u8; size as usize];
            f.read_exact_at(&mut name, off).ok()?;
            let end = name.iter().position(|&b| b == 0)?;
            let path = std::ffi::OsStr::from_bytes(&name[..end]);
            return Path::new(path).canonicalize().ok();
        }
    }
    None
}
