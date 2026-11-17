// SPDX-License-Identifier: Apache-2.0
//! `velarx quadlet enable|disable|status`: which Quadlet generator
//! systemd runs.  velarx's (systemd/generators/velarx-generator) runs
//! podman's own generator with PODMAN=velarx; both read the same files and
//! would write the same units, so velarx's does nothing while podman's is
//! active.  Enabling velarx's masks podman's: a link to /dev/null in
//! /etc/systemd/{system,user}-generators, as `systemctl mask` does for
//! units.  `--root` is the root of those paths (for tests and images).

use clap::Subcommand;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Subcommand, Clone)]
pub enum QuadletCommands {
    #[command(about = "Generate the Quadlet units with velarx: mask podman's generator")]
    Enable(Target),
    #[command(about = "Give the Quadlet units back to podman: unmask its generator")]
    Disable(Target),
    #[command(about = "Say which generator makes the Quadlet units")]
    Status(Target),
}

#[derive(clap::Args, Clone)]
pub struct Target {
    /// The generators of the users' managers (rootless units), not of the
    /// system's
    #[arg(long)]
    pub user: bool,
    /// The root of the systemd directories
    #[arg(long, default_value = "/")]
    pub root: PathBuf,
}

impl Target {
    fn kind(&self) -> &'static str {
        if self.user {
            "user"
        } else {
            "system"
        }
    }

    fn dir(&self, base: &str) -> PathBuf {
        self.root
            .join(base.trim_start_matches('/'))
            .join(format!("systemd/{}-generators", self.kind()))
    }

    fn podman_generator(&self) -> String {
        format!("podman-{}-generator", self.kind())
    }

    /// Where podman's generator is masked.
    fn mask(&self) -> PathBuf {
        self.dir("/etc").join(self.podman_generator())
    }

    fn installed(&self, name: &str) -> bool {
        ["/usr/lib", "/usr/local/lib"]
            .iter()
            .any(|d| self.dir(d).join(name).exists())
    }

    fn masked(&self) -> bool {
        ["/etc", "/run"].iter().any(|d| {
            std::fs::read_link(self.dir(d).join(self.podman_generator()))
                .is_ok_and(|t| t == Path::new("/dev/null"))
        })
    }
}

/// Which generator makes the Quadlet units of `t`.
#[derive(Debug, PartialEq, Eq)]
pub enum Active {
    Podman,
    Velarx,
    /// velarx's generator is not installed and podman's is masked.
    None,
}

pub fn active(t: &Target) -> Active {
    let podman = t.installed(&t.podman_generator()) && !t.masked();
    let velarx = t.installed(&format!("velarx-{}-generator", t.kind()));
    match (podman, velarx) {
        (true, _) => Active::Podman,
        (false, true) => Active::Velarx,
        (false, false) => Active::None,
    }
}

pub fn enable(t: &Target) -> io::Result<()> {
    if t.masked() {
        return Ok(());
    }
    let mask = t.mask();
    if std::fs::symlink_metadata(&mask).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "{} exists and is not a mask: leaving it alone",
                mask.display()
            ),
        ));
    }
    if let Some(dir) = mask.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::os::unix::fs::symlink("/dev/null", &mask)
}

pub fn disable(t: &Target) -> io::Result<()> {
    let mask = t.mask();
    match std::fs::read_link(&mask) {
        Ok(target) if target == Path::new("/dev/null") => std::fs::remove_file(&mask),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a mask: leaving it alone", mask.display()),
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

pub fn run(cmd: QuadletCommands) -> anyhow::Result<()> {
    let reload = |t: &Target| {
        if t.user {
            "systemctl --user daemon-reload"
        } else {
            "systemctl daemon-reload"
        }
    };
    match cmd {
        QuadletCommands::Enable(t) => {
            enable(&t).map_err(|e| anyhow::anyhow!("{}: {e}", t.mask().display()))?;
            if active(&t) == Active::None {
                eprintln!("Warning: velarx's {} generator is not installed", t.kind());
            }
            println!(
                "podman's {} generator is masked; `{}` makes the units with velarx",
                t.kind(),
                reload(&t)
            );
        }
        QuadletCommands::Disable(t) => {
            disable(&t).map_err(|e| anyhow::anyhow!("{}: {e}", t.mask().display()))?;
            println!(
                "podman's {} generator is unmasked; `{}` makes the units with podman",
                t.kind(),
                reload(&t)
            );
        }
        QuadletCommands::Status(t) => println!(
            "{}",
            match active(&t) {
                Active::Podman => "podman",
                Active::Velarx => "velarx",
                Active::None => "none",
            }
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn install(root: &Path, kind: &str, name: &str) {
        let d = root.join(format!("usr/lib/systemd/{kind}-generators"));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(name), "").unwrap();
    }

    #[test]
    fn enable_masks_podmans_generator_and_disable_unmasks_it() {
        let d = tempfile::tempdir().unwrap();
        for user in [false, true] {
            let t = Target {
                user,
                root: d.path().to_path_buf(),
            };
            let kind = t.kind();
            assert_eq!(active(&t), Active::None);
            install(d.path(), kind, &format!("podman-{kind}-generator"));
            install(d.path(), kind, &format!("velarx-{kind}-generator"));
            assert_eq!(active(&t), Active::Podman);
            enable(&t).unwrap();
            enable(&t).unwrap();
            assert_eq!(
                std::fs::read_link(t.mask()).unwrap(),
                Path::new("/dev/null")
            );
            assert_eq!(active(&t), Active::Velarx);
            disable(&t).unwrap();
            disable(&t).unwrap();
            assert!(std::fs::symlink_metadata(t.mask()).is_err());
            assert_eq!(active(&t), Active::Podman);
            // a file of someone else is left alone
            std::fs::write(t.mask(), "x").unwrap();
            assert!(enable(&t).is_err());
            assert!(disable(&t).is_err());
            assert_eq!(std::fs::read_to_string(t.mask()).unwrap(), "x");
        }
    }
}
