// SPDX-License-Identifier: Apache-2.0
//! The conditions of a container's wait (`ContainerWait`), as the command
//! line, velarx-api and the engine name them.

use serde::{Deserialize, Serialize};

/// What a wait waits for: podman's conditions, Docker's (`not-running`,
/// `next-exit`, `removed`) among them.  The wire spells a word with `_`
/// (`next_exit`), podman with `-` (`next-exit`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
pub enum WaitCondition {
    /// The container is created and was never initialized (as `created`)
    Configured,
    /// The container is created and does not run
    Created,
    /// The container exited, or never ran: its exit code (0)
    Exited,
    /// Its health check says healthy
    Healthy,
    /// The runtime made it, it was not started
    Initialized,
    /// Its next exit, whatever its state is now: the exit code; its removal
    /// ends the wait too
    NextExit,
    /// The container does not run (as `exited`)
    NotRunning,
    /// The container is paused
    Paused,
    /// The container is gone: the code of its last exit (0 if it never ran)
    Removed,
    /// The container is being removed or gone (-1 if it never ran)
    Removing,
    /// The container runs
    Running,
    /// As `exited`
    Stopped,
    /// A stop is in progress
    Stopping,
    /// Its health check says unhealthy
    Unhealthy,
}

impl WaitCondition {
    /// Every condition.
    pub const ALL: [WaitCondition; 14] = [
        Self::Configured,
        Self::Created,
        Self::Exited,
        Self::Healthy,
        Self::Initialized,
        Self::NextExit,
        Self::NotRunning,
        Self::Paused,
        Self::Removed,
        Self::Removing,
        Self::Running,
        Self::Stopped,
        Self::Stopping,
        Self::Unhealthy,
    ];

    /// The conditions Docker's API takes.
    pub const DOCKER: [WaitCondition; 3] = [Self::NotRunning, Self::NextExit, Self::Removed];

    /// podman's name of the condition (`next-exit`).
    pub fn name(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::Created => "created",
            Self::Exited => "exited",
            Self::Healthy => "healthy",
            Self::Initialized => "initialized",
            Self::NextExit => "next-exit",
            Self::NotRunning => "not-running",
            Self::Paused => "paused",
            Self::Removed => "removed",
            Self::Removing => "removing",
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Stopping => "stopping",
            Self::Unhealthy => "unhealthy",
        }
    }

    /// The condition of podman's name.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.name() == name)
    }

    /// The conditions of podman's names, or the error that names the first
    /// unknown one.
    pub fn parse_all<S: AsRef<str>>(names: &[S]) -> Result<Vec<Self>, String> {
        names
            .iter()
            .map(|n| {
                let n = n.as_ref();
                Self::from_name(n).ok_or_else(|| {
                    let known: Vec<&str> = Self::ALL.iter().map(|c| c.name()).collect();
                    format!("unknown wait condition {n:?} (one of {})", known.join(", "))
                })
            })
            .collect()
    }

    /// Met by the end of a run: the wait answers the exit code.
    pub fn is_exit(self) -> bool {
        matches!(self, Self::Exited | Self::Stopped | Self::NotRunning)
    }
}

/// The interval of a wait as podman reads it: a Go duration (`250ms`,
/// `-1s`), and for the command line a bare number of milliseconds
/// (`bare_ms`); in nanoseconds, negative as written (the engine refuses it).
pub fn parse_interval(s: &str, bare_ms: bool) -> Option<i64> {
    let (negative, unsigned) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let d = crate::duration::parse_go_duration(unsigned).or_else(|| {
        bare_ms
            .then(|| crate::duration::parse_go_duration(&format!("{unsigned}ms")))
            .flatten()
    })?;
    let ns = i64::try_from(d.as_nanos()).ok()?;
    Some(if negative { -ns } else { ns })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for c in WaitCondition::ALL {
            assert_eq!(WaitCondition::from_name(c.name()), Some(c));
            let wire = serde_json::to_value(c).unwrap();
            assert_eq!(wire, c.name().replace('-', "_"));
        }
        assert_eq!(WaitCondition::from_name("next_exit"), None);
        let e = WaitCondition::parse_all(&["running", "bogus"]).unwrap_err();
        assert!(e.contains("\"bogus\""), "{e}");
        assert_eq!(
            WaitCondition::parse_all(&["next-exit", "removed"]).unwrap(),
            [WaitCondition::NextExit, WaitCondition::Removed]
        );
    }

    #[test]
    fn intervals() {
        assert_eq!(parse_interval("250ms", false), Some(250_000_000));
        assert_eq!(parse_interval("-1s", false), Some(-1_000_000_000));
        assert_eq!(parse_interval("0", false), Some(0));
        assert_eq!(parse_interval("5000", false), None);
        assert_eq!(parse_interval("5000", true), Some(5_000_000_000));
        assert_eq!(parse_interval("-5", true), Some(-5_000_000));
        assert_eq!(parse_interval("100days", true), None);
        assert_eq!(parse_interval("", true), None);
    }
}
