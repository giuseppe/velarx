// SPDX-License-Identifier: Apache-2.0
//! The health of a container and the restart policy of its monitor: the
//! types the engine, its frontends and the monitor share (the monitor's
//! `Status` and `Event::Health` carry them, the engine's `ContainerRecord`
//! too).  The database stores the texts of the words below (`starting`,
//! `on-failure`, ...) through [`HealthStatus::word`] and
//! [`RestartPolicy::word`], not the form of the wire.
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The state of the health check of a container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
pub enum HealthStatus {
    /// No result yet, or the startup check has not passed
    #[default]
    Starting,
    Healthy,
    Unhealthy,
    /// The container stopped while a check ran
    Stopped,
}

impl HealthStatus {
    /// The word podman and the database have for it.
    pub fn word(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Healthy => "healthy",
            Self::Unhealthy => "unhealthy",
            Self::Stopped => "stopped",
        }
    }

    /// The status a word names (`starting` for any other).
    pub fn from_word(word: &str) -> Self {
        match word {
            "healthy" => Self::Healthy,
            "unhealthy" => Self::Unhealthy,
            "stopped" => Self::Stopped,
            _ => Self::Starting,
        }
    }
}

/// A result of a health check.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct HealthResult {
    /// Nanoseconds since the epoch
    pub start_ns: i64,
    /// Nanoseconds since the epoch
    pub end_ns: i64,
    pub exit_code: i64,
    /// The start of what the check wrote
    pub output: String,
}

/// The health of a container.  (`HealthState` in the interfaces: the Engine
/// has a method `Health`, and a type and a method share one namespace.)
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[cfg_attr(feature = "proxy", zlink(rename = "HealthState"))]
#[serde(default)]
pub struct Health {
    pub status: HealthStatus,
    /// The failures since the last success
    pub failing_streak: i64,
    /// The last results, the oldest first
    pub log: Vec<HealthResult>,
}

/// Results kept (podman's default HealthMaxLogCount).
pub const LOG_ENTRIES: u32 = 5;

/// The characters of the output of a check kept (podman's default
/// HealthMaxLogSize).
pub const LOG_OUTPUT_CHARS: u32 = 500;

const DEFAULT_PERIOD_NS: u64 = 30_000_000_000;

/// Failures before a container is unhealthy when the image does not say
/// (podman's DefaultHealthCheckRetries).
const DEFAULT_RETRIES: u32 = 3;

/// What a container that became unhealthy gets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
pub enum OnFailure {
    /// Nothing.
    #[default]
    None,
    /// Kill the container.
    Kill,
    /// Kill the container and start it again, whatever its restart policy.
    Restart,
    /// Stop the container: no restart.
    Stop,
}

impl OnFailure {
    /// The word podman has for it.
    pub fn word(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Kill => "kill",
            Self::Restart => "restart",
            Self::Stop => "stop",
        }
    }

    /// The action a word names (podman's `--health-on-failure`); `None`
    /// for one that is not an action (`""` is [`Self::None`]).
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "" | "none" => Self::None,
            "kill" => Self::Kill,
            "restart" => Self::Restart,
            "stop" => Self::Stop,
            _ => return None,
        })
    }
}

/// The check that runs until a container has started (podman's
/// `--health-startup-*`); the times are nanoseconds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct StartupHealthcheck {
    /// As the `test` of a health check
    pub test: Vec<String>,
    /// 0: 30 s
    pub interval_ns: u64,
    /// 0: 30 s
    pub timeout_ns: u64,
    /// Failures before the container is restarted; 0: never
    pub retries: u32,
    /// Successes before the regular check begins; 0: one
    pub successes: u32,
}

impl StartupHealthcheck {
    pub fn interval(&self) -> Duration {
        period(self.interval_ns)
    }

    pub fn timeout(&self) -> Duration {
        period(self.timeout_ns)
    }

    /// The command of the check, as an argument vector.
    pub fn command(&self) -> Option<Vec<String>> {
        test_command(&self.test)
    }
}

/// The health check of a container (its own, or its image's): what the
/// create request carries, the container record stores and `inspect` shows,
/// and what the monitor runs.  The times are nanoseconds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct Healthcheck {
    /// `CMD-SHELL cmd`, `CMD arg...`, `NONE`, or an argument vector
    pub test: Vec<String>,
    /// Between two checks; 0: 30 s
    pub interval_ns: u64,
    /// No timer: the checks are those of `healthcheck run` (podman's
    /// `--health-interval=disable`)
    pub interval_disabled: bool,
    /// For one check; 0: no timeout (libpod's), the check runs until it ends
    pub timeout_ns: u64,
    /// Failures in it do not count
    pub start_period_ns: u64,
    /// Between two checks in the start period
    pub start_interval_ns: u64,
    /// Failures in a row before the container is unhealthy; 0 is one, as
    /// podman's `FailingStreak >= Retries`
    pub retries: u32,
    /// What a container that became unhealthy gets
    pub on_failure: OnFailure,
    /// The check that runs until the container has started: the regular
    /// one begins once it passed.
    pub startup: Option<StartupHealthcheck>,
    /// Where the results go: `local` (the default, the state of the
    /// container), `events_logger`, or a directory (`<dir>/<id>-healthcheck.log`)
    pub log_destination: String,
    /// How many results are kept (default 5, 0: no limit)
    pub max_log_count: Option<u32>,
    /// How many characters of the output of a result are kept (default 500,
    /// 0: no limit)
    pub max_log_size: Option<u32>,
}

impl Healthcheck {
    /// The command of the check, as an argument vector; `None` when there
    /// is no check (`NONE`, or no command).
    pub fn command(&self) -> Option<Vec<String>> {
        test_command(&self.test)
    }

    /// Between two checks; `None` when there is no timer.
    pub fn interval(&self) -> Option<Duration> {
        (!self.interval_disabled).then(|| period(self.interval_ns))
    }

    /// For one check; `None` when it has no timeout.
    pub fn timeout(&self) -> Option<Duration> {
        (self.timeout_ns != 0).then(|| Duration::from_nanos(self.timeout_ns))
    }

    pub fn start_period(&self) -> Duration {
        Duration::from_nanos(self.start_period_ns)
    }

    /// Failures before the container is unhealthy (at least one).
    pub fn failures_allowed(&self) -> u32 {
        self.retries.max(1)
    }

    /// The check of an image with podman's defaults for the times it does
    /// not give (specgen's applyHealthCheckOverrides): a check a container
    /// takes from its image has 30 s for an interval or timeout of 0 and 3
    /// for 0 retries, where its own check has what it says.
    pub fn completed(mut self) -> Self {
        if self.interval_disabled {
            self.interval_ns = 0;
        } else if self.interval_ns == 0 {
            self.interval_ns = DEFAULT_PERIOD_NS;
        }
        if self.timeout_ns == 0 {
            self.timeout_ns = DEFAULT_PERIOD_NS;
        }
        if self.retries == 0 {
            self.retries = DEFAULT_RETRIES;
        }
        self
    }

    /// The directory the results are also written to; `None` when they stay
    /// with the container's own record.
    pub fn log_dir(&self) -> Option<&Path> {
        match self.log_destination.as_str() {
            "" | "local" | "events_logger" => None,
            dir => Some(Path::new(dir)),
        }
    }

    /// Results kept; 0: no limit.
    pub fn log_count(&self) -> u32 {
        self.max_log_count.unwrap_or(LOG_ENTRIES)
    }

    /// Characters of the output of a result kept; 0: no limit.
    pub fn log_size(&self) -> u32 {
        self.max_log_size.unwrap_or(LOG_OUTPUT_CHARS)
    }
}

fn period(ns: u64) -> Duration {
    Duration::from_nanos(if ns == 0 { DEFAULT_PERIOD_NS } else { ns })
}

/// The argument vector of a health check test in the notation of images and
/// Docker: `CMD-SHELL cmd`, `CMD arg...`, `NONE` (no check), or already a
/// vector.
pub fn test_command(test: &[String]) -> Option<Vec<String>> {
    match test.first().map(String::as_str) {
        None | Some("NONE") => None,
        Some("CMD-SHELL") => {
            let cmd = test[1..].join(" ");
            (!cmd.trim().is_empty()).then(|| vec!["/bin/sh".to_string(), "-c".to_string(), cmd])
        }
        Some("CMD") => (test.len() > 1).then(|| test[1..].to_vec()),
        Some(_) => Some(test.to_vec()),
    }
}

/// What to do when the container exits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
pub enum RestartPolicy {
    /// Nothing
    #[default]
    No,
    /// When it failed (`RestartSettings::max_retries` times at most)
    OnFailure,
    Always,
    /// As `Always`, but not after the user stopped it
    UnlessStopped,
}

impl RestartPolicy {
    /// The word of podman, docker and the database (`on-failure`).
    pub fn word(self) -> &'static str {
        match self {
            Self::No => "no",
            Self::OnFailure => "on-failure",
            Self::Always => "always",
            Self::UnlessStopped => "unless-stopped",
        }
    }

    /// The policy a word names; `None` for one that is not a policy
    /// (`""` and `"no"` are [`Self::No`]).
    pub fn from_word(word: &str) -> Option<Self> {
        Some(match word {
            "" | "no" => Self::No,
            "on-failure" => Self::OnFailure,
            "always" => Self::Always,
            "unless-stopped" => Self::UnlessStopped,
            _ => return None,
        })
    }
}

/// The restart policy with its limit.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
pub struct RestartSettings {
    pub policy: RestartPolicy,
    /// The most restarts of `on-failure`; 0: no limit.
    #[serde(default)]
    pub max_retries: u32,
}

/// The form a container's restart policy has in the database
/// (`{"name": "on-failure", "max_retries": 3}`), whatever the form of
/// [`RestartSettings`] on a wire: for `#[serde(with = "...")]` on an
/// `Option<RestartSettings>`.
pub mod stored_restart {
    use super::{RestartPolicy, RestartSettings};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct Stored {
        name: String,
        #[serde(default)]
        max_retries: u32,
    }

    pub fn serialize<S: Serializer>(
        value: &Option<RestartSettings>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        value
            .as_ref()
            .map(|r| Stored {
                name: r.policy.word().to_string(),
                max_retries: r.max_retries,
            })
            .serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<RestartSettings>, D::Error> {
        Option::<Stored>::deserialize(d)?
            .map(|r| {
                Ok(RestartSettings {
                    policy: RestartPolicy::from_word(&r.name).ok_or_else(|| {
                        serde::de::Error::custom(format!("{:?} is not a restart policy", r.name))
                    })?,
                    max_retries: r.max_retries,
                })
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commands() {
        let s = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            test_command(&s(&["CMD-SHELL", "exit", "1"])),
            Some(s(&["/bin/sh", "-c", "exit 1"]))
        );
        assert_eq!(
            test_command(&s(&["CMD", "curl", "-f", "x"])),
            Some(s(&["curl", "-f", "x"]))
        );
        assert_eq!(test_command(&s(&["curl", "x"])), Some(s(&["curl", "x"])));
        assert_eq!(test_command(&s(&["NONE"])), None);
        assert_eq!(test_command(&s(&["CMD"])), None);
        assert_eq!(test_command(&[]), None);
    }

    #[test]
    fn actions() {
        assert_eq!(OnFailure::parse("restart"), Some(OnFailure::Restart));
        assert_eq!(OnFailure::parse("none"), Some(OnFailure::None));
        assert_eq!(OnFailure::parse(""), Some(OnFailure::None));
        assert_eq!(OnFailure::parse("explode"), None);
    }

    #[test]
    fn the_defaults_are_in_one_place() {
        // a check as given: 0 is no timeout and one failure
        let h = Healthcheck::default();
        assert_eq!(h.interval(), Some(Duration::from_secs(30)));
        assert_eq!(h.timeout(), None);
        assert_eq!(h.failures_allowed(), 1);
        // an image's: podman's defaults
        let h = Healthcheck::default().completed();
        assert_eq!(
            (h.interval_ns, h.timeout_ns, h.retries),
            (30_000_000_000, 30_000_000_000, 3)
        );
        assert_eq!(h.timeout(), Some(Duration::from_secs(30)));
        let h = Healthcheck {
            interval_ns: 5,
            interval_disabled: true,
            timeout_ns: 7,
            retries: 2,
            ..Default::default()
        }
        .completed();
        assert_eq!((h.interval_ns, h.timeout_ns, h.retries), (0, 7, 2));
        assert_eq!(h.interval(), None);
        assert_eq!((h.log_count(), h.log_size()), (5, 500));
        assert_eq!(h.log_dir(), None);
        let h = Healthcheck {
            interval_disabled: true,
            retries: 7,
            max_log_count: Some(0),
            log_destination: "/var/log/h".into(),
            ..Default::default()
        };
        assert_eq!(h.interval(), None);
        assert_eq!(h.failures_allowed(), 7);
        assert_eq!(h.log_count(), 0);
        assert_eq!(h.log_dir(), Some(Path::new("/var/log/h")));
        for local in ["", "local", "events_logger"] {
            let h = Healthcheck {
                log_destination: local.into(),
                ..Default::default()
            };
            assert_eq!(h.log_dir(), None);
        }
    }

    #[test]
    fn a_time_below_a_millisecond_survives() {
        let h = Healthcheck {
            interval_ns: 1_500_000,
            timeout_ns: 700,
            startup: Some(StartupHealthcheck {
                interval_ns: 250_000,
                ..Default::default()
            }),
            ..Default::default()
        };
        let back: Healthcheck = serde_json::from_str(&serde_json::to_string(&h).unwrap()).unwrap();
        assert_eq!(back, h);
        assert_eq!(back.interval(), Some(Duration::from_nanos(1_500_000)));
        assert_eq!(back.timeout(), Some(Duration::from_nanos(700)));
        assert_eq!(back.startup.unwrap().interval(), Duration::from_micros(250));
    }

    #[test]
    fn the_stored_restart_policy_keeps_its_words() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Holder {
            #[serde(default, with = "stored_restart")]
            restart_policy: Option<RestartSettings>,
        }
        let held = Holder {
            restart_policy: Some(RestartSettings {
                policy: RestartPolicy::OnFailure,
                max_retries: 3,
            }),
        };
        let text = serde_json::to_string(&held).unwrap();
        assert_eq!(
            text,
            r#"{"restart_policy":{"name":"on-failure","max_retries":3}}"#
        );
        assert_eq!(serde_json::from_str::<Holder>(&text).unwrap(), held);
        assert_eq!(
            serde_json::from_str::<Holder>("{}").unwrap(),
            Holder {
                restart_policy: None
            }
        );
        let unknown = r#"{"restart_policy":{"name":"sometimes"}}"#;
        assert!(serde_json::from_str::<Holder>(unknown).is_err());
    }

    #[test]
    fn a_status_word_goes_both_ways() {
        for s in [
            HealthStatus::Starting,
            HealthStatus::Healthy,
            HealthStatus::Unhealthy,
            HealthStatus::Stopped,
        ] {
            assert_eq!(HealthStatus::from_word(s.word()), s);
            assert_eq!(
                serde_json::to_string(&s).unwrap(),
                format!("\"{}\"", s.word())
            );
        }
    }
}
