// SPDX-License-Identifier: Apache-2.0
//! Health checks: a command run in the container at an interval, and what
//! is made of its results.

use velarx_proto::health::Healthcheck;

use super::proto::{Health, HealthResult, HealthStatus};

/// Results kept when the count is not limited (`--health-max-log-count 0`):
/// a bound all the same, for the memory of the monitor.
const UNLIMITED_ENTRIES: usize = 10_000;

/// What a result of the startup check leads to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupOutcome {
    /// Keep checking.
    Again,
    /// The container has started: the regular check begins.
    Passed,
    /// Too many failures: the container is restarted.
    Restart,
}

/// The state of the checks of one run of a container.
#[derive(Debug, Clone)]
pub struct Tracker {
    pub health: Health,
    /// When the container started, nanoseconds since the epoch.
    started_ns: i64,
    /// While the startup check runs: its successes and failures.
    startup: Option<(u32, u32)>,
}

impl Tracker {
    pub fn new(started_ns: i64) -> Self {
        Self {
            health: Health {
                status: HealthStatus::Starting,
                failing_streak: 0,
                log: Vec::new(),
            },
            started_ns,
            startup: None,
        }
    }

    /// A tracker that runs the startup check of `cfg` first, if it has one.
    pub fn for_config(cfg: &Healthcheck, started_ns: i64) -> Self {
        let mut t = Self::new(started_ns);
        if cfg.startup.as_ref().is_some_and(|s| s.command().is_some()) {
            t.startup = Some((0, 0));
        }
        t
    }

    /// Whether the startup check runs (and not the regular one).
    pub fn in_startup(&self) -> bool {
        self.startup.is_some()
    }

    /// Take a result of the startup check: the status stays `starting`.
    pub fn record_startup(&mut self, cfg: &Healthcheck, result: HealthResult) -> StartupOutcome {
        let Some(startup) = &cfg.startup else {
            self.startup = None;
            return StartupOutcome::Passed;
        };
        let (mut ok, mut failed) = self.startup.unwrap_or((0, 0));
        if result.exit_code == 0 {
            ok += 1;
        } else {
            failed += 1;
        }
        self.keep(cfg, result);
        if ok >= startup.successes.max(1) {
            self.startup = None;
            return StartupOutcome::Passed;
        }
        self.startup = Some((ok, failed));
        if startup.retries > 0 && failed >= startup.retries {
            // A new run starts with the startup check again.
            self.startup = Some((0, 0));
            return StartupOutcome::Restart;
        }
        StartupOutcome::Again
    }

    /// Keep a result in the log, within its limits.
    fn keep(&mut self, cfg: &Healthcheck, mut result: HealthResult) {
        let size = cfg.log_size() as usize;
        if size > 0 && result.output.chars().count() > size {
            result.output = result.output.chars().take(size).collect();
        }
        self.health.log.push(result);
        let count = match cfg.log_count() {
            0 => UNLIMITED_ENTRIES,
            n => (n as usize).min(UNLIMITED_ENTRIES),
        };
        let extra = self.health.log.len().saturating_sub(count);
        self.health.log.drain(..extra);
    }

    /// Take the result of a check that failed as the container stops: the
    /// status is `stopped` and the failing streak stays; whether the status
    /// changed.
    pub fn record_stopped(&mut self, cfg: &Healthcheck, result: HealthResult) -> bool {
        let before = self.health.status;
        self.health.status = HealthStatus::Stopped;
        self.keep(cfg, result);
        before != self.health.status
    }

    /// Take a result; whether the status changed.
    pub fn record(&mut self, cfg: &Healthcheck, result: HealthResult) -> bool {
        let before = self.health.status;
        if result.exit_code == 0 {
            self.health.status = HealthStatus::Healthy;
            self.health.failing_streak = 0;
        } else {
            // Failures in the start period do not count, unless the
            // container was healthy already.
            let in_start_period = cfg.start_period_ns > 0
                && result.end_ns
                    < self
                        .started_ns
                        .saturating_add(i64::try_from(cfg.start_period_ns).unwrap_or(i64::MAX));
            if !in_start_period || before == HealthStatus::Healthy {
                self.health.failing_streak += 1;
            }
            if self.health.failing_streak >= i64::from(cfg.failures_allowed()) {
                self.health.status = HealthStatus::Unhealthy;
            }
        }
        self.keep(cfg, result);
        before != self.health.status
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_proto::health::{StartupHealthcheck, LOG_OUTPUT_CHARS};

    fn cfg(retries: u32, start_period_ms: u64) -> Healthcheck {
        Healthcheck {
            test: vec!["true".into()],
            interval_ns: 1_000_000_000,
            timeout_ns: 1_000_000_000,
            start_period_ns: start_period_ms * 1_000_000,
            retries,
            ..Default::default()
        }
    }

    fn result(code: i32, end_s: i64) -> HealthResult {
        HealthResult {
            start_ns: end_s * 1_000_000_000,
            end_ns: end_s * 1_000_000_000,
            exit_code: i64::from(code),
            output: String::new(),
        }
    }

    #[test]
    fn a_check_ended_by_the_stop_is_stopped_and_does_not_count() {
        let mut t = Tracker::new(0);
        let c = cfg(1, 0);
        assert!(t.record(&c, result(0, 1)));
        assert_eq!(t.health.status, HealthStatus::Healthy);
        assert!(t.record_stopped(&c, result(1, 2)));
        assert_eq!(t.health.status, HealthStatus::Stopped);
        assert_eq!(t.health.failing_streak, 0);
        assert_eq!(t.health.log.len(), 2);
    }

    #[test]
    fn retries_make_it_unhealthy_and_a_success_heals() {
        let mut t = Tracker::new(0);
        let c = cfg(3, 0);
        assert!(!t.record(&c, result(1, 1)));
        assert!(!t.record(&c, result(1, 2)));
        assert_eq!(
            (t.health.status.word(), t.health.failing_streak),
            ("starting", 2)
        );
        assert!(t.record(&c, result(1, 3)));
        assert_eq!(t.health.status, HealthStatus::Unhealthy);
        assert!(!t.record(&c, result(1, 4)));
        assert!(t.record(&c, result(0, 5)));
        assert_eq!(
            (t.health.status.word(), t.health.failing_streak),
            ("healthy", 0)
        );
    }

    #[test]
    fn a_start_period_beyond_the_clock_does_not_overflow() {
        for ns in [i64::MAX as u64, u64::MAX] {
            let mut t = Tracker::new(1_767_323_045_000_000_000);
            let c = Healthcheck {
                start_period_ns: ns,
                ..cfg(1, 0)
            };
            assert!(!t.record(&c, result(1, 1_767_323_046)));
            assert_eq!(t.health.failing_streak, 0);
        }
    }

    #[test]
    fn failures_in_the_start_period_do_not_count() {
        let mut t = Tracker::new(0);
        let c = cfg(2, 10_000);
        for s in 1..=5 {
            t.record(&c, result(1, s));
        }
        assert_eq!(
            (t.health.status.word(), t.health.failing_streak),
            ("starting", 0)
        );
        // After it, they do.
        t.record(&c, result(1, 11));
        t.record(&c, result(1, 12));
        assert_eq!(t.health.status, HealthStatus::Unhealthy);
        // A healthy container is judged even in the start period.
        let mut t = Tracker::new(0);
        t.record(&c, result(0, 1));
        t.record(&c, result(1, 2));
        t.record(&c, result(1, 3));
        assert_eq!(t.health.status, HealthStatus::Unhealthy);
    }

    #[test]
    fn only_the_last_results_are_kept() {
        let mut t = Tracker::new(0);
        let c = cfg(100, 0);
        for s in 0..9 {
            t.record(&c, result(1, s));
        }
        assert_eq!(t.health.log.len(), 5);
        assert_eq!(t.health.log[0].start_ns, 4_000_000_000);
    }

    fn startup(retries: u32, successes: u32) -> Healthcheck {
        Healthcheck {
            startup: Some(StartupHealthcheck {
                test: vec!["true".into()],
                interval_ns: 1_000_000_000,
                timeout_ns: 1_000_000_000,
                retries,
                successes,
            }),
            ..cfg(3, 0)
        }
    }

    #[test]
    fn the_startup_check_comes_first_and_keeps_the_status_starting() {
        let c = startup(0, 2);
        let mut t = Tracker::for_config(&c, 0);
        assert!(t.in_startup());
        assert_eq!(t.record_startup(&c, result(1, 1)), StartupOutcome::Again);
        assert_eq!(t.record_startup(&c, result(1, 2)), StartupOutcome::Again);
        assert_eq!(t.record_startup(&c, result(0, 3)), StartupOutcome::Again);
        assert_eq!(t.health.status, HealthStatus::Starting);
        assert_eq!(t.record_startup(&c, result(0, 4)), StartupOutcome::Passed);
        assert!(!t.in_startup());
        assert_eq!(
            (t.health.status.word(), t.health.failing_streak),
            ("starting", 0)
        );
        assert_eq!(t.health.log.len(), 4);
        // Then the regular check judges.
        assert!(t.record(&c, result(0, 5)));
        assert_eq!(t.health.status, HealthStatus::Healthy);
    }

    #[test]
    fn startup_failures_restart_the_container() {
        let c = startup(2, 0);
        let mut t = Tracker::for_config(&c, 0);
        assert_eq!(t.record_startup(&c, result(1, 1)), StartupOutcome::Again);
        assert_eq!(t.record_startup(&c, result(1, 2)), StartupOutcome::Restart);
        assert!(t.in_startup());
        // No retries: never.
        let c = startup(0, 0);
        let mut t = Tracker::for_config(&c, 0);
        for s in 0..10 {
            assert_eq!(t.record_startup(&c, result(1, s)), StartupOutcome::Again);
        }
        // A tracker without a startup check starts with the regular one.
        assert!(!Tracker::for_config(&cfg(3, 0), 0).in_startup());
    }

    #[test]
    fn the_log_limits() {
        let mut c = cfg(100, 0);
        c.max_log_count = Some(3);
        c.max_log_size = Some(4);
        let mut t = Tracker::new(0);
        for s in 0..6 {
            let mut r = result(1, s);
            r.output = "abcdefgh".into();
            t.record(&c, r);
        }
        assert_eq!(t.health.log.len(), 3);
        assert_eq!(t.health.log[0].output, "abcd");
        c.max_log_count = Some(0);
        c.max_log_size = Some(0);
        let mut t = Tracker::new(0);
        for s in 0..20 {
            let mut r = result(1, s);
            r.output = "abcdefgh".into();
            t.record(&c, r);
        }
        assert_eq!(t.health.log.len(), 20);
        assert_eq!(t.health.log[0].output, "abcdefgh");
    }

    #[test]
    fn the_output_is_cut() {
        let mut t = Tracker::new(0);
        let mut r = result(0, 1);
        r.output = "é".repeat(LOG_OUTPUT_CHARS as usize + 10);
        t.record(&cfg(100, 0), r);
        assert_eq!(
            t.health.log[0].output.chars().count(),
            LOG_OUTPUT_CHARS as usize
        );
    }
}
