// SPDX-License-Identifier: Apache-2.0
//! The one place where a transfer that fails on the way is tried again
//! (`--retry`, `--retry-delay`): pulls, pushes, artifacts and the base images
//! of a build.  The engine tries again, so that every frontend gets the same
//! rule and the progress of the tries comes on one stream.

use std::future::Future;
use std::time::Duration;
use velarx_proto::retry::Retry;
use velarx_types::ImageResult;

/// A try that follows a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attempt {
    /// This try, from 1.
    pub n: u32,
    /// The most tries after the first.
    pub of: u32,
    /// The time to wait before it.
    pub wait: Duration,
}

impl Attempt {
    /// What is told of the failure `error` before this try, in podman's
    /// words (`Failed, retrying in 1s ... (1/3). Error: ...`).
    pub fn note(&self, error: &str) -> String {
        let wait = i64::try_from(self.wait.as_nanos()).unwrap_or(i64::MAX);
        format!(
            "Failed, retrying in {} ... ({}/{}). Error: {error}",
            velarx_proto::duration::go_duration_string(wait),
            self.n,
            self.of
        )
    }
}

/// `op`, tried again as `retry` says while it fails with what may pass
/// ([`ImageError::is_transient`]); `told` hears of each failure (its words)
/// before the wait.  The last failure is the answer when the tries are used up.
pub async fn retried<T, F, Fut, N, NFut>(retry: &Retry, mut op: F, mut told: N) -> ImageResult<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ImageResult<T>>,
    N: FnMut(String, Attempt) -> NFut,
    NFut: Future<Output = ()>,
{
    let mut n = 0;
    loop {
        match op().await {
            Err(e) if n < retry.count && e.is_transient() => {
                n += 1;
                let wait = retry.wait();
                told(
                    e.to_string(),
                    Attempt {
                        n,
                        of: retry.count,
                        wait,
                    },
                )
                .await;
                tokio::time::sleep(wait).await;
            }
            r => return r,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use velarx_types::ImageError;

    fn transient() -> ImageError {
        ImageError::Registry("503 Service Unavailable".into())
    }

    /// A failure that may pass is tried again, up to the count, and each
    /// failure is told with the wait that follows it.
    #[tokio::test(start_paused = true)]
    async fn a_transient_failure_is_tried_again_up_to_the_count() {
        let retry = Retry {
            count: 3,
            delay_ms: None,
        };
        let calls = Cell::new(0);
        let told = RefCell::new(Vec::new());
        let r = retried(
            &retry,
            || {
                calls.set(calls.get() + 1);
                let ok = calls.get() == 3;
                async move {
                    if ok {
                        Ok(())
                    } else {
                        Err(transient())
                    }
                }
            },
            |e, a| {
                told.borrow_mut().push((e, a));
                async {}
            },
        )
        .await;
        assert!(r.is_ok());
        assert_eq!(calls.get(), 3);
        let told = told.into_inner();
        assert_eq!(told.len(), 2);
        assert_eq!(
            told.iter()
                .map(|(_, a)| (a.n, a.of, a.wait))
                .collect::<Vec<_>>(),
            [
                (1, 3, Duration::from_secs(1)),
                (2, 3, Duration::from_secs(1))
            ]
        );

        let calls = Cell::new(0);
        let last = retried::<(), _, _, _, _>(
            &Retry {
                count: 2,
                delay_ms: Some(10),
            },
            || {
                calls.set(calls.get() + 1);
                async { Err(transient()) }
            },
            |_, _| async {},
        )
        .await;
        assert!(matches!(last, Err(ImageError::Registry(_))));
        assert_eq!(calls.get(), 3, "the first try and two more");
    }

    /// A try is told in podman's words, the wait as Go writes it.
    #[test]
    fn a_try_is_told_as_podman_tells_it() {
        let at = |n, ms| Attempt {
            n,
            of: 3,
            wait: Duration::from_millis(ms),
        };
        assert_eq!(
            at(1, 1000).note("503"),
            "Failed, retrying in 1s ... (1/3). Error: 503"
        );
        assert_eq!(
            at(2, 1500).note("x"),
            "Failed, retrying in 1.5s ... (2/3). Error: x"
        );
        assert_eq!(
            at(3, 250).note("x"),
            "Failed, retrying in 250ms ... (3/3). Error: x"
        );
    }

    /// What a user must mend is not tried again, whatever the count.
    #[tokio::test(start_paused = true)]
    async fn a_refusal_is_not_tried_again() {
        let calls = Cell::new(0);
        let r = retried::<(), _, _, _, _>(
            &Retry {
                count: 5,
                delay_ms: Some(1),
            },
            || {
                calls.set(calls.get() + 1);
                async { Err(ImageError::Unauthorized("denied".into())) }
            },
            |_, _| async { panic!("nothing to tell") },
        )
        .await;
        assert!(matches!(r, Err(ImageError::Unauthorized(_))));
        assert_eq!(calls.get(), 1);
    }
}
