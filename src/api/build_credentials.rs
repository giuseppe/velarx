// SPDX-License-Identifier: Apache-2.0
//! The credentials of a build that streams its events: the client keeps its
//! auth file and the build asks, for each reference it pulls, for the
//! entries of the endpoints that reference reaches.  The question is an
//! event of the stream (`credentials`, with the number of the question and
//! the endpoints); the client answers it with a call of its own
//! (`ImageBuildAnswer`).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};
use velarx_core::services::build::CredentialSource;
use velarx_registry::Credentials;

type Answer = BTreeMap<String, Credentials>;

/// The questions of the builds that wait for their answer.
#[derive(Default)]
pub struct Asks {
    pending: Mutex<HashMap<String, oneshot::Sender<Answer>>>,
}

impl Asks {
    /// Give `answer` to the build that asked `ask`: whether one waited.
    pub fn answer(&self, ask: &str, answer: Answer) -> bool {
        let waiting = self
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(ask);
        waiting.is_some_and(|tx| tx.send(answer).is_ok())
    }

    #[cfg(test)]
    fn waiting(&self) -> usize {
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// A question that is not answered any more (the build ended or went
/// away) is forgotten.
struct Forget<'a>(&'a Asks, &'a str);

impl Drop for Forget<'_> {
    fn drop(&mut self) {
        self.0
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(self.1);
    }
}

/// The credentials a client gives on request, through the events of its
/// build.
#[derive(Clone)]
pub struct StreamAsker {
    asks: Arc<Asks>,
    events: mpsc::Sender<String>,
}

impl std::fmt::Debug for StreamAsker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StreamAsker")
    }
}

impl StreamAsker {
    pub fn new(asks: Arc<Asks>, events: mpsc::Sender<String>) -> Self {
        Self { asks, events }
    }
}

#[async_trait::async_trait]
impl CredentialSource for StreamAsker {
    async fn credentials(&self, scopes: &[String]) -> Result<Answer, String> {
        let ask = velarx_core::services::new_id();
        let (tx, rx) = oneshot::channel();
        self.asks
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(ask.clone(), tx);
        let _forget = Forget(&self.asks, &ask);
        let event = super::podman::build::event_line(&velarx_proto::buildspec::BuildEvent {
            kind: velarx_proto::buildspec::BuildEventKind::Credentials,
            ask: ask.clone(),
            scopes: scopes.to_vec(),
            ..Default::default()
        });
        let gone = || "the client went away".to_string();
        self.events.send(event).await.map_err(|_| gone())?;
        // (a client that goes without an answer does not leave the build
        // waiting)
        tokio::select! {
            answer = rx => answer.map_err(|_| "the client did not answer".to_string()),
            () = self.events.closed() => Err(gone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_question_reaches_the_client_and_its_answer_the_build() {
        let asks = Arc::new(Asks::default());
        let (tx, mut rx) = mpsc::channel(4);
        let asker = StreamAsker::new(asks.clone(), tx);
        let scopes = vec!["r.io/app".to_string()];
        let question = tokio::spawn({
            let scopes = scopes.clone();
            async move { asker.credentials(&scopes).await }
        });
        let event = rx.recv().await.unwrap();
        let data: serde_json::Value = serde_json::from_str(&event).unwrap();
        assert_eq!(data["kind"], "credentials");
        assert_eq!(data["scopes"], serde_json::json!(scopes));
        let ask = data["ask"].as_str().unwrap();
        assert!(!asks.answer("not-an-ask", Answer::new()));
        let mut answer = Answer::new();
        answer.insert("r.io/app".into(), Credentials::basic("u", "p"));
        assert!(asks.answer(ask, answer.clone()));
        assert_eq!(question.await.unwrap().unwrap(), answer);
        assert_eq!(asks.waiting(), 0);
        assert!(!asks.answer(ask, Answer::new()), "answered once");
    }

    #[tokio::test]
    async fn a_client_that_went_away_ends_the_question() {
        let asks = Arc::new(Asks::default());
        let (tx, rx) = mpsc::channel(4);
        drop(rx);
        let asker = StreamAsker::new(asks.clone(), tx);
        assert!(asker.credentials(&["r.io".into()]).await.is_err());
        assert_eq!(asks.waiting(), 0);
    }

    /// A client that goes while the build waits for its answer (it was
    /// asked, it did not answer) ends the wait: the build does not hang.
    #[tokio::test]
    async fn a_client_that_goes_before_it_answers_ends_the_wait() {
        let asks = Arc::new(Asks::default());
        let (tx, mut rx) = mpsc::channel(4);
        let asker = StreamAsker::new(asks.clone(), tx);
        let question = tokio::spawn(async move { asker.credentials(&["r.io".into()]).await });
        rx.recv().await.unwrap();
        drop(rx);
        let answered = tokio::time::timeout(std::time::Duration::from_secs(5), question)
            .await
            .expect("the build still waits");
        assert!(answered.unwrap().is_err());
        assert_eq!(asks.waiting(), 0);
    }

    #[tokio::test]
    async fn a_dropped_build_forgets_its_question() {
        let asks = Arc::new(Asks::default());
        let (tx, mut rx) = mpsc::channel(4);
        let asker = StreamAsker::new(asks.clone(), tx);
        let question = tokio::spawn(async move { asker.credentials(&["r.io".into()]).await });
        rx.recv().await.unwrap();
        question.abort();
        let _ = question.await;
        assert_eq!(asks.waiting(), 0);
    }
}
