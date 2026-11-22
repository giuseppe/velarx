// SPDX-License-Identifier: Apache-2.0
//! The pulls in progress: images whose layers are not all in the store.
//! They are not images of the store (`images` lists them with `--lazy`);
//! they are listed by `image pulls`, finished by `image complete`, cancelled
//! by `rmi`, and a container made with `--lazy` runs on one.

use super::*;
use velarx_content::pull::staged::{PullEntry, PullState, StagedPull};
use velarx_db::{LayerKey, LayerRecord};

/// A pull in progress as `image pulls` shows it.
#[derive(Debug, Clone)]
pub struct PullInfo {
    pub id: String,
    /// `repository:tag` and `repository@digest`
    pub names: Vec<String>,
    pub state: velarx_proto::workload::PullState,
    /// Why it failed, or the last error that was retried
    pub error: Option<String>,
    pub percent: u64,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub layers_done: u64,
    pub layers_total: u64,
    /// The containers made on it
    pub containers: u64,
    /// A process completes it now
    pub completer_alive: bool,
    pub started_at: String,
}

/// The error of a command that wants an image of the store when the name is
/// that of a pull in progress.
pub(super) fn pulling_error(reference: &str, entry: &PullEntry) -> ImageError {
    ImageError::Pulling(format!(
        "{reference} is being pulled ({}%, `velarx image pulls`): wait for it with `velarx image complete {reference}`, or run it with --lazy",
        entry.progress.percent()
    ))
}

impl ImageService {
    /// Whether a container is made on the image `id`.
    pub async fn containers_use(&self, id: &str) -> ImageResult<bool> {
        Ok(!self.db.containers_using_image(id).await?.is_empty())
    }

    /// The pull in progress that `reference` names.
    pub fn pulling(&self, reference: &str) -> Option<PullEntry> {
        self.staging_area().find(reference)
    }

    /// The pulls in progress.
    pub async fn pulls(&self) -> ImageResult<Vec<PullInfo>> {
        self.resume_pulls();
        let mut out = Vec::new();
        for entry in self.staging_area().pulls() {
            // a cancelled pull is not listed; its staging goes once its
            // completer has stopped
            if entry.state.state == PullState::Cancelled {
                if !entry.completer_alive {
                    self.discard_pull(&entry.pull).await;
                }
                continue;
            }
            let containers = self.db.containers_using_image(&entry.pull.id).await?.len() as u64;
            out.push(self.pull_info(&entry, containers));
        }
        Ok(out)
    }

    fn pull_info(&self, entry: &PullEntry, containers: u64) -> PullInfo {
        let mut names: Vec<String> = entry
            .pull
            .tags
            .iter()
            .map(|t| format!("{}:{}", t.repository, t.tag))
            .collect();
        names.extend(
            entry
                .pull
                .digest_names
                .iter()
                .map(|(r, d)| format!("{r}@{d}")),
        );
        use velarx_proto::workload::PullState as Shown;
        let (state, error) = match &entry.state.state {
            PullState::Failed { reason } => (Shown::Failed, Some(reason.clone())),
            PullState::Queued => (Shown::Queued, entry.progress.error.clone()),
            PullState::Running => (Shown::Running, entry.progress.error.clone()),
            PullState::NeedsCredentials => (Shown::NeedsCredentials, entry.progress.error.clone()),
            PullState::WaitingForSpace => (Shown::WaitingForSpace, entry.progress.error.clone()),
            PullState::Cancelled => (Shown::Cancelled, entry.progress.error.clone()),
        };
        // (a pull that should run and has no process: stalled until a
        // command starts the completer)
        let state = if entry.state.state.is_open() && !entry.completer_alive {
            Shown::Stalled
        } else {
            state
        };
        PullInfo {
            id: entry.pull.id.clone(),
            names,
            state,
            error,
            percent: entry.progress.percent(),
            bytes_done: entry.progress.bytes_done,
            bytes_total: entry.progress.bytes_total,
            layers_done: entry.progress.layers_done,
            layers_total: entry.progress.layers_total,
            containers,
            completer_alive: entry.completer_alive,
            started_at: entry.pull.started_at.clone(),
        }
    }

    /// The pull `reference` names, as the image a container runs on
    /// (`--lazy`): the record, its names, and the pull.
    pub async fn staged_image(
        &self,
        reference: &str,
    ) -> ImageResult<Option<(ImageRecord, Vec<ImageTag>, StagedPull)>> {
        let Some(entry) = self.pulling(reference) else {
            return Ok(None);
        };
        self.resume_pulls();
        match &entry.state.state {
            PullState::Cancelled => return Ok(None),
            PullState::Failed { reason } => {
                return Err(ImageError::Pulling(format!(
                    "the pull of {reference} failed: {reason}: `velarx image complete {reference}` tries again"
                )))
            }
            _ => {}
        }
        let tags = entry
            .pull
            .tags
            .iter()
            .map(|t| ImageTag {
                repository: t.repository.clone(),
                tag: t.tag.clone(),
                image_id: entry.pull.id.clone(),
            })
            .collect();
        Ok(Some((entry.pull.image_record(), tags, entry.pull)))
    }

    /// The image a container with this image id runs on: the image of the
    /// store, else the pull in progress that has the id.  A pull that was
    /// cancelled or failed is no image to start a container on.
    pub async fn get_for_run(
        &self,
        id: &str,
    ) -> ImageResult<(ImageRecord, Vec<ImageTag>, Option<StagedPull>)> {
        match self.get_with_tags(id).await {
            Ok((image, tags)) => Ok((image, tags, None)),
            Err(ImageError::Pulling(_)) => {
                let entry = self
                    .staging_area()
                    .find(id)
                    .ok_or_else(|| ImageError::NotFound(id.to_string()))?;
                match &entry.state.state {
                    PullState::Cancelled => Err(ImageError::Pulling(format!(
                        "the pull of image {id} was cancelled"
                    ))),
                    PullState::Failed { reason } => Err(ImageError::Pulling(format!(
                        "the pull of image {id} failed: {reason}"
                    ))),
                    _ => {
                        let tags = entry
                            .pull
                            .tags
                            .iter()
                            .map(|t| ImageTag {
                                repository: t.repository.clone(),
                                tag: t.tag.clone(),
                                image_id: entry.pull.id.clone(),
                            })
                            .collect();
                        Ok((entry.pull.image_record(), tags, Some(entry.pull)))
                    }
                }
            }
            Err(e) => Err(e),
        }
    }

    /// The pulls in progress that are not cancelled, the oldest first.
    pub fn staged_pulls(&self) -> Vec<StagedPull> {
        self.staging_area()
            .pulls()
            .into_iter()
            .filter(|e| e.state.state != PullState::Cancelled)
            .map(|e| e.pull)
            .collect()
    }

    /// The layers of the image being pulled `id`, in order: a layer the
    /// store has is its record, the others are staged (`status` `lazy`).
    pub async fn staged_layers(&self, id: &str) -> ImageResult<Vec<LayerRecord>> {
        let pull = self
            .staging_area()
            .pull(id)?
            .ok_or_else(|| ImageError::NotFound(format!("the pull of image {id}")))?;
        self.layers_of_pull(&pull).await
    }

    /// The layers of the pull `pull`, as [`Self::staged_layers`].
    pub async fn layers_of_pull(&self, pull: &StagedPull) -> ImageResult<Vec<LayerRecord>> {
        let area = self.staging_area();
        let mut out = Vec::with_capacity(pull.layers.len());
        for key in &pull.layers {
            let key = LayerKey::parse(key)
                .ok_or_else(|| ImageError::Layer(format!("{key:?} is no layer key")))?;
            if let Some(staged) = area.layer(&key)? {
                out.push(staged.record());
                continue;
            }
            out.push(self.db.get_layer(&key).await?);
        }
        Ok(out)
    }

    /// Cancel the pull `reference` names: nothing more is fetched and its
    /// staging goes (now, or with the next garbage collection).  Refused
    /// while a container is made on it, unless `force` (the callers remove
    /// those containers first, as `rmi -f` does).
    pub async fn cancel_pull(&self, reference: &str, force: bool) -> ImageResult<()> {
        let area = self.staging_area();
        let entry = area
            .find(reference)
            .ok_or_else(|| ImageError::NotFound(reference.to_string()))?;
        if let Some(c) = self
            .db
            .containers_using_image(&entry.pull.id)
            .await?
            .first()
        {
            return Err(ImageError::Storage(format!(
                "image is in use by the container {c}{}",
                if force {
                    ""
                } else {
                    ": remove it first, or force"
                }
            )));
        }
        // (the engine service that completes it cancels it: it stops what
        // it fetches for it)
        if entry.completer_alive {
            if let Some(h) = self.hand_off() {
                return h.cancel(&entry.pull.id, force).await;
            }
        }
        area.set_state(&entry.pull.id, PullState::Cancelled, entry.state.pid)?;
        // (the completion stops: its fetches in flight are dropped; the
        // staging of a pull that nothing completes goes now, the other with
        // the next garbage collection)
        if !self.stop_completion(&entry.pull.id).await && !entry.completer_alive {
            self.discard_pull(&entry.pull).await;
        }
        Ok(())
    }

    /// Remove the staging of a pull and the staged layers no other pull
    /// names, with the files staged for them.
    pub(super) async fn discard_pull(&self, pull: &StagedPull) {
        let area = self.staging_area();
        if let Err(e) = area.remove_pull(&pull.id) {
            warn!("Cannot remove the staging of the pull {}: {e}", pull.id);
        }
        // (one a process fetches into goes with the next collection)
        for key in area.unnamed_layers() {
            // (the fetchers forget a layer that went)
            if matches!(area.remove_layer_unless_leased(&key), Ok(true)) {
                self.forget_lazy(&key).await;
            }
        }
    }
}
