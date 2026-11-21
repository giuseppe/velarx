// SPDX-License-Identifier: Apache-2.0
//! The commits of a lazy pull.  The store holds only complete layers and
//! images: the layers of a pull in progress live in `staging/lazy` (the
//! files, `velarx_content::pull::staged`) and each enters the database in one
//! transaction when it is complete, the image in the transaction of its last
//! layer, or alone when every layer was there.

use super::{commit_layer, write_image, Database, DbError, DbResult};
use crate::{BlobSource, ImageTag, LayerCommit, LayerKey, PullCommit};
use velarx_types::digest::Digest;

/// The image of a lazy pull whose layers are all in the store.
pub struct StagedImageCommit {
    /// The image, its layers, its names and the repositories of its blobs;
    /// `layers` is empty (each was committed on its own).
    pub pull: PullCommit,
    /// When the pull started (RFC 3339): a name goes to this image only if
    /// the image that holds it in the store was recorded before.
    pub started_at: String,
}

impl Database {
    /// Complete layers, with where their blobs are, in one transaction, and
    /// no image yet: the layers a lazy pull fetched whole, or one its
    /// completion made complete.
    pub async fn commit_layers(
        &self,
        layers: Vec<LayerCommit>,
        sources: Vec<BlobSource>,
    ) -> DbResult<()> {
        self.conn
            .call(move |conn| {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                for layer in &layers {
                    commit_layer(&tx, layer)?;
                }
                for source in &sources {
                    super::add_blob_source(&tx, source)?;
                }
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// The image of a lazy pull, once every layer of it is in the store:
    /// the image, its layers, its names (those that a newer image of the
    /// store does not have) and the signatures of its pulls.
    pub async fn commit_staged_image(&self, commit: StagedImageCommit) -> DbResult<()> {
        self.conn
            .call(move |conn| {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let StagedImageCommit {
                    mut pull,
                    started_at,
                } = commit;
                pull.tags.retain(|t| !tag_is_newer(&tx, t, &started_at));
                pull.digest_names
                    .retain(|(r, d)| !digest_name_is_newer(&tx, r, d, &pull.image.id, &started_at));
                write_image(&tx, &pull)?;
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// Whether the store has the layer (complete: the store has no other).
    pub async fn has_layer(&self, key: &LayerKey) -> DbResult<bool> {
        let key = *key;
        self.conn
            .call(move |conn| {
                Ok(conn
                    .prepare_cached("SELECT 1 FROM layers WHERE id = ?1")?
                    .exists([&key])?)
            })
            .await
            .map_err(DbError::Sqlite)
    }
}

/// The tag is held by another image of the store that was recorded after
/// the pull started: the newer pull keeps its name.
fn tag_is_newer(tx: &rusqlite::Transaction, tag: &ImageTag, started_at: &str) -> bool {
    tx.query_row(
        "SELECT 1 FROM image_tags t JOIN images i ON i.id = t.image_id
         WHERE t.repository = ?1 AND t.tag = ?2 AND t.image_id != ?3 AND i.created_at > ?4",
        rusqlite::params![tag.repository, tag.tag, tag.image_id, started_at],
        |_| Ok(()),
    )
    .is_ok()
}

fn digest_name_is_newer(
    tx: &rusqlite::Transaction,
    repository: &str,
    digest: &Digest,
    image_id: &str,
    started_at: &str,
) -> bool {
    tx.query_row(
        "SELECT 1 FROM image_digest_names n JOIN images i ON i.id = n.image_id
         WHERE n.repository = ?1 AND n.digest = ?2 AND n.image_id != ?3 AND i.created_at > ?4",
        rusqlite::params![repository, digest, image_id, started_at],
        |_| Ok(()),
    )
    .is_ok()
}
