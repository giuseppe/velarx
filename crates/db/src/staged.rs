// SPDX-License-Identifier: Apache-2.0
//! The commits of a lazy pull.  The store holds only complete layers and
//! images: the layers of a pull in progress live in `staging/lazy` (the
//! files, `velarx_content::pull::staged`) and each enters the database in one
//! transaction when it is complete, the image in the transaction of its last
//! layer, or alone when every layer was there.

use super::{commit_layer, write_image, Database, DbError, DbResult};
use crate::{BlobSource, ImageTag, LayerCommit, LayerKey, PullCommit};
use velarx_types::digest::Digest;

/// A layer of a lazy pull that is complete: its files are in `objects/`, its
/// tar-split was replayed against its diff id.
pub struct StagedLayerCommit {
    pub layer: LayerCommit,
    /// The pull may be shared: the layer may have its files asked of the
    /// content sources.
    pub public: bool,
    /// No byte of the layer came from the store as it was: it may be given.
    pub proven: bool,
}

/// The image of a lazy pull whose layers are all in the store.
pub struct StagedImageCommit {
    /// The image, its layers, its names and the repositories of its blobs;
    /// `layers` is empty (each was committed on its own).
    pub pull: PullCommit,
    /// When the pull started (RFC 3339): a name goes to this image only if
    /// the image that holds it in the store was recorded before.
    pub started_at: String,
    /// The references the image was pulled by and the signatures found.
    pub pulled: Vec<(String, Vec<u8>)>,
    /// The names the image may be announced under, when the pull may be
    /// shared.
    pub shared: Option<Vec<(String, String)>>,
}

impl Database {
    /// The layers a lazy pull fetched whole, with where their blobs are, in
    /// one transaction: complete layers, and no image yet.  `shared`: the
    /// layers of a pull that may be shared, and whether each is proven.
    pub async fn commit_layers(
        &self,
        layers: Vec<LayerCommit>,
        sources: Vec<BlobSource>,
        shared: Vec<(LayerKey, bool)>,
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
                for (key, proven) in &shared {
                    share_layer(&tx, key, *proven)?;
                }
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// A layer of a lazy pull, complete, in one transaction: its row, files,
    /// references and chunks, and whether it may be shared.
    pub async fn commit_staged_layer(&self, commit: StagedLayerCommit) -> DbResult<()> {
        self.conn
            .call(move |conn| {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                commit_layer(&tx, &commit.layer)?;
                if commit.public {
                    share_layer(&tx, &commit.layer.record.key, commit.proven)?;
                }
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// The image of a lazy pull, once every layer of it is in the store:
    /// the image, its layers, its names (those that a newer image of the
    /// store does not have), the signatures of its pulls and the right to
    /// announce it.
    pub async fn commit_staged_image(&self, commit: StagedImageCommit) -> DbResult<()> {
        self.conn
            .call(move |conn| {
                let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let StagedImageCommit {
                    mut pull,
                    started_at,
                    pulled,
                    shared,
                } = commit;
                pull.tags.retain(|t| !tag_is_newer(&tx, t, &started_at));
                pull.digest_names
                    .retain(|(r, d)| !digest_name_is_newer(&tx, r, d, &pull.image.id, &started_at));
                write_image(&tx, &pull)?;
                let manifest_digest = pull.image.manifest_digest;
                for (reference, signatures) in &pulled {
                    tx.execute(
                        "INSERT OR REPLACE INTO pulled_images (manifest_digest, reference, signatures)
                         VALUES (?1, ?2, ?3)",
                        rusqlite::params![manifest_digest, reference, signatures],
                    )?;
                }
                if let Some(names) = shared {
                    for (repository, tag) in
                        std::iter::once((String::new(), String::new())).chain(names)
                    {
                        tx.execute(
                            "INSERT OR IGNORE INTO shared_images (image_id, repository, tag)
                             VALUES (?1, ?2, ?3)",
                            rusqlite::params![pull.image.id, repository, tag],
                        )?;
                    }
                }
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

fn share_layer(tx: &rusqlite::Transaction, key: &LayerKey, proven: bool) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO shared_layers (layer_id, proven)
         SELECT id, ?2 FROM layers WHERE id = ?1
         ON CONFLICT(layer_id) DO UPDATE SET proven = MAX(proven, ?2)",
        rusqlite::params![key, proven as i64],
    )?;
    Ok(())
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
