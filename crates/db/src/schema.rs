// SPDX-License-Identifier: Apache-2.0
use rusqlite::{Connection, TransactionBehavior};

/// The version of the schema, kept in `PRAGMA user_version`: a database of
/// another version is not opened, and a new file (`user_version` 0, no table)
/// is told from a made one.  It stays 1: a change of the schema edits it in
/// place with no bump, and a store made by another build is not told when it
/// is opened, it fails at the first statement that needs the new shape.
pub const SCHEMA_VERSION: i64 = 1;

#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    #[error(
        "the database is of schema version {found}, this velarx uses {SCHEMA_VERSION}: \
         it is not opened (remove the store, or use the velarx that made it)"
    )]
    Version { found: i64 },
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

/// The tables of the database.  `PRAGMA user_version` is 0 for a file with
/// no table of ours; it is then made, in one transaction that the processes
/// opening it together wait for.
pub(super) fn init(conn: &mut Connection) -> Result<(), SchemaError> {
    let found: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if found == SCHEMA_VERSION {
        return Ok(());
    }
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let found: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if found == SCHEMA_VERSION {
        return Ok(());
    }
    let tables: i64 = tx.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        [],
        |r| r.get(0),
    )?;
    if found != 0 || tables != 0 {
        return Err(SchemaError::Version { found });
    }
    for sql in SCHEMAS {
        tx.execute_batch(sql)?;
    }
    tx.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))?;
    tx.commit()?;
    // (no row was counted: the tables are a write that must survive)
    super::volatile::mark_durable();
    Ok(())
}

/// Every schema `init` makes, in order: `SCHEMA` and the tables of the
/// other modules.  A table of the store is made here, never by its service
/// when it starts.
pub(super) const SCHEMAS: [&str; 8] = [
    SCHEMA,
    super::container_ext::SCHEMA,
    super::manifests::SCHEMA,
    super::build_cache::SCHEMA,
    super::checks::SCHEMA,
    super::network_ext::SCHEMA,
    SECRETS,
    super::namespaces::SCHEMA,
];

/// The secrets (velarx_core's `SecretStore`): their data is in files of the
/// store, by id.
const SECRETS: &str = "
CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    driver TEXT,
    labels TEXT,
    driver_opts TEXT,
    created INTEGER NOT NULL,
    updated INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS secret_users (
    secret_id TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    container_id TEXT NOT NULL,
    PRIMARY KEY (secret_id, container_id)
);
";

pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS images (
    id TEXT PRIMARY KEY,
    manifest_digest TEXT NOT NULL UNIQUE,
    config_digest TEXT NOT NULL,
    manifest TEXT NOT NULL,
    config TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_images_manifest_digest ON images(manifest_digest);

CREATE TABLE IF NOT EXISTS image_tags (
    repository TEXT NOT NULL,
    tag TEXT NOT NULL,
    image_id TEXT NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    PRIMARY KEY (repository, tag)
);

CREATE INDEX IF NOT EXISTS idx_image_tags_image_id ON image_tags(image_id);

-- The names `repository@digest` of an image: the repository a pull by
-- digest asked for.  Such an image is named (not dangling) and has the
-- digest among its repo digests, as with podman.  A name is of one image:
-- given to another one (a pull of the same list digest for another
-- platform), it moves.
CREATE TABLE IF NOT EXISTS image_digest_names (
    repository TEXT NOT NULL,
    digest TEXT NOT NULL,
    image_id TEXT NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    PRIMARY KEY (repository, digest)
);

CREATE INDEX IF NOT EXISTS idx_image_digest_names_image_id ON image_digest_names(image_id);

-- Every name an image had, the last one given last (podman's NamesHistory):
-- a name that moved to another image stays in the history of this one.
CREATE TABLE IF NOT EXISTS image_name_history (
    image_id TEXT NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    repository TEXT NOT NULL,
    tag TEXT NOT NULL,
    PRIMARY KEY (image_id, repository, tag)
);

CREATE TRIGGER IF NOT EXISTS image_tags_history AFTER INSERT ON image_tags
BEGIN
    DELETE FROM image_name_history
        WHERE image_id = NEW.image_id AND repository = NEW.repository AND tag = NEW.tag;
    INSERT INTO image_name_history (image_id, repository, tag)
        VALUES (NEW.image_id, NEW.repository, NEW.tag);
END;

-- (a name `repository@digest` is in the history with the tag `@digest`: a
-- tag has no `@`)
CREATE TRIGGER IF NOT EXISTS image_digest_names_history AFTER INSERT ON image_digest_names
BEGIN
    DELETE FROM image_name_history
        WHERE image_id = NEW.image_id AND repository = NEW.repository
            AND tag = '@' || NEW.digest;
    INSERT INTO image_name_history (image_id, repository, tag)
        VALUES (NEW.image_id, NEW.repository, '@' || NEW.digest);
END;

-- What the store was first used with (`runroot`: the state directory of
-- its engine; another one is refused: it would not see these containers),
-- and the indexes (`index:<digest>`) that images were pulled by.
CREATE TABLE IF NOT EXISTS store_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- A layer, by what verified it (velarx_types::LayerKey): `sha256:<hex>`, the
-- blob, for a layer pulled whole (its blob digest and diff id checked);
-- `toc:sha256:<hex>`, the TOC digest of a descriptor with zstd:chunked
-- labels, for a layer pulled through its table of contents (its blob never
-- checked).  `blob`: the digest of the blob of a descriptor of the layer,
-- which the registry of `registry_ref` knows it by (the lazy fetches read
-- it there; the two, and `size`, are of the same pull).  `diff_id`: only
-- once the layer was verified against it (the claim of a layer being pulled
-- is the configuration's, in the staging area).  A layer of a table of
-- contents (`toc:` key), pulled eagerly or lazily, has none until a
-- recreation of its stream checked one: its table is what verified it.  `blob_checked`: the blob was hashed to
-- its digest (not by a layer of a TOC, nor by one made of the files the
-- peers have for a diff id: a layer of the blob pulled whole replaces such
-- a layer whose diff id is another).
CREATE TABLE IF NOT EXISTS layers (
    id TEXT PRIMARY KEY,
    blob TEXT NOT NULL,
    blob_checked INTEGER NOT NULL DEFAULT 0,
    diff_id TEXT,
    -- the diff id of the other algorithm than diff_id's, once a pull of an
    -- image of that algorithm verified the layer against it (the same tar
    -- under the two names: the layer is still the one of its key)
    diff_id_other TEXT,
    size INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    registry_ref TEXT,
    -- the fs-verity digest of the EROFS image of the layer, made at the
    -- pull (velarx_fuse::layer_erofs), and the owners of its files
    -- ([[uids], [gids]])
    erofs TEXT,
    owners TEXT,
    -- 1 when the EROFS image and the objects of the layer were made with
    -- fs-verity (the file system of the store has it): a start holds the
    -- layer to the record, and an image that is not the one recorded is an
    -- error, never a layer without fs-verity.  NULL on a file system without
    -- fs-verity.
    sealed INTEGER,
    -- the size of the uncompressed tar of the layer, from its tar-split, kept
    -- at the pull so that a listing never decodes it (it stays when the
    -- tar-split of a layer marked incomplete is dropped)
    stream_size INTEGER NOT NULL,
    -- The table of contents and the tar-split are files of the layer
    -- (`layers/<stem>/toc-<hex>.zst`, `tarsplit-<hex>.zst`, see `layer_files`), checked
    -- against a digest whenever they are read.  The table of contents of a
    -- layer pulled by its table (`toc:` key) is the table as the registry
    -- sent it, whose digest is the checksum of the key; that of any other
    -- layer is the zstd of its JSON.  NULL while the layer has none.
    toc_digest TEXT,
    -- The digest of the tar-split: NULL for a layer that is not complete,
    -- empty for a layer that has none (and no file), whose table of
    -- contents is of version 2.
    tarsplit_digest TEXT
);

CREATE INDEX IF NOT EXISTS idx_layers_diff_id ON layers(diff_id);

-- Repositories a blob is known to be in (pulled from, or pushed to), to
-- mount it instead of uploading it again; a layer is not always pulled by
-- the name it was first fetched under.
CREATE TABLE IF NOT EXISTS blob_sources (
    digest TEXT NOT NULL,
    registry TEXT NOT NULL,
    repository TEXT NOT NULL,
    PRIMARY KEY (digest, registry, repository)
);

CREATE TABLE IF NOT EXISTS image_layers (
    image_id TEXT NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    layer_id TEXT NOT NULL REFERENCES layers(id) ON DELETE CASCADE,
    layer_index INTEGER NOT NULL,
    PRIMARY KEY (image_id, layer_index)
);

-- The files of the store, by their fs-verity digest (the name of the
-- object); checked: the kernel measured it on the object (it has fs-verity)
CREATE TABLE IF NOT EXISTS files (
    digest TEXT PRIMARY KEY,
    size INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    checked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS file_refs (
    layer_id TEXT NOT NULL REFERENCES layers(id) ON DELETE CASCADE,
    file_digest TEXT NOT NULL REFERENCES files(digest) ON DELETE CASCADE,
    ref_count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (layer_id, file_digest)
);

-- Chunk location index: where a chunk can be found, in which file and at
-- which offset.  A chunk is in every file that has it (two versions of a
-- file share most of their chunks): a row for each, so that what a file
-- gone or not to be given takes away is only its own.
CREATE TABLE IF NOT EXISTS chunk_locations (
    chunk_digest TEXT NOT NULL,
    file_digest TEXT NOT NULL,
    offset INTEGER NOT NULL,
    size INTEGER NOT NULL,
    PRIMARY KEY (chunk_digest, file_digest)
);

CREATE INDEX IF NOT EXISTS idx_chunk_locations_file_digest ON chunk_locations(file_digest);

CREATE TABLE IF NOT EXISTS containers (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE,
    -- an image of the store, or one that is being pulled (`staging/lazy`):
    -- no foreign key
    image_id TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'created',
    pid INTEGER,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    exit_code INTEGER,
    -- the SELinux level of the container (of its process, or of the files
    -- of a privileged one), from its config: the levels in use are read
    -- at every create, without the configs
    selinux_level TEXT,
    -- 1 from the record of the exit of a container that goes with it
    -- (`--rm`) until its removal is done or given up: a removal that its
    -- process did not finish (killed) is found by the next one that opens
    -- the store
    removing INTEGER NOT NULL DEFAULT 0,
    -- last: the big one
    config TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_containers_name ON containers(name);
CREATE INDEX IF NOT EXISTS idx_containers_state ON containers(state);
-- (the levels in use are read from the index alone: a scan of the table
-- reads a page per container)
CREATE INDEX IF NOT EXISTS idx_containers_selinux_level ON containers(selinux_level)
    WHERE selinux_level IS NOT NULL;
-- (empty but for a removal that was interrupted: the read at every start of
-- an engine costs a page)
CREATE INDEX IF NOT EXISTS idx_containers_removing ON containers(id) WHERE removing = 1;

-- The containers a container refers to in its config (`--requires`, the
-- namespaces it joins: `container:TARGET`), as written: the dependents of a
-- container are found at its removal without reading every config.
CREATE TABLE IF NOT EXISTS container_deps (
    container_id TEXT NOT NULL,
    target TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_container_deps_id ON container_deps(container_id);

CREATE TABLE IF NOT EXISTS networks (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    driver TEXT NOT NULL,
    subnet TEXT,
    gateway TEXT,
    options TEXT,
    created_at TEXT NOT NULL,
    subnet6 TEXT,
    gateway6 TEXT
);

CREATE INDEX IF NOT EXISTS idx_networks_name ON networks(name);

CREATE TABLE IF NOT EXISTS userns_allocations (
    id TEXT PRIMARY KEY,
    label TEXT,
    uid_start INTEGER NOT NULL,
    uid_count INTEGER NOT NULL,
    gid_start INTEGER NOT NULL,
    gid_count INTEGER NOT NULL,
    container_id TEXT REFERENCES containers(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_userns_allocations_container_id ON userns_allocations(container_id);

CREATE TABLE IF NOT EXISTS volumes (
    name TEXT PRIMARY KEY,
    driver TEXT NOT NULL DEFAULT 'local',
    mountpoint TEXT NOT NULL,
    labels TEXT,
    options TEXT,
    created_at TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'local',
    state TEXT
);

-- The pulls of images from registries: the manifest, the reference it was
-- pulled by and the signatures found then, which the signature policy is
-- checked against again when a container of the image is made.
CREATE TABLE IF NOT EXISTS pulled_images (
    manifest_digest TEXT NOT NULL,
    reference TEXT NOT NULL,
    signatures BLOB NOT NULL,
    PRIMARY KEY (manifest_digest, reference)
);

CREATE INDEX IF NOT EXISTS idx_file_refs_file ON file_refs(file_digest);
CREATE INDEX IF NOT EXISTS idx_image_layers_layer ON image_layers(layer_id);
CREATE INDEX IF NOT EXISTS idx_containers_image ON containers(image_id);
"#;

use serde::{Deserialize, Serialize};
use velarx_types::digest::Digest;
pub use velarx_types::LayerKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageRecord {
    pub id: String,
    pub manifest_digest: Digest,
    pub config_digest: Digest,
    pub manifest: String,
    pub config: String,
    pub created_at: String,
    /// The image is one that is being pulled (`staging/lazy`), not an image of
    /// the store: never read from the database, whose images are complete.
    pub is_lazy: bool,
}

impl ImageRecord {
    /// The bytes of its manifest and configuration: what the record has of
    /// its own, besides its layers (the size of an image counts them, and so
    /// does the space its removal frees).
    pub fn metadata_size(&self) -> u64 {
        (self.manifest.len() + self.config.len()) as u64
    }

    /// The digests of the blobs of the layer descriptors of its manifest, the
    /// lowest layer first, which the chain of trust names the layers by (the
    /// layer of a TOC is of any blob that names the TOC: the record of the
    /// layer has one of them).
    pub fn layer_blobs(&self) -> Vec<String> {
        serde_json::from_str::<velarx_types::OciManifest>(&self.manifest)
            .map(|m| m.layers.into_iter().map(|l| l.digest.to_string()).collect())
            .unwrap_or_default()
    }

    /// From a row of `SELECT id, manifest_digest, config_digest, manifest,
    /// config, created_at`.
    pub(super) fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            manifest_digest: row.get(1)?,
            config_digest: row.get(2)?,
            manifest: row.get(3)?,
            config: row.get(4)?,
            created_at: row.get(5)?,
            is_lazy: false,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ImageTag {
    pub repository: String,
    pub tag: String,
    pub image_id: String,
}

#[derive(Debug, Clone)]
pub struct LayerRecord {
    /// What the layer is known by: what verified it.
    pub key: LayerKey,
    /// The digest of the blob of its descriptor; none for a layer made of
    /// files the peers have for its diff id.
    pub blob: Option<Digest>,
    /// The diff id, once the layer was verified against it; None while
    /// nothing proved it (a lazy layer).
    pub diff_id: Option<Digest>,
    /// The diff id in the other algorithm, once a pull of an image whose
    /// configuration has that algorithm verified the layer against it.
    pub other_diff_id: Option<Digest>,
    pub size: i64,
    /// `ready` for a layer of the store, `lazy` for one that is being pulled
    /// (`staging/lazy`): not kept in the database, whose layers are complete.
    pub status: String,
    pub created_at: String,
    /// Registry reference for on-demand fetching (e.g., "docker.io/library/nginx:latest")
    pub registry_ref: Option<String>,
    /// The fs-verity digest of the EROFS image of the layer.
    pub erofs: Option<String>,
    /// The owners of its files, `[[uids], [gids]]`.
    pub owners: Option<String>,
    /// The size of its uncompressed tar, recorded at the pull (every row
    /// has it); None only for a layer of a lazy pull in progress, which has
    /// no row yet.
    pub stream_size: Option<i64>,
}

impl LayerRecord {
    /// The columns `from_row` reads, of the table `layers` as `l`.
    pub const COLUMNS: &'static str =
        "l.id, l.diff_id, l.size, l.created_at, l.registry_ref, l.erofs, l.owners, l.blob, l.diff_id_other, l.stream_size";

    /// The diff id the layer was verified against in `alg`, if it was.
    pub fn diff_id_in(&self, alg: velarx_types::digest::Algorithm) -> Option<&Digest> {
        [&self.diff_id, &self.other_diff_id]
            .into_iter()
            .flatten()
            .find(|d| d.alg() == alg)
    }

    /// Whether the layer was verified against the diff id `d`.
    pub fn has_diff_id(&self, d: &Digest) -> bool {
        self.diff_id_in(d.alg()) == Some(d)
    }

    /// Whether the layer may be the one an image says by the diff id `d`: it
    /// was verified against it, or it was verified against none and is a
    /// layer of a table of contents (the key is what verified it).
    pub fn matches_diff_id(&self, d: &Digest) -> bool {
        match self.diff_id_in(d.alg()) {
            Some(x) => x == d,
            None => self.key.is_toc() && self.diff_id.is_none() && self.other_diff_id.is_none(),
        }
    }

    /// From a row of `SELECT` [`Self::COLUMNS`].
    pub(super) fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            key: row.get(0)?,
            diff_id: row.get(1)?,
            size: row.get(2)?,
            status: "ready".to_string(),
            created_at: row.get(3)?,
            registry_ref: row.get(4)?,
            erofs: row.get(5)?,
            owners: row.get(6)?,
            blob: {
                let text: String = row.get(7)?;
                (!text.is_empty())
                    .then(|| text.parse())
                    .transpose()
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            7,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?
            },
            other_diff_id: row.get(8)?,
            stream_size: row.get(9)?,
        })
    }
}

/// What `Database::mark_layer_incomplete` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerMarking {
    /// The tar-split is dropped: a pull fetches the layer again.
    Marked,
    /// Not marked: the layer was not pulled from a registry (made here), so
    /// a pull could not bring its tar-split back.
    NotPulled,
    /// No row of this store (a layer of a read-only image store).
    NotHere,
}

/// What a layer row says of itself, without its files (see
/// `Database::get_own_layer_states`).
#[derive(Debug, Clone)]
pub struct LayerState {
    pub key: LayerKey,
    /// The diff id the layer was verified against; None while nothing proved it.
    pub diff_id: Option<Digest>,
    /// The diff id in the other algorithm, if a pull verified it.
    pub other_diff_id: Option<Digest>,
    /// The layer has its tar-split (push and archives rebuild its stream from it).
    pub has_tarsplit: bool,
    /// The layer has its table of contents (a file the row names).
    pub has_toc: bool,
}

impl LayerState {
    /// Whether the store has the layer as an image that says the diff id `d`
    /// needs it: complete, with its tar-split, and proven against `d`.  The
    /// one answer to "the store has it" (a layer marked incomplete has a row
    /// and is not).
    pub fn is_stored_as(&self, d: &Digest) -> bool {
        self.has_tarsplit && self.matches_diff_id(d)
    }

    /// Whether the layer may be the one an image says by the diff id `d`: it
    /// was verified against it, or against none and is a layer of a table
    /// of contents (as [`LayerRecord::matches_diff_id`]).
    pub fn matches_diff_id(&self, d: &Digest) -> bool {
        match [&self.diff_id, &self.other_diff_id]
            .into_iter()
            .flatten()
            .find(|x| x.alg() == d.alg())
        {
            Some(x) => x == d,
            None => self.key.is_toc() && self.diff_id.is_none() && self.other_diff_id.is_none(),
        }
    }

    /// Whether the layer was verified against the diff id `d` (as
    /// [`LayerRecord::has_diff_id`]).
    pub fn has_diff_id(&self, d: &Digest) -> bool {
        [&self.diff_id, &self.other_diff_id]
            .into_iter()
            .flatten()
            .find(|x| x.alg() == d.alg())
            == Some(d)
    }
}

#[derive(Debug, Clone)]
pub struct FileRecord {
    /// The fs-verity digest.
    pub digest: String,
    pub size: i64,
    pub created_at: String,
    /// Measured by the kernel on the object.
    pub checked: bool,
}

/// A layer to record with a pull.
#[derive(Debug, Clone)]
pub struct LayerCommit {
    pub record: LayerRecord,
    pub files: Vec<FileRecord>,
    /// Files the layer holds and how many times.
    pub refs: Vec<(String, i64)>,
    pub chunks: Vec<ChunkLocation>,
    /// The digest of `toc.zst`, the table of contents the layer keeps (a
    /// file of its directory, which the pull wrote).
    pub toc_digest: Digest,
    /// The digest of `tarsplit.zst`, the tar-split of the layer: with the
    /// files of the layer it gives back the exact tar stream.  None for a
    /// canonical layer, which has none (no file).
    pub tarsplit: Option<Digest>,
    /// The blob was hashed to its digest (`layers.blob_checked`)
    pub blob_checked: bool,
    /// The EROFS image and the objects of the layer have fs-verity
    /// (`layers.sealed`).
    pub sealed: bool,
}

/// What the pull of a lazy layer needed to reach its registry: the later
/// fetches of its files need it again (kept in `staging/lazy`).  It says what was used, never the
/// secret itself: credentials and certificates are not stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerReach {
    /// Whether the registry was reached with TLS verification
    /// (`--tls-verify=false` says no).
    pub tls_verify: bool,
    /// Credentials of the request (`--creds`, `--authfile`, `X-Registry-Auth`)
    /// were used.
    pub creds: bool,
    /// Certificates of the request (`--cert-dir`) were used.
    pub certs: bool,
}

impl Default for LayerReach {
    fn default() -> Self {
        Self {
            tls_verify: true,
            creds: false,
            certs: false,
        }
    }
}

/// Everything a pull records.
#[derive(Debug, Clone)]
pub struct PullCommit {
    pub layers: Vec<LayerCommit>,
    pub image: ImageRecord,
    /// The layers of the image, in order.
    pub image_layers: Vec<LayerKey>,
    pub tags: Vec<ImageTag>,
    /// The (repository, digest) names of a pull by digest.
    pub digest_names: Vec<(String, Digest)>,
    /// Blobs (layers and configuration) and the repository they came from
    pub sources: Vec<BlobSource>,
    /// The references the image was pulled by and the signatures found
    /// (JSON), recorded with the image: a stored image has them.
    pub pulled: Vec<(String, Vec<u8>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobSource {
    pub digest: Digest,
    pub registry: String,
    pub repository: String,
}

#[derive(Debug, Clone)]
pub struct FileRef {
    pub layer: LayerKey,
    pub file_digest: String,
    pub ref_count: i64,
}

/// Where a container is in its life: libpod's states, in its words (the text
/// of the `containers.state` column, of `inspect` and of the filters).  The
/// engine stores `created`, `initialized`, `running`, `paused`, `stopped`
/// and `exited` (a container that ended before a restart of the host is
/// `stopped`, one that a previous build ended may be `exited`: both mean
/// ended); the others are podman's, read when a row has them.  A text that is
/// none of these is `Unknown`, so a row never fails to load.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordState {
    Configured,
    #[default]
    Created,
    Initialized,
    Running,
    Paused,
    Stopping,
    Stopped,
    Exited,
    Removing,
    /// A word of no state (also when read with serde)
    #[serde(other)]
    Unknown,
}

impl RecordState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::Created => "created",
            Self::Initialized => "initialized",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Exited => "exited",
            Self::Removing => "removing",
            Self::Unknown => "unknown",
        }
    }

    /// The state of a stored word; any other is `Unknown`.
    pub fn of_word(word: &str) -> Self {
        match word {
            "configured" => Self::Configured,
            "created" => Self::Created,
            "initialized" => Self::Initialized,
            "running" => Self::Running,
            "paused" => Self::Paused,
            "stopping" => Self::Stopping,
            "stopped" => Self::Stopped,
            "exited" => Self::Exited,
            "removing" => Self::Removing,
            _ => Self::Unknown,
        }
    }

    /// Its processes are there: running or paused.
    pub fn is_alive(self) -> bool {
        matches!(self, Self::Running | Self::Paused)
    }

    /// It ran and ended: `stopped` or `exited` (podman tells them apart, a
    /// container that is gone is one or the other for every reader here).
    pub fn has_ended(self) -> bool {
        matches!(self, Self::Stopped | Self::Exited)
    }
}

impl std::fmt::Display for RecordState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl rusqlite::types::ToSql for RecordState {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(self.as_str().into())
    }
}

impl rusqlite::types::FromSql for RecordState {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        Ok(Self::of_word(value.as_str()?))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainerRecord {
    pub id: String,
    pub name: Option<String>,
    pub image_id: String,
    pub config: String,
    pub state: RecordState,
    pub pid: Option<i32>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub exit_code: Option<i32>,
}

impl ContainerRecord {
    /// From a row of `SELECT id, name, image_id, config, state, pid,
    /// created_at, started_at, finished_at, exit_code`.
    pub(super) fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            name: row.get(1)?,
            image_id: row.get(2)?,
            config: row.get(3)?,
            state: row.get(4)?,
            pid: row.get(5)?,
            created_at: row.get(6)?,
            started_at: row.get(7)?,
            finished_at: row.get(8)?,
            exit_code: row.get(9)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct NetworkRecord {
    pub id: String,
    pub name: String,
    pub driver: String,
    pub subnet: Option<String>,
    pub gateway: Option<String>,
    pub options: Option<String>,
    pub created_at: String,
    /// The IPv6 subnet of a dual-stack bridge network.
    pub subnet6: Option<String>,
    pub gateway6: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UsernsAllocation {
    pub id: String,
    pub label: Option<String>,
    pub uid_start: u32,
    pub uid_count: u32,
    pub gid_start: u32,
    pub gid_count: u32,
    pub container_id: Option<String>,
    pub created_at: String,
}

/// Represents the location of a chunk within a file
#[derive(Debug, Clone)]
pub struct ChunkLocation {
    pub chunk_digest: Digest,
    pub file_digest: String,
    pub offset: u64,
    pub size: u64,
}

#[cfg(test)]
mod tests {
    use super::{RecordState, SCHEMA_VERSION};
    use crate::{ContainerRecord, Database};

    /// The stored words are libpod's, the same as before the type: every
    /// state reads and writes its word, both of `stopped` and `exited`
    /// stay, and a word of no state is `unknown` (the row still loads).
    #[tokio::test]
    async fn a_container_state_is_stored_as_its_word() {
        use RecordState::*;
        let all = [
            (Configured, "configured"),
            (Created, "created"),
            (Initialized, "initialized"),
            (Running, "running"),
            (Paused, "paused"),
            (Stopping, "stopping"),
            (Stopped, "stopped"),
            (Exited, "exited"),
            (Removing, "removing"),
            (Unknown, "unknown"),
        ];
        let db = Database::open_in_memory().await.unwrap();
        db.insert_container(&ContainerRecord {
            id: "c1".into(),
            name: None,
            image_id: "img".into(),
            config: "{}".into(),
            state: Created,
            created_at: "now".into(),
            ..Default::default()
        })
        .await
        .unwrap();
        for (state, word) in all {
            assert_eq!(state.as_str(), word);
            assert_eq!(
                serde_json::to_string(&state).unwrap(),
                format!("\"{word}\"")
            );
            db.update_container_state("c1", state, None, None, None, None)
                .await
                .unwrap();
            assert_eq!(db.get_container("c1").await.unwrap().state, state);
            let stored: String = db
                .conn()
                .call(|c| {
                    Ok(
                        c.query_row("SELECT state FROM containers WHERE id = 'c1'", [], |r| {
                            r.get(0)
                        })?,
                    )
                })
                .await
                .unwrap();
            assert_eq!(stored, word);
        }
        assert!(Running.is_alive() && Paused.is_alive() && !Created.is_alive());
        assert!(Stopped.has_ended() && Exited.has_ended() && !Running.has_ended());
        assert_eq!(RecordState::of_word("dead"), Unknown);
        assert_eq!(RecordState::of_word("Running"), Unknown);
        assert_eq!(
            serde_json::from_str::<RecordState>("\"dead\"").unwrap(),
            Unknown
        );
    }

    /// A new database is made of this version; a file of another version is
    /// refused, with the version in the error.
    #[tokio::test]
    async fn a_database_of_another_version_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        Database::open(&path).await.unwrap().close().await.unwrap();
        let conn = rusqlite::Connection::open(&path).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        conn.execute_batch(&format!("PRAGMA user_version = {};", SCHEMA_VERSION + 1))
            .unwrap();
        drop(conn);
        let other = format!("schema version {}", SCHEMA_VERSION + 1);
        let e = Database::open(&path).await.err().unwrap().to_string();
        assert!(e.contains(&other), "{e}");
    }

    /// A file with tables and `user_version` 0 is refused with its version,
    /// not taken for a new, empty file.
    #[tokio::test]
    async fn a_made_file_of_version_0_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        Database::open(&path).await.unwrap().close().await.unwrap();
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch("PRAGMA user_version = 0;")
            .unwrap();
        let e = Database::open(&path).await.err().unwrap().to_string();
        assert!(e.contains("schema version 0"), "{e}");
        assert!(e.contains("remove the store"), "{e}");
    }

    /// A database made by an earlier build that wrote `PRAGMA application_id`
    /// opens: nothing reads it.
    #[tokio::test]
    async fn an_application_id_in_the_database_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        Database::open(&path).await.unwrap().close().await.unwrap();
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch("PRAGMA application_id = 12345;")
            .unwrap();
        Database::open(&path).await.unwrap().close().await.unwrap();
    }
}
