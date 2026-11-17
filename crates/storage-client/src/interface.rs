// SPDX-License-Identifier: Apache-2.0
//! The text of the two interface definitions, made from the types of
//! [`super::proto`] and [`super::feed_proto`] and the methods below
//! (`interfaces/org.velarx.Storage.varlink` and
//! `interfaces/org.velarx.StorageFeed.varlink`), with the rules of the
//! protocol in their headers.  The methods are the signatures only: the
//! driver is a program of its own (the reference one is a later change), and
//! the client in this package makes its calls by hand over
//! `velarx_wire::varlink`, as the monitor's client of the fetchers does.
//! `VELARX_WRITE_INTERFACES=1 cargo test -p velarx-storage-client --lib
//! interface` writes the files.

use super::feed_proto::{
    Copy, EventKind, FeedError, FeedInfo, FeedLayer, FetchEvent, Fetched, Handed, Piece, Region,
    Want, Zeros,
};
use super::proto::*;
use futures::stream::{self, Stream};
use std::future::ready;
use std::os::fd::OwnedFd;
use velarx_proto::transfer::{Failure, FailureClass};
use zlink::Reply;

/// The stream of one error: what a method of the description answers.
fn unsupported<T>() -> impl Stream<Item = Result<Reply<T>, StorageError>> + Unpin {
    stream::once(ready(Err(StorageError::Unsupported {
        reason: "the description has no server".into(),
    })))
}

fn no<T>() -> Result<T, StorageError> {
    Err(StorageError::Unsupported {
        reason: "the description has no server".into(),
    })
}

mod storage {
    #![allow(missing_docs)]
    use super::*;

    /// The description of the driver: signatures only.
    pub struct Endpoint;

    #[allow(
        clippy::too_many_arguments,
        reason = "one parameter for each field of the varlink call"
    )]
    #[zlink::service(
        interface = "org.velarx.Storage",
        vendor = "org.velarx",
        product = "velarx",
        types = [LayerRef, PullLayer, Range, IdMap, Mapping, Owner, Accepted, MountAsk, VolumeAsk,
            MountKind, Idmap, Label, Mounted, IdmapWay, MountCaps, MountWays,
            Progress, PullEventKind, ProblemKind, Problem,
            Artifact, Owners, Pair, StoreEntry, Remedy]
    )]
    impl Endpoint {
        /// Who the driver is and what it does.  The first call of every
        /// connection: the engine refuses a `proto` other than its own.
        async fn get_info(&self) -> Info {
            Info {
                name: String::new(),
                version: String::new(),
                proto: PROTO,
                capabilities: Vec::new(),
                limits: std::collections::BTreeMap::new(),
                mounts: MountWays {
                    root: MountCaps { idmap: Vec::new() },
                    volume: None,
                },
            }
        }

        /// Which of `layers` the driver has: one answer for each, in the order
        /// asked (at most `max_layers` of the capabilities), true for a layer
        /// that is committed and complete.  A layer that is only staged, or
        /// committed with another diff id, is not reported.  A chained driver
        /// answers for the place of each layer in its stack.
        async fn has_layers(
            &self,
            store: String,
            layers: Vec<LayerRef>,
        ) -> Result<HasReply, StorageError> {
            let _ = (store, layers);
            no()
        }

        /// Which of `objects` the driver holds: one answer for each, in the
        /// order asked (at most `limits.wants` of them), true for an object
        /// it has committed and can read now, under that key or by an alias
        /// of it (the hash of its content, for an object it names by its
        /// fs-verity digest).  An object that is only staged by a pull, or
        /// that a collection removed, is not held.  Answered from the driver's
        /// own store.  Asked only of a driver that says `objects` in its
        /// capabilities; the engine names a held object as the source of a
        /// `copy` event of a `Fetch`.
        async fn has_objects(
            &self,
            store: String,
            objects: Vec<String>,
        ) -> Result<ObjectsReply, StorageError> {
            let _ = (store, objects);
            no()
        }

        /// The pull of the layers of an image, driven by the driver.  `layers`
        /// is the whole ordered list of the image, those `stored` included.
        /// The call carries the descriptor 0: the driver's end of a socket
        /// pair on which the engine serves `org.velarx.StorageFeed` for this
        /// pull only.  Called with `more`, it lives as long as the pull: the
        /// driver replies `progress` at least every `timeout_secs / 2`, also
        /// while its own calls to the feed run, and `staged` once every object
        /// it needs is staged (the engine keeps the feed open after it until it
        /// has committed or aborted the pull: org.velarx.StorageFeed, "The
        /// end").  Closing the connection cancels the pull.  The
        /// `pull` is a random id the engine made for this attempt (32 hex
        /// digits): a call with the id of a pull the driver has resumes it, an
        /// id it does not know is a new pull, and the engine reuses an id only
        /// to resume its own.
        #[zlink(more)]
        async fn begin_pull(
            &self,
            more: bool,
            #[zlink(fds)] fds: Vec<OwnedFd>,
            store: String,
            pull: String,
            layers: Vec<PullLayer>,
        ) -> impl Stream<Item = Result<Reply<PullEvent>, StorageError>> + Unpin {
            let _ = (more, fds, store, pull, layers);
            unsupported()
        }

        /// The bytes of objects, committed or staged by `pull`, in pipe form.
        /// The call carries the descriptor 0: the write end of a pipe.  Called
        /// with `more`: one reply for each range, in the order asked, and the
        /// reply for range `i` is sent **before** the `length` bytes of its
        /// range are written to the pipe (a range larger than the pipe buffer
        /// would block the driver, and the engine too, were the bytes first).
        /// At most `limits.ranges` ranges.  A key that is no object's name is
        /// `Missing` with the remedy `pull_again`; an object with fewer bytes
        /// than a range wants is `Corrupt`.  The engine checks what it needs
        /// of the bytes: a driver is trusted to store, not to be right.
        #[zlink(more)]
        async fn read_objects(
            &self,
            more: bool,
            #[zlink(fds)] fds: Vec<OwnedFd>,
            store: String,
            pull: Option<String>,
            ranges: Vec<Range>,
        ) -> impl Stream<Item = Result<Reply<Read>, StorageError>> + Unpin {
            let _ = (more, fds, store, pull, ranges);
            unsupported()
        }

        /// Publish the layers of the pull and their objects, all or nothing,
        /// with one barrier.  Idempotent: succeeds when each layer is
        /// committed by this pull or already committed, by anyone, with the
        /// same diff id; `Busy` with another.
        async fn commit(
            &self,
            store: String,
            pull: String,
            layers: Vec<LayerRef>,
        ) -> Result<Ack, StorageError> {
            let _ = (store, pull, layers);
            no()
        }

        /// End the pull: drop only what no other live pull and no committed
        /// layer uses.  Idempotent.
        async fn abort(&self, store: String, pull: String) -> Result<Ack, StorageError> {
            let _ = (store, pull);
            no()
        }

        /// Make what the driver keeps for the root of a container, and say what
        /// the root will be: the reply has the kind of the mount, the mapping
        /// and the label it will have, and **no descriptor** (none without an
        /// image, `--rootfs`).  Every later `Mounts` answers the same kind,
        /// `idmap` and `label`.  `workdir` is the work directory of the store,
        /// a directory of the engine's user closed to others: a `directory`
        /// root is made beneath it and named relative to it, and a driver
        /// that answers `mount_fd` may ignore it.  Idempotent.  Called with `more`: a call that
        /// costs O(image) for a driver that copies sends `progress` at least
        /// every `timeout_secs / 2`.  `Busy` for a second `CreateRoot` of one
        /// container that runs.
        #[zlink(more)]
        async fn create_root(
            &self,
            more: bool,
            store: String,
            container: String,
            workdir: String,
            image: Option<String>,
            layers: Vec<LayerRef>,
            owner: Option<Owner>,
            ask: MountAsk,
            size_limit: Option<u64>,
        ) -> impl Stream<Item = Result<Reply<Created>, StorageError>> + Unpin {
            let _ = (
                more, store, container, workdir, image, layers, owner, ask, size_limit,
            );
            unsupported()
        }

        /// The same for the image mounted in a container as its `--mount
        /// type=image` number `index`.  Idempotent; `progress` as `CreateRoot`.
        /// The engine counts the volumes that are `mount_fd` and refuses more
        /// than 15 at create.
        #[zlink(more)]
        async fn create_image_volume(
            &self,
            more: bool,
            store: String,
            container: String,
            index: u32,
            image: String,
            layers: Vec<LayerRef>,
            ask: MountAsk,
        ) -> impl Stream<Item = Result<Reply<VolumeCreated>, StorageError>> + Unpin {
            let _ = (more, store, container, index, image, layers, ask);
            unsupported()
        }

        /// The root file system of a container and the images mounted in it,
        /// as the monitor mounts them for this start: **the only source of
        /// descriptors**.  Asked at every start, restart of the engine and
        /// restore, and gives new descriptors each time.  The mounts of one
        /// container per call.  The reply carries the descriptors of the
        /// `mount_fd` mounts, each named by its position among them
        /// (`Mounted.fd`).  The driver makes a **new** mount for each reply, a
        /// detached `open_tree(OPEN_TREE_CLONE)` or `fsmount`, closes every
        /// copy of it after sending it, and never hands the same mount twice.
        /// A volume that was never created is `Missing` with the remedy
        /// `recreate_container`.
        #[zlink(return_fds)]
        async fn mounts(
            &self,
            store: String,
            container: String,
            root: Option<MountAsk>,
            volumes: Vec<VolumeAsk>,
        ) -> (Result<MountsReply, StorageError>, Vec<OwnedFd>) {
            let _ = (store, container, root, volumes);
            (no(), Vec::new())
        }

        /// The root file system of the image made of `layers` as its containers
        /// see it, as the one descriptor of the reply: a read-only mount of it (a detached
        /// `open_tree(OPEN_TREE_CLONE)` or `fsmount`) or, where the service
        /// cannot make one, a directory.  For the engine's reads of what a
        /// create needs of the image (the user's entries of `/etc/passwd` and
        /// `/etc/group`, `/etc/localtime`, the `--workdir`, the sub path of an
        /// image mount, the content of a volume that takes the image's): the
        /// engine opens every name below it with `openat2` (beneath, no link,
        /// no magic link, no other mount), reads regular files only and at
        /// most what it needs, refuses the root of the host, and closes the
        /// descriptor when it is done.  The mount is new for each reply and
        /// the service keeps no hold on it (as for `Mounts`); what it keeps
        /// to make one (a copy of the image, for a service that copies its
        /// layers) is its own, dropped by the `Collect` that no longer keeps
        /// a layer of it.  It carries the ids of the image, no mapping.  A
        /// layer the service does not have is `Missing` with the remedy
        /// `pull_again`.
        #[zlink(return_fds)]
        async fn mount_image(
            &self,
            store: String,
            layers: Vec<LayerRef>,
        ) -> (Result<Ack, StorageError>, Vec<OwnedFd>) {
            let _ = (store, layers);
            (no(), Vec::new())
        }

        /// The root of the writable layer of the container, as the one
        /// descriptor of the reply: a directory, or a detached clone of the
        /// mount the container runs on (the same superblock), never a second
        /// mount of the same upper.  For the engine's walks: the user files and
        /// the label at create, `cp` and `export` of a stopped container, and
        /// `diff`, `changes` and `commit`, which may be of a running one.
        #[zlink(return_fds)]
        async fn writable_root(
            &self,
            store: String,
            container: String,
        ) -> (Result<Ack, StorageError>, Vec<OwnedFd>) {
            let _ = (store, container);
            (no(), Vec::new())
        }

        /// The bytes of the files the container wrote.
        async fn size(&self, store: String, container: String) -> Result<SizeReply, StorageError> {
            let _ = (store, container);
            no()
        }

        /// Whether the container has a writable layer made.
        async fn exists(
            &self,
            store: String,
            container: String,
        ) -> Result<ExistsReply, StorageError> {
            let _ = (store, container);
            no()
        }

        /// Remove the writable layer of the container, its image volumes with
        /// it.  Idempotent.
        async fn remove_root(&self, store: String, container: String) -> Result<Ack, StorageError> {
            let _ = (store, container);
            no()
        }

        /// Forget what the driver keeps of a removed image (the layers go at a
        /// collection).  Idempotent.
        async fn remove_image(&self, store: String, image: String) -> Result<Ack, StorageError> {
            let _ = (store, image);
            no()
        }

        /// What is wrong with what the driver made of the layers of `image`;
        /// `full` reads it and compares it with what the tables of contents
        /// make.  Called with `more`: `progress` as `CreateRoot`.
        #[zlink(more)]
        async fn check(
            &self,
            more: bool,
            store: String,
            image: String,
            layers: Vec<LayerRef>,
            full: bool,
        ) -> impl Stream<Item = Result<Reply<Checked>, StorageError>> + Unpin {
            let _ = (more, store, image, layers, full);
            unsupported()
        }

        /// Make the artifacts of the layers again from what the driver keeps,
        /// and answer their identities, which the engine checks against those
        /// it makes from the tables of contents before it records them.
        /// Idempotent.  Called with `more`: `progress` as `CreateRoot`.
        #[zlink(more)]
        async fn repair(
            &self,
            more: bool,
            store: String,
            layers: Vec<LayerRef>,
        ) -> impl Stream<Item = Result<Reply<Repaired>, StorageError>> + Unpin {
            let _ = (more, store, layers);
            unsupported()
        }

        /// What the driver holds on its disk for itself: the files and bytes
        /// of its own artifacts (the objects are the engine's).
        async fn usage(&self, store: String) -> Result<UsageReply, StorageError> {
            let _ = store;
            no()
        }

        /// What the driver reports of itself, as names and values.
        async fn status(&self, store: String) -> Result<StatusReply, StorageError> {
            let _ = store;
            no()
        }

        /// The stores of the caller's uid that the driver holds, for a driver
        /// that serves several: each with what it takes and when an engine last
        /// opened it, so that a store no engine opens any more is found (the
        /// id of the engine's store is in a file of its graph root).  A driver
        /// isolates stores by the pair (uid of the peer, store).
        async fn list_stores(&self) -> Result<StoresReply, StorageError> {
            no()
        }

        /// Remove the store and everything under it (layers, roots, image
        /// mounts, staging).  Idempotent.  `Busy` while a pull or a container
        /// of it is in progress; a name that is not a store id (32 hex digits)
        /// is refused before it names a path.
        async fn drop_store(&self, store: String) -> Result<Ack, StorageError> {
            let _ = store;
            no()
        }

        /// Remove what the driver holds that the keep set does not name, and
        /// what an interrupted pull left.  The keep set is the JSON lines of
        /// the descriptor 0, a sealed memory file of `keep_length` bytes (the
        /// grace period, then one record for each layer, chain, image,
        /// container and pull: a set can be larger than a message).  What the
        /// driver finds that nothing names it keeps while it has changed within
        /// the grace period.  Idempotent.  Called with `more`: `progress` as
        /// `CreateRoot`.
        #[zlink(more)]
        async fn collect(
            &self,
            more: bool,
            #[zlink(fds)] fds: Vec<OwnedFd>,
            store: String,
            keep_length: u64,
        ) -> impl Stream<Item = Result<Reply<Collection>, StorageError>> + Unpin {
            let _ = (more, fds, store, keep_length);
            unsupported()
        }
    }

    /// The interface as the macro described it.
    pub(super) fn description() -> String {
        format!("{}", __Endpoint_INTERFACE_0)
    }
}

mod feed {
    #![allow(missing_docs)]
    use super::*;

    /// The description of the feed: signatures only.
    pub struct Endpoint;

    #[zlink::service(
        interface = "org.velarx.StorageFeed",
        vendor = "org.velarx",
        product = "velarx",
        types = [FailureClass, Failure, FeedLayer, Want, Region, Piece, Copy, Handed, Zeros, EventKind,
            FetchEvent]
    )]
    impl Endpoint {
        /// The shared `GetInfo` (`limits` has `max_wants`, `max_fetches` and
        /// `max_fetch_bytes`), the pull and its layers.
        async fn get_info(&self) -> FeedInfo {
            FeedInfo {
                name: String::new(),
                version: String::new(),
                proto: super::super::feed_proto::PROTO,
                capabilities: Vec::new(),
                limits: std::collections::BTreeMap::new(),
                pull: String::new(),
                layers: Vec::new(),
            }
        }

        /// Another connection to this feed, for a parallel `Fetch`: the reply
        /// carries its descriptor, the end of a socket pair served as this
        /// one.  `TooMuch` at `max_fetches`.
        #[zlink(return_fds)]
        async fn connect(&self) -> (Result<Ack, FeedError>, Vec<OwnedFd>) {
            (Ok(Ack {}), Vec::new())
        }

        /// The verified table of contents (descriptor 0) and the zstd
        /// compressed tar-split (descriptor 1) of a `chunked` layer, as sealed
        /// memory files of the lengths `GetInfo` says.
        #[zlink(return_fds)]
        async fn index(&self, layer: String) -> (Result<Ack, FeedError>, Vec<OwnedFd>) {
            let _ = layer;
            (
                Err(FeedError::UnknownLayer {
                    layer: String::new(),
                }),
                Vec::new(),
            )
        }

        /// The driver has every file of `layer` that it lacks: the engine
        /// frees what it keeps to serve the layer (the spool of a layer it
        /// read whole), and a `Fetch` of the layer after it is `Failed`.
        /// Idempotent; nothing for a layer that keeps nothing.
        async fn release(&self, layer: String) -> Result<Ack, FeedError> {
            let _ = layer;
            Err(FeedError::UnknownLayer {
                layer: String::new(),
            })
        }

        /// Fetch `wants` (at most `max_wants` of the limits, keys of the table of contents
        /// of `layer`, each once), all planned and merged together by the
        /// engine.  Called with `more`.  The call carries the files the
        /// engine writes the bytes into: the descriptor 0 is the pack file,
        /// an empty regular file open for writing (or the driver's memory
        /// file), then up to 15 files of one object each (`Want.file`).  A
        /// file must be a regular, empty file on a file system whose writes
        /// cannot be held up by another process (not FUSE, not a network file
        /// system): the engine writes into it in line, and a write that never
        /// returns would hold up every pull of the engine.  The engine keeps
        /// no descriptor after the call.  The events: `ready` (pieces),
        /// `copy` and `zeros` (the driver's own bytes and holes), `complete`
        /// (objects whole, their keys verified) and `failed` (with the
        /// failure); the last reply has no event and `continues: false`, and
        /// an event this side does not know is ignored.  The feed is scoped to the pull: a key that is not
        /// in the table of contents of the layer is `UnknownObject`, and the
        /// total asked for is at most twice the planned bytes of the layer
        /// (`TooMuch`).  Closing the connection cancels the call.
        #[zlink(more, return_fds)]
        async fn fetch(
            &self,
            more: bool,
            #[zlink(fds)] fds: Vec<OwnedFd>,
            layer: String,
            wants: Vec<Want>,
        ) -> impl Stream<Item = (Result<Reply<Fetched>, FeedError>, Vec<OwnedFd>)> + Unpin {
            let _ = (more, fds, layer, wants);
            stream::once(ready((
                Err(FeedError::failed("the description has no server")),
                Vec::new(),
            )))
        }
    }

    pub(super) fn description() -> String {
        format!("{}", __Endpoint_INTERFACE_0)
    }
}

/// The text of `interfaces/org.velarx.Storage.varlink`.
pub fn definition() -> String {
    format!(
        "# SPDX-License-Identifier: Apache-2.0\n\
         #\n\
         # The interface org.velarx.Storage: a storage driver that is a program of its\n\
         # own, asked by the engine for the content of its images and the root file\n\
         # systems of its containers.  The driver owns where the bytes live and how a\n\
         # root is made of them; the engine owns the network, the table of contents and\n\
         # tar-split of each layer, the identities (diff ids, EROFS digests, owners) and\n\
         # the reachability of everything.  The pull is driven by the driver through\n\
         # org.velarx.StorageFeed (BeginPull).  Generated from the Rust types\n\
         # (crates/storage-client/src/proto.rs and interface.rs) by the test\n\
         # `interface::tests::the_interface_file_is_current`:\n\
         # VELARX_WRITE_INTERFACES=1 cargo test -p velarx-storage-client --lib interface\n\
         # writes it.  docs/STORAGE.md maps it to the StorageDriver trait.\n\
         #\n\
         # Versions: the engine calls GetInfo first on each connection and refuses a\n\
         # `proto` other than its own ({PROTO}); there is no negotiation and no\n\
         # compatibility.  A change of a shape is a new version, so what is announced for\n\
         # later is a capability (`later` in GetInfo), not a new shape.  Unknown fields\n\
         # are ignored.  A value of an enum the engine does not know, in a reply, is a\n\
         # Storage error that names it, not a protocol error; the engine asks only for\n\
         # what it can take (it asks `idmap_mount: true` only when it can handle `mount`).\n\
         # What the engine learns to do within a version is an optional field of\n\
         # `capabilities` (absent: false), `objects` so far (HasObjects, and the `copy`\n\
         # events of the feed): the engine asks and sends only what the driver\n\
         # announces, and a driver that announces what an older engine does not know is\n\
         # asked nothing of it.\n\
         #\n\
         # One connection for each call, from the engine's user or root; the engine\n\
         # talks only to a driver served by its own user or root (SO_PEERCRED).  A\n\
         # connection with no reply for `[storage.varlink] timeout_secs`, a connect not\n\
         # accepted and a request not read within it, are failed (TimedOut).  A call\n\
         # that can take longer (CreateRoot, CreateImageVolume, BeginPull, Collect,\n\
         # Repair, Check) is made with `more`, and the driver sends a `progress` reply at\n\
         # least every timeout_secs / 2; every reply starts the deadline again.\n\
         #\n\
         # Limits (GetInfo `limits`, applied by the engine, which splits a request that\n\
         # would exceed one and never sends it): a message is at most {MAX_MESSAGE} bytes of JSON and\n\
         # carries at most {MAX_FDS} descriptors; a Fetch asks for at most {MAX_WANTS} objects, a ReadObjects\n\
         # for at most {MAX_RANGES} ranges (the ranges are answered in the order asked, across calls).\n\
         # What can be longer than a message does not travel in one: the keep set of\n\
         # Collect is a sealed memory file of JSON lines, and its length is the argument.\n\
         #\n\
         # Descriptors are named, not counted: a reply that carries descriptors says for\n\
         # each which one it is by its position in the reply (Mounted.fd).  A position used\n\
         # twice, outside the reply, or a descriptor no mount names, is a refused reply.\n\
         # The driver makes a new mount for each reply and closes every copy of it after\n\
         # sending it; the monitor attaches a clone of it.\n\
         #\n\
         # Every call but GetInfo and ListStores takes the `store`, the id of the store the\n\
         # engine keeps in a file of its graph root (32 hex digits); a driver isolates\n\
         # stores by the pair (uid of the peer, store).\n\
         #\n\
         # Roots: a `directory` root is made beneath the `workdir` of CreateRoot (the\n\
         # work directory of the store, the engine's) and named relative to it; any\n\
         # other path is refused, and the monitor resolves it beneath that base without\n\
         # following a link.  Every other root is a `mount_fd`.\n\
         #\n\
         # Errors: Missing and Corrupt carry a `remedy` (pull_again, repair,\n\
         # recreate_container); Unsupported, NotFound, Busy, Unavailable and Failed carry a\n\
         # reason.  An error name the engine does not know is a Storage error that carries\n\
         # the name in its message.  The engine makes Unavailable (connect refused, the\n\
         # socket gone: start the storage service), TimedOut and ProtocolMismatch (both\n\
         # versions named: upgrade the driver or velarx) of a transport that failed; a driver\n\
         # whose own backend does not answer sends Unavailable.  Contradicted,\n\
         # DigestEnforced and Refused are verdicts of the engine, and a driver never sends\n\
         # them.\n\
         #\n\
         # Lazy images: the driver sees none.  An image pulled with --lazy is staged and\n\
         # run by the engine from its own files (the table of contents of each layer is\n\
         # the engine's), and when its files are all there the engine pulls its layers\n\
         # into the driver as an eager pull does (BeginPull, Index, Fetch, the read-back\n\
         # of ReadObjects, Commit).  An image with a layer that cannot be served that way\n\
         # is refused by the engine before anything is staged.  `capabilities.lazy` is\n\
         # the engine's word for itself, not a driver's; what a driver says is ignored.\n\
         #\n\
         # Idempotence: CreateRoot, CreateImageVolume, RemoveRoot, RemoveImage, Repair,\n\
         # Collect, Commit, Abort and DropStore can be called again with the same arguments\n\
         # and give the same state.  Mounts is asked at every start and MountImage at every\n\
         # read of an image, and both give new descriptors each time.  The engine does\n\
         # not call Collect while a create, a removal or a pull of the same store is\n\
         # between its first call and the record of its result.\n\
         \n{}\n",
        storage::description()
    )
}

/// The text of `interfaces/org.velarx.StorageFeed.varlink`.
pub fn feed_definition() -> String {
    use super::feed_proto::{MAX_WANTS as FEED_WANTS, PROTO as FEED_PROTO};
    format!(
        "# SPDX-License-Identifier: Apache-2.0\n\
         #\n\
         # The interface org.velarx.StorageFeed: what the engine offers a storage driver\n\
         # during a pull, served by the engine on the socket pair that BeginPull of\n\
         # org.velarx.Storage hands the driver (the descriptor 0), for that pull only; the\n\
         # driver is its client.  Generated from the Rust types\n\
         # (crates/storage-client/src/feed_proto.rs and interface.rs) by the test\n\
         # `interface::tests::the_feed_file_is_current`:\n\
         # VELARX_WRITE_INTERFACES=1 cargo test -p velarx-storage-client --lib interface\n\
         # writes it.\n\
         #\n\
         # The driver reads the index of each layer (Index), works out what it lacks\n\
         # against its own store, and asks for sets of missing files (Fetch, at most\n\
         # {FEED_WANTS} keys); the engine merges the ranges by cost, fetches from the sources and\n\
         # peers first, checks every chunk against the table of contents, and writes the\n\
         # bytes into the files the driver passed.  The engine holds the credentials: no\n\
         # URL, repository or digest of a blob is accepted from the driver, only keys of\n\
         # the tables of contents of the layers of this pull.\n\
         #\n\
         # Versions: GetInfo is the first call; the `proto` is the one of\n\
         # org.velarx.Storage ({FEED_PROTO}).  Limits: a message is at most {MAX_MESSAGE} bytes and\n\
         # carries at most {MAX_FDS} descriptors.\n\
         #\n\
         # Parallelism: one connection for each concurrent Fetch (Connect), at most\n\
         # `max_fetches` of the limits.  Back-pressure: the driver asks when it has room, and a driver\n\
         # that stops reading the replies stalls its own fetch until the idle deadline of\n\
         # the pull.  Cancellation: the engine closes the feed when the pull ends or is\n\
         # cancelled; the driver closes a Fetch connection and the engine stops that\n\
         # call's requests.  The end: after BeginPull replied `staged` the engine makes\n\
         # no more calls on the feed but keeps it open until its Commit or Abort of the\n\
         # pull has returned, so a feed that the engine closed before it decided is a\n\
         # pull nobody will decide (its engine died or gave up): the driver may end it\n\
         # and free what it holds at once, as an Abort, and need not look.\n\
         #\n\
         # The proof: the engine proves the diff id of each layer after BeginPull replies\n\
         # `staged` and before anything is published, by reading the layer back from the\n\
         # driver (ReadObjects of org.velarx.Storage): the bytes are verified chunk by\n\
         # chunk as they are fetched, and the driver may have changed them.\n\
         #\n\
         # The write: a Fetch is checked (the layer, the keys, the files, the wants and\n\
         # the budget), planned by the engine for the wants alone, fetched (every chunk\n\
         # checked against the table of contents), and written into the files the\n\
         # driver passed, each object at its place: in the file\n\
         # `Want.file` names, else in the pack file (the descriptor 0) at an offset the\n\
         # engine chooses, a multiple of 4096.  The events tell the driver as the\n\
         # objects become whole: `zeros` (the holes of an object, already holes in the\n\
         # file), `ready` (the place of each whole object, read back by the engine and\n\
         # checked to be what its key names, its fs-verity digest or the hash of its\n\
         # content: Region.fd is the position of its file among the descriptors of the\n\
         # call), `complete` (their positions among\n\
         # the wants), `failed` (the wants that were not written, and the failure: its class says\n\
         # `no_space` for the free space of the spool, `invalid` for a chunk that is not what\n\
         # the table of contents says, the class of the party that failed otherwise); the\n\
         # last reply has no event.  A\n\
         # driver that announces `objects` (org.velarx.Storage) is also told `copy`: bytes\n\
         # of an object it asked for that another object it holds has (the engine asked\n\
         # HasObjects for the objects the chunks of its records are in), which the driver\n\
         # copies itself, from `from_offset` of its object `from` to `at` of the want.\n\
         # The `copy` events of a want come before its `ready` and `complete`; the\n\
         # copied ranges are not written by the engine, and the engine does not read\n\
         # the object back at the fetch (it reads it back when it proves the layer, and\n\
         # checks it against the key it is staged under).  An object that a fetcher\n\
         # staged and the engine verified (once: the kernel's measure of its fs-verity\n\
         # digest, else one read) is not written to a place of the driver: `staged`\n\
         # hands the file itself over, a descriptor of the message at the position\n\
         # `Handed.fd` with the fs-verity digest the engine verified, and `complete`\n\
         # follows.  The driver keeps the file its own way: a link of the inode where\n\
         # its store is in the same file system, else a copy of its own; it need not\n\
         # read it.  A file that went by `staged` is no `ready`.\n\
         #\n\
         # A layer that has no table of contents in a registry (gzip, zstd without\n\
         # zstd:chunked metadata, a layer the engine made itself by a commit, a\n\
         # build step or an import) is no call of its own: the engine reads it\n\
         # whole before BeginPull, into a spool of its own, makes the table of\n\
         # contents and the tar-split from the headers and checks the blob and\n\
         # the diff id, and the driver sees it as any other layer: Index, then\n\
         # Fetch for the files it lacks, which the engine copies from the spool,\n\
         # each checked against its key (the holes of a file are told as `zeros`).\n\
         # The spool of a layer is as large as the layer: when the driver has every file\n\
         # of a layer it lacks it says so (Release) and the engine frees the spool, or\n\
         # it goes with the pull.  The engine checks the free space of the directory of\n\
         # the spool as it grows and refuses the layer naming the directory and the\n\
         # bytes it needs.\n\
         # Who may call: a peer of the same user or root (SO_PEERCRED); any\n\
         # accepted peer may make every call.\n\
         \n{}\n",
        feed::description()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(name: &str, text: &str) {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../interfaces")
            .join(name);
        if std::env::var_os("VELARX_WRITE_INTERFACES").is_some() {
            std::fs::write(&path, text).unwrap();
        }
        let on_disk = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            on_disk == text,
            "{} is not what the types make; run VELARX_WRITE_INTERFACES=1 cargo test -p \
             velarx-storage-client --lib interface and commit it",
            path.display()
        );
        // (no rustdoc of the Rust side in a text for other languages)
        assert!(!text.contains("[`"), "a rustdoc link in the definition");
    }

    /// The files are valid varlink: the parser of zlink takes them, and the
    /// one of systemd (`varlinkctl validate-idl`) where it is installed.
    #[test]
    fn the_files_are_valid_varlink() {
        for (name, text) in [
            ("org.velarx.Storage", definition()),
            ("org.velarx.StorageFeed", feed_definition()),
        ] {
            let parsed = zlink::idl::Interface::try_from(text.as_str())
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(parsed.name(), name);
            assert!(parsed.methods().count() >= 4);
            let path = std::env::temp_dir().join(format!("{name}.{}.varlink", std::process::id()));
            std::fs::write(&path, &text).unwrap();
            let run = std::process::Command::new("varlinkctl")
                .arg("validate-idl")
                .arg(&path)
                .output();
            let _ = std::fs::remove_file(&path);
            match run {
                Ok(out) => assert!(
                    out.status.success(),
                    "varlinkctl validate-idl {name}: {}{}",
                    String::from_utf8_lossy(&out.stderr),
                    String::from_utf8_lossy(&out.stdout)
                ),
                Err(_) => eprintln!("varlinkctl is not installed: {name} checked by zlink only"),
            }
        }
    }

    /// The file is made from the types: when they change it changes.
    #[test]
    fn the_interface_file_is_current() {
        check("org.velarx.Storage.varlink", &definition());
    }

    #[test]
    fn the_feed_file_is_current() {
        check("org.velarx.StorageFeed.varlink", &feed_definition());
    }
}
