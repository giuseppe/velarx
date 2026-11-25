<!-- SPDX-License-Identifier: Apache-2.0 -->
# Storage

How Velarx stores images, its security properties and limits, and the wire
interface of a storage driver.

## Overview

The files of all the layers of all the images live in one directory,
`<store>/objects`, each regular file once, named by its **fs-verity digest**
(`objects/ab/cdef...`): SHA-256 (SHA-512 for an image made with
`--digest sha512`) over blocks of 4096 bytes, no salt. Layers are
tables of contents (TOC), not trees of files: the database
(`<store>/db.sqlite`) keeps a small row for each layer, and its TOC and
tar-split are two files of a directory of the layer, `<store>/layers/<name>/`
(`toc-<hex>.zst`, and `tarsplit-<hex>.zst` for a layer that is not canonical,
`<hex>` the digest of the file). A file is written before the row that names
it, and is never replaced by other bytes, since its name is its digest (a
layer pulled again with other bytes has the new file beside the old one, which
goes with the layer). The row has their digests, and a file is hashed against
its digest whenever it is read: a file that is not the one its row names is
refused. The table file of a layer pulled by its table (key `toc:`) is the
table as the registry sent it, which is what the store service gives; that of
any other layer is the zstd of the JSON of its TOC. A layer marked incomplete
has a row that says it has no tar-split, and the next pull of it makes it
complete.

A root file system is an EROFS image of metadata (`<store>/composefs/`)
whose regular files point to objects; the kernel (overlayfs with data-only
layers) or a FUSE file system of the image server puts the objects behind it.
Per-file work (hashing, fs-verity, the EROFS images) is done when the pull
ends, so that running an image costs the same however big it is. A lazy pull
(zstd:chunked) fetches only the TOC to start a container; files come on
demand. It is transient until it is complete: nothing of its staging is made
durable and a reboot discards it; its completion makes the layers and the
image durable before they are named in the store. Names appear only for whole, checked files and the database is written
after the names are durable: the files of a layer are written with the images
of the layers, before the barrier of the store that makes them durable, and the
row that names the layer comes after it. The collection removes the directory
of a layer with its row, and the directories no row names (a pull that wrote
its files and did not commit) and the temporary files of a writer that died,
which the start of the daemon, the first start of a boot and the storage
service at its start remove too, when no pull holds the store.

What a pull, a commit or a build in progress uses is told by a hold: a
directory `staging/pull-<id>` or `staging/build-<id>` that is live while a
process has an `flock` on it (the owner takes it shared and keeps it, so the
kernel lets it go when the process ends however it ends; whoever judges or
removes a hold tries to take it exclusive without waiting, and a failed try
counts as live). A hold is made under a temporary name, locked, and renamed,
so no directory of that name is ever seen unlocked while its owner lives. The last user to let go does it under a gate (a lock on `staging` itself that a look takes shared): it renames the hold away and removes it after the gate is free, so a look never sees the instant between the unlock and the removal and never waits for a tree. The
file `pins` in it lists the layers and images the owner uses (`layer KEY`,
`image ID`); the pins of a hold nobody holds count for nothing. The
collection and `system check` ask the directory, so several commands on one
store with no service need nothing else, and a hold left by a process that
died is reported by `system check` as `stale_staging` and removed by
`--repair` and by the next collection.

The EROFS image of a layer is made from its table of contents alone, so it
is the same file in every image that has the layer, whatever is below it.
The root of a layer is its `./` entry, or a plain directory (0755, owned by
root, no time, no attributes) when it has none, and so is a directory it has
entries in but does not list: its attributes replace those of the directory
below, whose entries stay, in every view of the image (the overlay, `vfs`,
`build`, `commit --squash`, `cp`). A hard link names a file of its own
layer. An opaque marker (`.wh..wh..opq`) in the root of a layer hides
nothing, as in the kernel's overlay, whose root is the merge of the roots of
all its layers.

A named volume is a directory `volumes/NAME` (0700) next to the store, holding
`_data` (the volume's files) and `volume.json` (its labels, options, creation
time and state). The directory is the volume; its database row is a copy.
`system check` holds `volumes.lock` exclusive and reports what a change that
died leaves: a directory without a row or a row without a directory, a row or
a `volume.json` that differs or is missing, the shell of a removal or of a
create, a mode other than 0700, and anything else under `volumes`.
`--repair` makes the rows and files say what the directories say and removes
only shells, with `unlink` and `rmdir`: it never deletes data, and what is
not a volume is left untouched.

The driver is chosen by `[storage] driver` or `--storage-driver`: `composefs`
(the default), `vfs` and `varlink` (never chosen for you). A store keeps the
driver it was made with; opening it with another is an error that names both.

## The driver interface (`org.velarx.Storage`, version 2)

The engine owns the network, the identities (diff ids, EROFS digests, owners)
and the reachability of everything (what is kept); the table of contents and
tar-split of each layer are files of the driver (`Index` of the feed gives them
to it, `LayerFiles` brings them back), which the engine hashes against the
digests of its record each time it reads one.  A **storage driver** owns where the bytes live and
how a root file system is made of them.  The interface is the Rust trait
`StorageDriver` (`crates/graph/src/lib.rs`); a driver that is a separate
process serves `org.velarx.Storage`
([interfaces/org.velarx.Storage.varlink](../interfaces/org.velarx.Storage.varlink),
whose header has the rules of every call: versions, limits, descriptors,
errors, idempotence) and is fed by the engine through `org.velarx.StorageFeed`
([interfaces/org.velarx.StorageFeed.varlink](../interfaces/org.velarx.StorageFeed.varlink)).
Both are generated from the types of `crates/storage-client`; the engine's
side is `velarx_storage_client::VarlinkDriver`.  The socket must be served by
the engine's user or root (`SO_PEERCRED`, checked on every connection).  Tests
fail when the definition and the two tables below disagree.

`GetInfo -> (name, version, proto, capabilities, limits, mounts)` is the first
call of every connection: who the driver is, its words of capabilities, its
limits and the ways it can show the ids of a mapping.

### The calls

Every call but `GetInfo` and `ListStores` takes the `store` (the id of the
store the engine keeps in a file of its graph root).  `LayerRef` is `(key, diff_id, chain_id)` (the chain id is the OCI ChainID of
the layer as the top of its stack, computed by the engine; a driver that is not
`layer_chain` ignores it, and one that is keeps a layer for each stack it is
in, not one for every image that has it); `MountAsk` is
`(mapping?, idmap_mount, label?, verity?)` with `verity` the digests the engine
accepts for each layer in order (`VerityAsk::Enforce { accepted }`); `Mounted` is
`(kind: (directory, mount_fd), fd?, path?, idmap: (none, applied, mount),
label: (none, mount_context, files))`; the `path` of a `directory` root is
relative to the `workdir` that `CreateRoot` names, the work directory of the
store (`<graph root>/varlink/work`, made by the engine at open, owned by its
user, 0700, named without links): the client makes the plan
`RootfsPlan::Directory { beneath: workdir, path }` and refuses an absolute
path, `..`, `.` or an empty component, so a driver cannot have the monitor
mount any other directory of the host; an image mount is never a `directory`.

| call | arguments and reply | notes |
|---|---|---|
| `HasLayers` | `(layers: []LayerRef) -> (have: []bool)` | at most `max_layers`; one answer for each layer asked, in the order asked (the same layer at two places of a stack is two questions, for a `layer_chain` driver two answers); true for committed and complete layers only |
| `HasObjects` | `(objects: []string) -> (have: []bool)` | asked only of a driver whose `objects` capability is true; at most `limits.wants` keys; one answer for each, in the order asked, true for an object the driver has committed and can read now, under that key or by an alias of it (an object it names by its fs-verity digest is held for the hash of its content too); not an object that is only staged by a pull, nor one a collection removed; answered from the driver's own store, the engine keeps no table of its own; the engine names a held object as the source of a `copy` event of a `Fetch`, below |
| `BeginPull` | `(pull, layers: []PullLayer) -> (kind)` | the pull of an image, driven by the driver; the whole ordered layer list, each layer with its `chain_id`, its `parent` chain id and `stored` (what `HasLayers` answered for its place), and only the layers not stored are fetched; the descriptor 0 is the driver's end of the feed socket pair (`org.velarx.StorageFeed`); `more`: replies of kind `progress` (with a `progress` field), then `staged` (the engine's `Settled` check comes after it, **before** the driver publishes: a refusal leaves nothing visible) |
| `ReadObjects` | `(pull?, ranges: []Range) -> (index, size?)` | `more`: one reply for each range, in the order asked, and the bytes of the range follow on the pipe that is the descriptor 0; `pull` names the objects a pull staged and has not committed; at most `limits.ranges` |
| `Commit` | `(pull, layers: []LayerRef) -> ()` | the layers the pull brought in; all or nothing, made durable by the driver (the engine takes no barrier) |
| `Abort` | `(pull) -> ()` | ends a pull; drops only what no other live pull and no committed layer uses |
| `CreateRoot` | `(container, workdir, image?, layers: []LayerRef, owner?, ask: MountAsk, size_limit?) -> (root?: Mounted)` | idempotent; `more`; makes what the driver keeps for the root; the reply has the kind of the mount (`plan`, `idmap`, `label`) and **no descriptor**, none without an image (`--rootfs`); every later `Mounts` answers the same kind, `idmap` and `label` |
| `CreateImageVolume` | `(container, index, image, layers: []LayerRef, ask: MountAsk) -> (volume?: Mounted)` | idempotent; `more`; the same for an image mount (the engine counts the `mount_fd` ones and refuses more than 15 at create) |
| `Mounts` | `(container, root?: MountAsk, volumes: []VolumeAsk) -> (root?: Mounted, volumes: []Mounted)` | the only source of descriptors; the mounts of one container per call (the client takes it from `MountsRequest::container`, which refuses a request of two); a volume never created is `missing` with `recreate_container` |
| `LayerFiles` | `(layer) -> ()` | the files of a committed layer as the driver kept them, as regular files opened read-only: `toc.zst` is the descriptor 0 and `tarsplit.zst`, if the layer has one, the descriptor 1; the engine hashes them against the digests of its record, so a file that is not those bytes is refused; a layer that is not committed is `missing` with `pull_again` |
| `MountImage` | `(layers: []LayerRef) -> ()` | one descriptor: a new read-only mount of the root file system of the image made of the layers (a directory where the service cannot make a mount), for the engine's reads of what a create needs of the image; no container, no mapping, no label; the engine reads below it with `openat2` and drops it |
| `WritableRoot` | `(container) -> ()` | one descriptor: the container's writable layer, the directory its writes land in (the upper of an overlay, the copy of a copying driver), for the engine's walks: the user files and the label at create, `cp` and `export` of a stopped container, and `diff`, `changes` and `commit`, which may be of a **running** one.  A driver whose layer is a mount answers a new detached clone of the mount the container runs on (the same superblock), never a second mount of the same upper |
| `Size` | `(container) -> (bytes)` | mandatory: a walk over the wire costs a call per file |
| `Exists` | `(container) -> (exists)` | |
| `RemoveRoot` | `(container) -> ()` | the volumes go with it; idempotent |
| `RemoveImage` | `(image) -> ()` | forgets what the driver keeps of the image |
| `Check` | `(image, layers: []LayerRef, full) -> (problems: []Problem)` | `more`; `Problem` is `(kind, message, layer?, path?, repair)` with `kind` an enum |
| `Repair` | `(layers: []LayerRef) -> (artifacts: []Artifact)` | `more`; an `Artifact` is `(key, erofs, owners)`: makes the artifacts again from what the driver keeps and answers their identities, which the engine checks against those it makes from the tables of contents before it records them; idempotent |
| `Usage` | `() -> (files, bytes)` | of the driver's own artifacts; the objects are the engine's |
| `Status` | `() -> (pairs)` | names and values the driver reports of itself |
| `ListStores` | `() -> (stores)` | no `store`; the stores of the caller's uid that the driver holds, each `(store, bytes, last_open?)`, for a driver that serves several stores; the engine's `StoreId` of each is in a file of its graph root, so a store whose graph root is gone is found here |
| `DropStore` | `(store) -> ()` | removes the store and everything under it (layers, roots, image mounts, staging); idempotent; `busy` while a pull or a container of it is in progress; a name that is not a store id (32 hex digits) is refused before it names a path |
| `Collect` | `(keep_length) -> (bytes_freed, errors)` | `more`; the keep set is JSON lines of the sealed memfd that is the descriptor 0, `keep_length` bytes |

### Trait method to wire call

Every method of `StorageDriver`, and what a varlink client does for it.

| trait method | wire call or engine-side form |
|---|---|
| `name`, `graph_name` | `GetInfo.name` (the graph name is the engine's table) |
| `capabilities` | `GetInfo` (cached for the life of the connection's version) |
| `graph_data` | engine-side: empty `GraphDriver.Data` for a remote store |
| `status` | `Status` |
| `pull` | `BeginPull` ... `Commit`, with the feed (`Fetch`, `ReadObjects`) |
| `has_layers` | `HasLayers` |
| `remake_staged` | the engine's own `composefs` driver, which runs the image while it is pulled; no wire call |
| `repair` | `Repair` |
| `read_objects`, `open_object` | `ReadObjects` (`open_object` spools the bytes into an unnamed file of `<graph root>/varlink/scratch`, on disk, not in `TMPDIR`) |
| `objects_in_order` | `ReadObjects`, one call for the next objects of a list the reader takes in order (up to the limits of the proof of a pull), not one call for each; no other change on the wire |
| `remove_image` | `RemoveImage` |
| `image_volume_create` | `CreateImageVolume` |
| `mounts` | `Mounts` |
| `image_view` | `MountImage`, read through its descriptor (`velarx_fuse::MountedImage`); the tables of contents of the layers are not read |
| `holds_objects` | engine-side: false (the objects are the service's, which its `Check` reads) |
| `writable_create` | `CreateRoot` |
| `writable_paths` | engine-side: a path only for the engine's own driver (an overlay's upper); a remote store has none |
| `writable_root` | `WritableRoot` |
| `writable_size` | `Size` |
| `writable_remove` | `RemoveRoot` |
| `writable_release` | none: what the monitor of an `--rm` container needs to send `RemoveRoot` itself (the socket, the store) |
| `writable_exists` | `Exists` |
| `diff`, `changes`, `apply`, `stopped_view` | engine-side: the engine walks the descriptor of `WritableRoot` (`diff_native` is announced for later); the files of the image below that a change needs (a metadata-only copy-up, a renamed directory) and the files of a squash are read back with `ReadObjects` (the next ones of the walk in one call, `objects_in_order`), never from the engine's own store |
| `is_root_of` | engine-side: the engine compares the process's root with the root it attached itself |
| `lock_unused_layers` | engine-side: none in use (the layers are the service's, which mounts them itself; the engine does not know what the service holds, and the service removes only what its own `Collect` is told to keep) |
| `check` | `Check` |
| `release_engine_copies` | engine-side: the engine's own copy of the files of a lazy image, which only the engine's lazy phase keeps (the pins of the containers it serves); the service is not asked, a driver with no copy of its own has nothing to release |
| `leftovers` | engine-side: the engine scans its objects, and a remote store answers no file of its own |
| `collect` | `Collect` |
| `usage` | `Usage` |
| `list_stores`, `drop_store` | `ListStores`, `DropStore` (a driver of a single store, the engine's own, answers `unsupported`) |

What is not in the trait because it is the engine's own: the stream of a
layer's diff id (`objects::open_layer`, from the tar-split and `ReadObjects`, or
from the table of contents alone for a layer that is a canonical tar, which has
no tar-split),
the owners of the files of the layers (`objects::image_owners`), the digest of
the merged image a sealed manifest states, the mode of `composefs_digests`, and
what is served to peers (the store service serves the objects when the driver
says `serve_content`, and nothing otherwise).

## Between versions

Nothing is compatible between versions (README).  A database of another
schema version is not opened (`remove the store, or use the velarx that made
it`); a store of another build with the same version fails at the first
statement that needs what changed, and `system check` stops on a table of
contents of the old form and removes nothing.  A store whose driver this velarx does not have is not
opened either; a client asks an engine service whose interface, version or
digest is not its own to `Restart` from the installed binary; a monitor or a
p2p service of another version is refused with an error.

## Security properties and limits

What the design gives:

* **Content is checked on entry.**  Every chunk is verified against its
  sha256 and every file against the fs-verity digest the TOC gives before it
  can get a name; every layer
  against its diff id and the configuration; the merged EROFS against the
  digest the manifest states; the manifest by policy.  Sources and peers are
  untrusted: everything they send is verified, and a lazy file is verified
  chunk by chunk and as a whole.
* **Immutability where the file system has fs-verity.**  Files of the store
  (0444) and the images in `composefs/` have fs-verity enabled before they
  have their names.  No process can write them, including by an old
  descriptor, and the kernel checks every page against the Merkle tree.
* **The kernel enforces the image.**  With `verity=on` overlayfs refuses a file
  whose measured digest is not the one in the stub; with `require` also a file
  with none.  The layer images are checked against their digest before they
  are mounted.  On the FUSE path with passthrough the kernel checks the pages
  of the backing file.
* **Staging is not trusted.**  A lazy commit opens with `O_NOFOLLOW`, has the
  kernel measure the file through the descriptor (its name must be the
  digest), and links that inode; for a file that can still be written, it
  copies and hashes the copy.
* **Decompression is bounded as it happens.**  A layer (gzip, zstd, the
  files of a zstd:chunked layer) or an archive given to `load` may inflate to
  `max_inflate_ratio` (128) times its compressed size, or `inflate_floor_mib`
  (64 MiB) if more, never above `max_layer_gib` (`max_archive_gib` for an
  archive).  The decompressed bytes are counted as they are produced and the
  stream is cut at the limit, before they are written or staged, so a 1 KB
  bomb writes at most 64 MiB.  The entries of a layer or an archive are
  bounded too (4 Mi for a layer, 1 Mi for an archive), as are the names, the
  extension headers and the xattrs of a tar entry.
* **The memory of a pull is bounded, the disk is the file system's.**  A
  write that finds the file system full (or the quota of the user spent)
  fails with the error of the file system, and the pull removes what it
  wrote.  A layer that the manifest announces larger than
  `max_layer_gib`, or whose table of contents gives its files more bytes
  than that, is not fetched, and a download (a layer, a blob, a range,
  a manifest, a URL) that brings less than `min_speed_kib` KiB per second
  over `min_speed_secs` seconds of waiting fails: the read timeout (60 s)
  restarts with every byte.  The pull workers run in a
  cgroup (`pulls/<id>` below the daemon when its unit has
  `OOMPolicy=continue`, else a systemd scope per worker, decided when the
  first worker of the process starts) with
  `memory_high_mib`, `memory_max_mib` and `pids_max`; a worker the kernel
  kills for its memory fails the pull naming the knob, and only the pull.  The
  lazy files the engine stages, for a miss or a completion, are bounded by
  their table of contents.
* **Names are validated.**  An object name is `fsverity-sha256-12:` and 64
  lowercase hex digits, or `fsverity-sha512-12:` and 128, and nothing else
  (`Object::new`); a digest from a peer or a source is checked before it names
  a path.

What an attacker with write access to the store (the user, or root) can do:

* Edit `files`, the files of a layer's directory (`layers/<name>/`, whose
  digests the rows keep: a change is found when the file is read, a change of
  the row and the file together is not) or the images' records and sidecars (the
  `.verity`, `.id`, `*.json` files), and replace any file that has no
  fs-verity, or delete and recreate one that has.  The checks above compare
  what a file *is* with what the store *says*, and the store says what its
  writer wants.  fs-verity makes accidental or low-privilege modification
  fail; it is not a defence against whoever owns the store directory.  The
  content behind a name is only re-established by `system check`.

What an attacker with that access cannot do: make the kernel serve a file
whose measured digest differs from the one in an *unmodified* image stub;
modify a file with fs-verity in place; make a staged file enter the store
under a digest it does not have; make a half-written file appear under an
object name.

**Not implemented / known limits**

* **The chain of trust is held by default where the store can hold it.**  With `[storage] fsverity` not
  off, on a file system with fs-verity, for an image that is all in the store whose
  layers were pulled with it (`layers.sealed`: no probe of the store at a
  start, and a sealed layer that cannot be measured is refused, never run
  unheld), a start holds the files to the chain when the
  container was made from a digest (`NAME@sha256:...`, `--mount
  type=image,source=NAME@sha256:...`), when `--verify-image` gives the digest
  of the manifest of the image (an index digest is not accepted), or when the
  image has a signature the signature policy accepts now and accepted at the
  pull; with no option.  The digest is hashed against the manifest again at every
  start (a plain `start` goes by the digest recorded at the create), each
  layer image is held to the digest the manifest states or, where it states
  none of ours, to the one recorded when the engine made it, the overlay has
  `verity=require`, and the monitor reads the mount back.  Held to the record,
  the chain does not cover a writer of the store who edits the record and the
  EROFS image together; a manifest that states the digests, signed or typed,
  does, and `--security-opt verity=enforce` or `composefs_digests =
  "require"` demand it.  An image named by a tag that no signature vouches
  for, an image that is not all in the store (a lazy pull, until it is
  complete), layers recorded when the file system had no
  fs-verity (a pull of the image, and a full `system check`, seal a layer
  whose EROFS image the kernel measures as the digest recorded for it, one
  ioctl each, and never otherwise), and a driver that checks at pull only
  (vfs) are held to nothing, silently; the debug log says `verity
  chain: OFF (reason)` for each.  `--security-opt verity=off` and `[storage]
  verity_chain = "off"` turn it off, and are refused where the digests or
  signatures are required (`composefs_digests = "require"`,
  `image_signature = "require"`, `signature=require`, `verity=enforce`).
  `[storage] verity_chain = "require"` makes a start whose image cannot be
  held (any of the reasons above) an error with the reason, and refuses
  `verity=off`; an image that states no digest is fine, it is held to the
  record.
  A container with an image mount holds the chain for all of its images or
  for none (the monitor enforces for the container).  Rootless, on a kernel
  without `redirect_dir=followdata`, the files of the layers above the lowest
  are checked on open by the image server.
* **The images of the layers are held to the manifest at every start by the
  engine.**  The stored manifest is hashed against the image id, and each
  layer image is opened once, measured (fs-verity, constant time) and held to
  the digests the manifest states (`io.containers.composefs.digest`), or to
  the layer's record when the manifest states none and the chain is not held
  (`--security-opt verity=enforce` and `[storage] composefs_digests =
  "require"` demand the manifest's own digests, strictly); the open file that
  was measured is what is mounted.  A
  restart of a container by its own monitor checks nothing again.  A file
  without fs-verity, or on a file system whose blocks are smaller than 4096
  bytes, cannot be measured that way; `system check` reads it.  A signature
  over the manifest covers these digests.  The layers of a lazy image are
  unproven until completion, and its files are not fs-verity checked by the
  kernel before they are fetched.
* **No composefs-rs image in the store.**  The merged EROFS of an image is
  made for its digest and not kept: the store cannot be mounted with
  `mount.composefs`, and a manifest that does not state the digest gets it
  only when it is pushed again.
* **Without fs-verity** (`fsverity = false`, or a file system that lacks it)
  files are named by a computed digest, nothing is enforced, and the store
  is only as safe as its permissions.
* **Block size.**  fs-verity uses a Merkle block of 4096 bytes, or the file
  system's block size if smaller (an ext4 of 1 KiB blocks refuses a larger
  one).  On such a file system the kernel's digest differs from the one
  composefs-rs computes; the objects are named by the kernel's (`checked`),
  the images of the layers redirect to them, and the merged EROFS digest
  is not what `cfsctl` computes.  Such a store also cannot share objects with
  a repository of composefs-rs.
* **mmap and SIGBUS.**  The image server maps its EROFS images and the index into
  memory for its lifetime.  They are read-only; with fs-verity they cannot be
  truncated.  Without it, a file truncated or lost under the mapping kills the
  image server with `SIGBUS` (there is no handler); the container loses its root
  file system.  The files served from `objects` are read with `pread`, not
  mapped, and a file that is shorter than the image says is an `EIO`.  This
  is not guarded on purpose: reading the image into memory instead would
  cost its size in resident memory per container and time at every start
  (a run of a big image must cost what a run of alpine does), to protect
  against someone who can already write the store, who can do worse; the
  image is a file nobody writes (0444, in a directory only the store's user
  can write) and, with fs-verity, one that cannot be changed.
* **Kernel.**  The root file system needs Linux 7.3 or later
  (`datadir+`/`lowerdir+`; the `volatile` option of the throw-away containers
  needs 5.10); fs-verity needs a file system that has it (ext4,
  f2fs, btrfs).
* **Hashing cost.**  The fs-verity digest of a file on a file system without
  fs-verity is computed by software at commit.  A layer read whole is the exception: the pass that
  hashes each file also measures its fs-verity digest (one more SHA-256 tree
  over the bytes), because the store can only be asked for a file by that
  digest; a file the store has is then not written, and not read again at the
  commit, and a file it lacks is measured once more by the kernel or by the
  commit.
* **The binary table.**  A zstd:chunked layer that velarx writes has, beside
  its JSON TOC, the same table of contents in records of fixed size: a
  skippable frame before the TOC, named by the annotations `table-position`
  and `table-checksum`, which other readers ignore.  Every digest of it is of
  the algorithm of the layer (the one of `--digest` or `[build] digest` when
  the image was made), `table-checksum` too.  A layer gets one when each of
  its paths is there once and in the order of the paths, a directory before
  what it holds, with hard links to an earlier file: every layer velarx
  builds.  A pull of a layer that has one, lazy or not, fetches and checks
  the table instead of the JSON TOC (its checksum against the descriptor,
  then every record where it is, see `crates/storage/src/table.rs`, whose
  rules hold what the checks of a JSON TOC test: each path once and in
  order, one size for a digest, an fs-verity digest for each file), makes
  the entries the layer is stored by from it in one pass, and never reads
  the JSON: a table that cannot be used is an error that names the layer.
  Its key is `toc:` and the table's checksum, so the layer is not the one
  a pull by its JSON TOC stored.
* **Layers of other tools.**  A zstd:chunked layer is pulled through its
  TOC or not at all, lazily or not: one whose TOC gives no fs-verity digest
  for a file (containers/storage writes none unless asked) is refused with
  an error that names the layer and the file, and Velarx does not compute
  the digests itself.  Push such an image again with velarx (`push
  --compression-format zstd:chunked`) to make one it pulls.  A zstd:chunked
  layer of an archive or a directory, which have no ranges to read the TOC
  by, is refused too (`load` of such an image is not supported yet), and so
  is a layer whose tar-split does not describe the entries of its TOC.
* Only the main store is written; additional stores are read-only.
