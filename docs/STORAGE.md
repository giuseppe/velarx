<!-- SPDX-License-Identifier: Apache-2.0 -->
# Storage

How Velarx stores images, its security properties and limits, and the
interface of the storage driver.

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
below, whose entries stay, in every view of the image (the overlay,
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

A store has one storage driver, and `composefs` is the only one there is.
`[storage] driver`, `--storage-driver` and `VELARX_STORAGE_DRIVER` accept
`composefs` or nothing; any other value is an error. The driver is recorded in
the store, and a store recorded with another driver is not opened (the error
names the driver and the store: use the velarx that made it, or remove the
store).

## The driver trait

The engine owns the network, the identities (diff ids, EROFS digests, owners)
and the reachability of everything (what is kept).  The **storage driver**
owns where the bytes live and how a root file system is made of them.  The
interface is the Rust trait `StorageDriver` (`crates/graph/src/lib.rs`); the
driver, `composefs`, is in the engine's process, and the conformance suite of
`crates/graph` is run against it.

What is not in the trait because it is the engine's own: the stream of a
layer's diff id (`objects::open_layer`, from the tar-split and `read_objects`, or
from the table of contents alone for a layer that is a canonical tar, which has
no tar-split),
the owners of the files of the layers (`objects::image_owners`), the digest of
the merged image a sealed manifest states, the mode of `composefs_digests`, and
what is served to peers (the store service serves the objects when the driver
says `serve_content`, and nothing otherwise).

## Files inside the image

`[storage] inline_threshold` (`velarx pull --inline-threshold=N` for one
pull) makes the EROFS image of a layer hold the regular files of 1 to N bytes
itself (-1: every file, 0, the default: none).  The layers a pull, a load, a
build, a commit or an import make take the configured value; the layers a
store has keep the one they were made with, silently (`velarx rmi` and a
pull again make them with another).  `layers.inline` records the value and
the table `inlined_files` where each file is in the image (`offset`, `size`);
those files are not in `files` and `file_refs`, so they are no objects and
collection needs nothing of them.  "The content of the file with digest d" is
the object when the store has it, else its extent of the image of a layer
(`Database::inlined_file`); what reads a file by its digest (push, save,
commit, copy) finds it either way, and an extent is read back as a temporary
copy of it.

The image of such a layer is not the one its table of contents alone makes,
so the digest of it that a manifest states can never be the recorded one:
`composefs_digests = "require"` and `verity=enforce` fail for it as for any
other mismatch.  A manifest that velarx writes states the digest of the image
made from the table of contents alone.  `system check` does not fetch what
an inlined layer lacks: a layer to be made again with another threshold is
removed with `velarx rmi` and pulled again.

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
  ioctl each, and never otherwise) are held to nothing, silently; the debug
  log says `verity chain: OFF (reason)` for each.  `--security-opt verity=off` and `[storage]
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
  A store whose database has a write-ahead log or a journal with content is
  skipped with a warning: another velarx is running on it, or one ended and
  left its log (one that was killed, or one whose writes were all volatile,
  such as a daemon or a `container run --rm`, which does not write the log
  back at its end).  The log holds changes that are not in the database file, which is
  all that is read, so the store would show an old state.  Any command that
  writes nothing, run by its owner when no other velarx runs on the store,
  writes the log back and removes it.  A store that is absent, of another
  schema version or made with another storage driver than composefs fails
  the start.
