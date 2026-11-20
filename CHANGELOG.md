<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to Velarx are in this file.  The format is that of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries are written by hand, for a user of Velarx: what a release adds,
changes or fixes in words, not the titles of merged pull requests, and
without the numbers of issues or pull requests of any tracker.

## [Unreleased]

### Added

- Containers of one image share the in-memory file system of its layers
  where the kernel has the EROFS mount option `superblock_share` (Linux
  7.4): a second container adds no inodes or memory for the files the first
  has read.  The layer stays in use until the last of them is gone.
- The overlay network of the containers is a process of its own, `velarx-p2p
  overlay` (`velarx-p2p-overlay.service`, which replaces the drop-in of
  `velarx-p2p.service`), a node of a swarm of its own: the swarm key or
  authority of `p2p.toml`, but its own identity, port and Kademlia protocol
  (`[overlay] listen_addresses`, `bootstrap_peers`, `identity_path`,
  `certificate_path`; `[overlay] enabled` is gone), so the containers'
  packets and the layers' requests do not compete, and `velarx-p2p.service`
  needs no capability.  A container cannot
  send with the address of another container of its node.  On an upgrade:
  remove `enabled` from `[overlay]` (a `p2p.toml` that has it is refused) and
  the drop-in `velarx-p2p.service.d/overlay.conf`, and enable
  `velarx-p2p-overlay.service`.
- runc and youki start a container with `[containers] keyring = false` (the
  rootless RUN steps of a build too): their `create --no-new-keyring` is used
  where it was tied to crun.
- `container checkpoint` and `container restore` take the options they refused:
  `restore --tcp-close`, `--latest`, `checkpoint --create-image` and `restore
  IMAGE` (a checkpoint image), `restore --pod` (the container of a pod into
  another pod) and `--publish` with `--import` or an image, `checkpoint
  --pre-checkpoint` and `--with-previous` with `--export` and `restore
  --import-previous` for the archive of a pre-checkpoint, and `--print-stats` with `--export`.  A checkpoint or a
  restore of several containers looks them all up before it acts on the first,
  and `restore --tcp-established --name` is refused, as podman's.
- `velarx-api` serves its TCP listeners with TLS (`--tls-cert`, `--tls-key`
  or `[api] tls_cert`, `tls_key`) and, with `--tls-client-ca`, only to the
  clients whose certificate that CA signed; a client certificate replaces the
  bearer token.  The podman client reaches it with `--url tcp://HOST:PORT
  --tls-ca --tls-cert --tls-key`.
- `velarx-p2p` gives the peers the files a pull has staged as soon as each is
  complete (each chunk was checked when it came, and the asker checks it again),
  tells the filter the layer from the first file, and a pulling node takes its
  files in an order that differs from node to node, so the nodes of a rollout
  exchange what they have instead of all waiting for the seed: 20 nodes on 1 Gbit/s
  links pull 300 MB in 25 s instead of 47 s.  A group the peers are much slower
  with than they were before (a quarter of the rate, for five seconds) is left to
  the registry, a part of a spread group is asked of a second peer only when the
  first is late for the group, and the peers of the node's zone (the zone of its
  certificate) are asked first.  `velarx-p2p serve --dir DIR` gives the files of a
  directory to a swarm with no engine; a container name belongs to the first peer
  that claimed it, and `name.<peer id>` reaches the container of one peer.
- `velarx-p2p` tells each peer a Bloom filter of the layers it holds (the ones
  that may be given to peers), when the peer connects and as small updates after
  (at most one every two seconds), and pulls ask the peers whose filter says the
  layer may be there, without asking each peer a question first: in a swarm of
  1000 nodes a pull sends no question to the peers (32 to 64 for a pull of 4
  layers before), a layer nobody holds goes to the registry at once, and a node
  that pulls 50 layers at once no longer asks each peer eight questions.  A
  filter takes about 10 bits a layer (10 KiB for 5000 layers); the settings are
  `advertise_layers`, `filter_fpr`, `filter_max_kib` and
  `filter_interval_secs` of `p2p.toml`.  A member that knows the digest of a
  layer can test it in the filter of any node (it could ask the node before);
  `advertise_layers = false` keeps the filter from the peers.  `announce_images`
  now only tells the list of the images and publishes the layers in the DHT.
  `velarx p2p peers` shows the filter of each peer and `explain` which peers were
  asked because their filter said maybe.
  A filter never says "no" for a layer its node told it holds: an update
  that was lost or came out of order, or one of a node that restarted, makes
  the filter say "maybe" or "not known" until the next whole filter, an
  update that could not be delivered is followed by the whole filter, and the
  whole filter goes to every peer about every 10 minutes at a random time.
- A node that pulls many layers at once has at most eight QUIC streams of
  requests open to one peer (a request takes one for each lane of
  `quic_streams`), so that the peer does not answer the others "no room".

- `velarx-p2p` asks its peers fewer questions whether they have a chunk: the groups
  of a layer that run at once share each round of questions (the first asks, the
  others use its answers, for a few seconds), and a node has at most four
  questions in flight to one peer (the slots a peer answers them in), so a node
  that pulls 50 layers at once asks each peer a few at a time instead of all at
  once, and every layer is still asked about.
- `velarx-p2p` limits the memory a connection can make the node hold: it does
  not depend on the windows the peer advertises (`quic_window_mib`, 8 MiB sent
  and not acknowledged, it was 64; also what a connection moves in a round trip:
  raise it for long fast paths).
- The places `velarx-p2p` lends to newcomers when it is full are freed one
  second after the newcomer was answered.
- `velarx-p2p` asks its peers for others when it has few: a node that a full
  bootstrap peer refused, or that has no more than `min_peers` peers (counting those
  it is dialing for an earlier answer), asks a few of the peers it has which peers
  they know and connects to some of them (at most 8 for
  an answer, only addresses the dial filter allows, a peer asked and answering once
  in 10 seconds), so it joins the swarm through peers it learnt.
- `velarx-p2p` dials only the addresses its filter allows, whoever named them (the
  DHT, the peers, mDNS): not loopback, link-local, multicast, unspecified
  or reserved addresses nor the node's own, and only an IP address with a TCP
  port (no name, no address in an address),
  with `dial_allow` networks in `p2p.toml` to change that
  (nodes on one host need `dial_allow = ["127.0.0.0/8"]`); the bootstrap peers you
  name are never refused.  `velarx p2p status` counts what was refused by reason.
- `velarx-p2p` keeps its identity: the key pair of the node is made at the first
  start and read at the next ones (`identity_path` in `p2p.toml`, by default
  `p2p/identity.key` in the root directory of the engine, mode 0600), so a
  restarted node is the same peer: what the others hold against it, give it
  or know of it by peer id applies again, and its overlay subnet does not
  change.  It is not a credential (the swarm is still one trust domain with
  one key); `docs/THREAT-MODEL.md` says what it is and is not.
- `velarx p2p` shows more of a running node: `peers` tells for each peer its
  QUIC state, what it announced, what this node believes it has and lacks, and
  what was fetched from it; `advertised`, `serving` (slots, the upload credit)
  and `knowledge`; and
  `explain [LAYER|CHUNK|IMAGE]` says which peers a pull considered and why,
  what each answered, and why what they did not give went to the next source.
  The groups, probes and requests of a pull and each request a node serves have
  tracing spans (`RUST_LOG`).  A deterministic simulator of the peer layer
  (hundreds of nodes on a virtual clock) tests it without a cluster.
- Quadlet `.kube` units run: `velarx kube play` and `velarx kube down` run
  `velarx-kube`, which takes the global options `--log-level` and `--log-format`
  that `velarx NAME` passes to every program it runs.  The kube routes of the
  REST API are not served (501), by design.
- `Remove` in the interface `org.velarx.Monitor`: the monitor removes its
  container (stopped first with `force`), as it does when an `--rm`
  container exits, and answers once it is gone; `velarx rm` uses it.
- A layer that a build, a commit or a squash makes is the canonical tar of
  its table of contents: its diff id is the digest of that tar, and no
  tar-split is kept for it.  Pushed as `zstd:chunked` it is a layer of
  version 2 (`io.github.containers.zstd-chunked.version`, `"version": 2` in
  its table of contents, no tar-split), which any reader of tar and zstd
  reads, and which a pull, lazy or not, takes by its table alone.  Pulled
  layers keep their diff ids and their tar-split, and are pushed as they
  were.  A whiteout has the mode 0644, the owner 0:0 and the time 0 in
  every layer.  A table of version 2 that is not canonical is an error that
  names the layer.  The steps that the build cache of an earlier release
  has are built again.

### Changed

- A registry that cannot give the parts of a zstd:chunked layer (S3-backed
  registries ignore a request of several ranges and answer it with the whole
  blob; some refuse a range with 400 or 416) is read once: the fetcher
  reads the blob into a file with no name beneath the staging, checking its
  digest as it goes, and the workers cut the table of contents and the
  chunks of every request from that file.  The file goes with the layer
  (`Forget`) and with the connection.  A pull of such a layer reads the blob
  once (it read it about four times), a lazy pull and its completion once
  each.
- The binaries are position independent executables again, with packed
  relative relocations: the address space of the engine and of its helpers is
  randomized, at no cost in size.  They need glibc 2.36 or later (the
  package requires it by itself) and the build a linker that supports
  `-z pack-relative-relocs` (GNU ld 2.38, lld or mold).
- The table of contents of a layer is kept compressed in the database: a store
  made by an earlier build is not used (remove it).  `system check` stops with
  an error on such a store and `--repair` removes nothing, where it removed
  every image; a layer whose table cannot be read in a store of this build is
  reported for its images, which `--repair` removes, and the others are
  checked.
- The copy of an image of the `vfs` driver, `build`, `build --squash` and
  `commit --squash` show what the overlay of the EROFS images of the layers
  shows, where each layer is its own: the root of a layer with no entry `./`
  is a plain directory (0755, root, no time, no attributes) and so is a
  directory a layer adds files to without listing it, in place of the one
  below; a directory a layer removes and makes does not have what was below
  it, whatever the order of its table; a hard link to a file of a layer
  below is an error.  These views kept the root and directories of the
  layers below.  An opaque marker in the root of a layer hides nothing in
  any view, as in the kernel's overlay, where these views dropped the files
  of the layers below.
- A zstd:chunked layer is pulled through its table of contents or not at all,
  eagerly and lazily, so that an image whose table and tar stream describe
  different filesystems is never taken for the layer of its stream: the
  entries of the layer and its EROFS image are the table's, and a tar-split
  that does not describe the same entries is refused.  What was pulled whole
  instead is now an error that names the layer, and nothing of the image is
  stored: a table without a tar-split (and not of version 2), a table that
  gives a file no fs-verity digest (what containers/storage writes by
  default), zstd:chunked annotations that do not name a table this reads (one
  of `manifest-position` and `manifest-checksum` without the other, another
  kind of table, annotations on a layer that is not zstd), and a zstd:chunked
  layer of an archive or a directory (`load`, `oci-archive:`, `oci:`,
  `dir:`), which has no ranges to read the table by: loading such an image
  is not supported yet.  A registry that serves no ranges, or refuses them,
  gives the blob whole as the transport of the ranges.  The statistics of a
  pull no longer have `note`, and `ImageNotLazy` no longer says
  `no_file_digests`.
- A table of contents that gives one content (one fs-verity digest) two
  sizes, or whose files add up to more than a layer may have
  (`max_layer_gib`), is refused, with an error that names the layer, before
  anything is fetched or stored.  The first was pulled, and left a file that
  could not be read and a store that `system check` called damaged; a lazy
  pull of a table of version 2 whose tar would be 2^64 bytes or more never
  completed.
- A pull of a layer that has no table of contents (a gzip layer) is faster,
  for the layers of many small files most: the fetcher hands the files it
  unpacks over to the engine as descriptors of the replies of `Unpack` (a
  small file is a file in memory), not as names in the staging, and the
  engine copies them with several threads while the rest of the layer is
  unpacked, starts their write-back as they are made, and knows each by the
  digest of the bytes it read.  Fetchers that serve `org.velarx.Fetcher` hand
  the files of `Unpack` over so (`interfaces/org.velarx.Fetcher.varlink`).
- A pull of a zstd:chunked layer of many small files is faster in the same
  way: a fetcher that announces `handover` hands over the small files it
  fetches as descriptors of its `staged` events when the engine asks for it
  (`Fetch` with `handover`), instead of naming each in the staging for the
  commit to read and link, and the engine copies and hashes them with
  several threads as they come.  The files that are not small, a store with
  fs-verity and a fetcher without the word keep the names of the staging.
- Bridge networks: a long range of published ports starts and is removed (the
  rules go as several transactions, and the soft limit of open files is raised
  for a socket per port); a name that several containers have answers all
  their addresses; the DNS server forwards the queries of a TCP client over
  TCP, several per connection; a route of the host added after `network create`
  no longer fails the start of the containers of the network; a container
  disconnected from its last network starts with the loopback only; `network
  update --dns-add` works on a network with routes or a macvlan one; a pasta
  is still found and stopped after an update of its package.
- `velarx-p2p` moves all its data over QUIC (UDP) and over nothing else: chunks,
  files, layer indexes, startup profiles and the question whether a peer has a
  chunk (a probe is one short stream).  libp2p (TCP) keeps the membership, the
  discovery and the announcements.  The second path, the JSON chunk protocol of
  libp2p with its own serving slots, limits and busy answers, is gone, with the
  fallback to it: one server of data, one set of limits (`[serving]`), one
  error mapping.  **UDP must be reachable between the nodes**: by default the
  UDP port is the port of the first TCP address of `listen_addresses` (4001),
  and `quic_port` sets another.  A peer that cannot be reached over UDP stays a
  member and is not asked for data: every request to it fails with an error
  that names the peer and why, the pull goes on to the next peer and then to
  the registry, a refused connection is tried again after 30 seconds, and
  `velarx p2p status` counts the connected peers with no QUIC path while
  `velarx p2p peers` and `velarx p2p explain` say why.  The settings `quic`
  (QUIC cannot be turned off) and `[serving] libp2p_slots` are removed, the
  budgets of a peer by its identity are gone from `[serving]` and from
  `velarx p2p serving` (the server knows an address, not who is behind it), and `velarx p2p peers`
  no longer counts the bytes sent to a peer over libp2p.  A node that cannot
  bind its UDP port does not start (the error names the address).  The
  endpoint binds `::` (IPv6 and IPv4) when `::` is a listen address.
- An image of the most layers the overlay takes mounts with the soft limit of
  1024 open files that a shell or a user unit gives: the engine raises its
  soft limit to what the image needs, `3 * layers + 64` open files, just
  before it opens the layers (never lowered, never above the hard limit), and
  a command that mounts no big image (`ps`, `inspect`, `run alpine`) keeps the
  limit its shell gave.  The engine service raises its soft limit when it
  starts (to the hard one, at most 2^20; it raised it to the hard one, a
  billion under `LimitNOFILE=infinity`), for its clients' connections.  The
  OCI runtime (the creation, the start, the `exec`s, the health checks, a
  `kill` or `delete` of the engine) and the `precreate` hooks have the limit
  the engine had, not the raised one; the container's own is the limit of its
  spec (`--ulimit`, podman's default), as it was.
- A pull refuses an image the overlay could never mount before it fetches
  anything, with the image and the limit named, as `TooLarge` of the API: its
  layers and the objects of the stores are more than 500, or for `--lazy`
  its layers, the directory of the files fetched for each and the objects
  (a lazy image of one store has at most 249 layers).  It was 498 layers
  whatever the stores were, and a lazy image of more than 249 failed to mount.
- A hard limit of open files below what the layers of an image need
  (`3 * layers + 64`) refuses the pull or the load before anything is
  fetched (as `TooLarge` of the API), and the mount, with an error that names
  the image, the need and the limits, for the kernel mount and the image server alike; it was a mount
  made another way, or `velarx system check --repair` advised for an image
  that was not broken.

- `velarx-p2p`: a node that cannot reach its bootstrap peers (they are down,
  or full) dials them again, after a second and then after twice as long each time up to
  `bootstrap_retry_max_secs`, with a random part so that nodes refused together
  do not return together, while it has fewer than `min_peers` connections;
  it used to dial them once and stay alone.  A full node (at `max_incoming`)
  takes a few more connections for 3 seconds each, in which the newcomer
  learns the peers it knows and joins through them: it used to refuse them
  outright, and with one bootstrap peer for many nodes all but the first
  `max_incoming` stayed alone.  `max_incoming`, `max_outgoing`,
  `idle_timeout_secs` and the new `[serving]` section of `p2p.toml` (slots,
  QUIC connections, `upload_limit_mbit`) replace limits that were constants.
- `velarx-p2p`: `upload_limit_mbit` limits what the node uploads, for libp2p and QUIC
  together: the credit is given before the files are read, in turn to the
  addresses that ask (bytes, not requests), so a node asked for more than it
  may send does not read and buffer ahead, no address takes all of it, a
  request whose credit does not come in time is answered busy, and answers
  without data are never delayed.  A chunk is read and hashed as it is sent,
  once, and its last piece is held back until it has its digest.  A store
  file that does not match its chunk is logged as an error and told to the
  asker as a failure of that peer's store (it asks another peer, and keeps
  the peer and QUIC), never as a chunk the peer does not have.
- `velarx-p2p`: the question whether a node has a chunk (a probe) has places of
  its own, four, over libp2p: a node at its upload limit, with all its libp2p
  slots waiting for credit, still answers it instead of saying "busy", so the
  askers know where the layer is.
- `velarx-p2p`: the DHT is asked once for a layer at a time: the groups of a
  pull that ask for the same layer while a walk runs wait for its answer, and a
  walk that took more than its 3 seconds is kept as an empty answer for 5
  seconds, so that each group does not walk again.  The providers the DHT names
  are no longer hidden by the peers that announced the layer (an announcement
  is a peer's word, the DHT another source).
- `velarx-p2p`: a pull no longer hands a layer to the registry because the
  first peers it asked were bad.  A group that asked the peers that announced
  a layer (at most two of them at a time) and found them silent, failing,
  lying or without the layer goes on to the next sources: the peers whose
  gossip names the chunk, the connected peers that say they have it, the
  providers of the DHT, any connected peer, up to eight peers for a group.  A
  peer that sent wrong bytes is not asked for the layer again, and ranks last
  for every layer, for ten minutes or until it sends right chunks (saying it
  has a chunk does not undo it); one that failed ranks last until it sends chunks.
  The requests under way go on while the next peers are looked for, so a slow
  honest peer is not timed by the probes made beside it, and the hedges of a
  group are spaced (each waits twice as long as the one before it), so a swarm
  that is slow everywhere is asked a group's chunks by about four peers, not
  eight.
- There is one database: the namespaces and holders of a boot are tables of the
  store's `db.sqlite`, and the run root keeps no database.  A command that only reads the store (`ps`, `images`,
  `inspect`...) writes nothing for them.  A store made by an earlier build is
  not used; the rootless containers of an earlier build must be stopped before
  the update.
- The rows of a container run with `--rm` (its record, state, exit, network
  attachments, removal) are written without a sync of the database: such a
  container does not survive a crash of the machine anyway.  A command that
  wrote only such rows leaves the log of the database to the next one (up to
  1 MiB) instead of writing it back: `run --rm` back to back no longer pays
  two `fdatasync` per run.  Every other write stays as durable as before.
- `ps` and the container listings no longer look in a network namespace for
  stopped containers, and `ps --size` reads the size of each image once.
- A health check is one type, `Healthcheck`, in the interfaces `org.velarx.Engine`
  and `org.velarx.Monitor`: the create request, the container record,
  `inspect` and the monitor use it, with the times in nanoseconds (a time
  below a millisecond reaches the monitor as typed, it is no longer rounded)
  and `on_failure` as the `OnFailure` enum.  The request, record and monitor
  forms (`RequestHealthcheck`, `HealthConfig` and their startup and log
  types) are gone, and so are the `health_log_destination`,
  `health_max_log_count` and `health_max_log_size` of `ProcessConfig`, which
  repeated the check's own (`inspect` shows the same `HealthLogDestination`,
  `HealthcheckMaxLogCount`, `HealthcheckMaxLogSize`).  The stored record of a container has the new field names
  (`interval_ns`, ...): containers of an earlier development build do not
  carry over.
- The EROFS image of a layer is locked (a shared `flock`) while it is
  served by the image server, and, on Linux 7.3 or later, while the kernel has
  it mounted: the kernel mount is given the open image as the source of the
  file system (`FSCONFIG_SET_FD`) and keeps the lock for as long as the mount
  exists.  The garbage collection keeps a layer whose image is locked, even
  when no image or container names it any more (the feature `erofs-lock` of
  the run root says whether the kernel mounts keep the lock).  On Linux 6.12
  to 7.2 the kernel still mounts the images, by the name of the descriptor, and
  holds no lock: there the rows of the containers (`container_layers`, for
  the root and the image mounts) keep the layers of every kernel mount, as
  before.  A collection of many layers holds their images 256 at a time.
- `velarx-kube play` opens the directory of the build of an image itself and
  gives the engine the descriptor of that directory, not its path, and the
  engine builds from the directory in place, nothing is copied: COPY and ADD
  (and the digests their steps are cached under), the Containerfile and the
  ignore files read the tree through the descriptor, with no link followed
  out of it, so what is built from is the directory `play` opened, whatever
  the path of it becomes meanwhile.  A file that changes while the build runs
  is read as it is when a step reads it; a COPY whose files change between
  the digest its step is looked up in the build cache by and its copy is
  recorded under the digest of what it copied (the copy compares the status
  change times of what it copies with the time the digest began), and a RUN
  whose copied mount source changed so is not recorded.  The
  source of a `RUN --mount=type=bind` or `type=cache` from such a context, and
  the context an SBOM scanner is given, is a copy that the confined build
  worker makes for the step (as for a directory of an image: the kernel does
  not clone a mount of the client's mount namespace for the runtime), so the
  step sees the tree as it is when it starts.  The engine never changes the
  SELinux label of the directory of a client.
- The monitor of a container records its exits, restarts and health checks
  and releases its network (pasta, the port forwarder, the firewall rules, the
  bridge interfaces, the DNS records, CNI, the namespace pool, the rootless
  namespace, the network providers) itself, from job threads confined with
  Landlock and seccomp, and removes an `--rm` container the same way: a
  killed engine leaves nothing behind.  `velarx cleanup` is gone, and so is
  the `records_health` parameter of `Subscribe`.  Monitors started by an
  older velarx are settled by the next command after their container ends.
  The exit policy of a pod is applied by the monitor of the member that
  exits: a pod with the policy `stop` stops its infra container when its
  containers are gone, and a pod with no member left is stopped, with no
  engine alive.  The image of `run --rm --rmi` goes with a detached container
  too (its layers are released by the next collection), a monitor removes
  the cgroups of its container when it ends, and the monitor of a container
  on a rootless bridge network holds the namespace of the bridges through a
  descriptor: killing the process that holds it no longer risks the
  containers' networks.  A container in a network namespace of its own with
  bridge or CNI networks has its network set up before it is created.
- The default network of a container that asks for none is named `default`
  in the errors and the log (it was named `bridge`, also for rootless
  containers, whose default is pasta).

- The monitor of a container has a core that outlives upgrades of the
  engine: `Stop`, `Kill`, `Wait` and the container's state mean the same in
  every version of the monitor that says `core` 1, so that a container
  started by an older Velarx is still stopped, signalled and waited for by a
  newer one.  `velarx stop` gives the monitor the signal and the deadline
  and it kills at that deadline even when the command that asked is gone; a
  stop during the back-off of a restart cancels the restart; a kill of a
  user switches the restart policy off.  `Pause` and `Resume`, the exit plan
  (`--rm`) and the resources of `update` go through the monitor instead of
  lock files and the runtime's command line.  The monitor starts with
  `--varlink-fd N RUN_DIRECTORY`, its first call creates or restores the
  container, and the directories of a checkpoint, of a restore and of the
  health log are descriptors.  `Quit`, `Signal` and `Resize` say when they
  cannot be done.

- `run`, `start --attach`, `attach`, `exec` and `logs` go through the engine
  like the REST API and the CRI do, and the command line never opens the
  socket of a container's monitor.  `ContainerAttach` and `ExecStart` answer
  more than once: the session is taken, the descriptors of the streams of the
  process come when the container has them, and the last reply says how it
  ended; `SessionDetach` and `SessionCloseStdin` tell the engine what the
  client typed.  The channel with its letters is gone, and one copy loop
  serves the command line, the REST API and the CRI.  `exec --preserve-fds`
  passes its descriptors in `ExecStart`.  `ContainerStartAttached` no longer
  names the run directory of the monitor, and `ContainerAttachInfo` and
  `ContainerLogLocation` are gone.

- `velarx load` and `velarx pull oci:`, `oci-archive:`, `docker-archive:` and
  `dir:` are pulls like the others: the engine starts `velarx-dir --origin`,
  which confines itself to the file or the directory the command opened and
  only then reads the archive, so that the tar, its compression and its
  manifests are no longer parsed by the engine's process.  The reserved
  source names `archive` and `stores` of `[pull] sources` are gone; a pull
  of a path asks no helper unless `--sources` names some.  A transport of
  `[[transports]]` that serves `org.velarx.Fetcher` is the origin of
  `velarx pull SCHEME://...`.

- `[[push.transports]]` is now the top level `[[transports]]`, one table for
  both directions: the process on its socket serves `org.velarx.Pusher`
  and/or `org.velarx.Fetcher` and announces `origin` in the `GetInfo` of
  each.

- One spawner for every process that confines itself and must still start a
  program (`velarx_sys::spawner`): the pull workers of the registry fetcher
  and the xz and bzip2 programs of `ADD` are started by it, forked before
  the confinement, through the descriptor of the program (no path is looked
  up after the start), with arguments and variables the program's checks
  accept, and killed with the process that asked.  A pull worker that
  cannot be opened is the error of the fetcher's start, not of its first
  pull.
- `Fetch(whole)` and its event `indexed` are the call `Unpack` (the
  capability word is `unpack`).  A fetcher's failures carry a class
  (`unavailable`, `transient`, `invalid`, `not_found`, `unauthorized`, `forbidden`, `no_space`, `failed`) and a
  reason; `Cause` and the event `done` of the fetcher interface are gone (the
  last reply of a call has no event).  A fetcher that brings bytes that are
  not what their name says fails the pull naming it.  `Open` carries
  `idle_ms`: the engine ends a pull call that is silent for it
  (`[[sources.external]] idle_timeout_secs`, two minutes for the registry
  fetcher) and asks the next fetcher; a fetcher says something at least every
  half of it.  `progress` events carry the cumulative bytes of one object.
- The engine checks (`SO_PEERCRED`) that the process serving the socket of an
  external source, an external sink or a transport runs as its own user or
  as root, and refuses another, naming the socket.  Every interface file
  says who may call.
- Pod checkpoints and shared checkpoints are at version 1, as every format
  and interface is until the first release: those of earlier builds are
  not read.
- A file a fetcher staged is verified once and then linked into the store,
  whatever the file system: a store without fs-verity no longer copies every
  file at the commit (the kernel's measure is compared where there is one,
  else the file is read once, before the commit takes any lock).  The part
  of the commit that runs under the locks of the store links, renames and
  syncs, and reads, hashes and copies nothing.  A store service of the
  `varlink` driver is handed the verified file itself (`staged` event of
  `org.velarx.StorageFeed`) and links it into its store.  Without fs-verity
  a fetcher that kept a writable descriptor could change a linked file after
  the check (see the threat model).

- A push is a walk over an ordered list of pushers that speak
  `org.velarx.Pusher`: the helper sinks (`[push] sinks`, `push --sinks` and
  `manifest push --sinks`, names of `[[sinks.external]]`, each with
  `socket`, `idle_timeout_secs` and `credentials`) and, always last, the
  destination's own pusher, which the engine chooses by the scheme of the
  destination: `velarx-registry` for a registry, `velarx-dir` for `oci:`,
  `dir:` and `oci-archive:`, and for any other `SCHEME://...` the
  `[[transports]]` of that scheme, a process that announces the
  capability `origin`.  The registry is not named in the list.  A helper is
  told of the manifest the destination took, a helper silent for
  `idle_timeout_secs` ends its call, and a sink that `--sinks` names and
  cannot be reached is an error.  `[push] compression`, `compression_level`,
  `mount` and `skip_existing` tune the walk.  A destination of a
  `[[transports]]` is no docker reference: its pusher gets the
  credentials of exactly `SCHEME://AUTHORITY` (`credentials = true`), is
  failed with its name after `idle_timeout_secs` of silence, and it and the
  helpers are told the URL and the committed tag (a URL with `user:secret@`
  or without an authority is refused; the key of the credentials is in lower
  case; `velarx login s3://bucket` writes the entry); `manifest push` goes
  there too.  The four push calls of
  `org.velarx.Registry` are gone, and `ImagePush` is the one push: an image, a manifest list or an
  artifact (`artifact`) to a registry, a path or a transport, and several
  images to an archive (a save); `ImageSave`, `ArtifactPush` and
  `ManifestPush` are gone.  The progress of a transfer is `TransferProgress`
  with `TransferStatus` (they were `PullProgress` and `PullStatus`) and no longer
  carries bytes by source: the statistics of a pull or of a completion are
  `TransferStats` (`by_source`, a `BySource` of name, bytes and files for each
  fetcher of the walk, `registry` and `store`; `layers_cached`, `duration_ms`),
  which replaces `PullStats` (`bytes_from_peers` and its kin are gone, and
  `velarx image pull` prints a line for each source); the state of
  a pull in `ImagePulls` is `PullState` and the reason of `ImageNotLazy` is the
  Fetcher's `NotLazy`, both enums of the wire, not text.  `PushedImage.placed` says, for each name and for
  the digest, whether the destination took the manifest (`digest_refused`
  is gone).  The Fetcher and the Pusher give a connection its scope through
  one endpoint (`GetInfo`, `Open` once, `Connect`, `Renew`; `NotScoped` and
  `Busy` are said the same way by both).

- `save` is a push to an oci-archive (or, with `--format oci-dir`, an OCI
  layout) written by `velarx-dir --push`: it shows no progress (`--quiet`
  is dropped), the manifests carry the EROFS annotations of a push, and so
  a save needs an EROFS record for every layer of the image (`velarx system
  check --repair` makes a missing one).

- `push` to `oci:`, `dir:` and `oci-archive:` is written by a confined
  process of its own (`velarx-dir --push`) over the same list of pushers as
  a registry push (`--sinks`), with the destination opened by the client and
  handed to the engine: the engine and the pusher never resolve the path.
  The images keep their manifest and layers (a pulled image is written as it
  was pulled, a built one with `zstd:chunked` layers, or gzip with
  `dir: --compress`).  A pusher whose claim that the destination has an
  object cannot be confirmed ends the push with an error that names it and
  the object; a pusher that fails or does not place an object is passed over
  for the next one.

- `commit` and `build` no longer compress: a new layer is stored as an
  uncompressed tar (named by its diff id, hashed once as it is made), the id
  of the image is the digest of its configuration, and `push` compresses the
  layers (`zstd:chunked` unless `--compression-format` asks for another) and
  uploads the manifest with their digests.  `--compression-format` is gone
  from `commit` and `build`.

- A pull of an updated image fetches again only the chunks that changed:
  the engine hands the registry fetcher the chunks its store holds (reuse
  hints of `org.velarx.Fetcher.Fetch`), as pulls did before they went
  through the fetcher.

- `org.velarx.Fetcher`: the chunks of the store a fetcher may reuse come
  in one file the engine makes of exactly those bytes, read-only, and only
  to a fetcher that announces the word `reuse` (never a file of the store);
  new errors `NotFound`, `Forbidden`, `TooLarge` and `Busy` (a connection
  limit, which no longer takes a fetcher out of a pull; an engine keeps at
  most 128 call connections to fetchers); `Layer` again ends the calls on
  the layer told before, a scope keeps at most 1024 layers and the engine
  cancels a layer whose staging went; `Get`, `Probe` and the repository
  calls stop when the asker goes; `Probe` says `no_file_digests`; the
  table source `registry` is `carried`; the unused `ahead` of `Fetch` is
  gone; a reply value a client does not know is read as the most general
  one.  `org.velarx.Registry`: `NotFound` (no answer) is `NoResults`,
  `RegistryNotFound` is `NotFound`.  `org.velarx.ImageFetch`: a miss no
  fetcher has is `unavailable`; an image id of 128 digits (sha512) is
  taken.

- A file that several layers of one image have is fetched once by a pull
  (the layers that plan it later wait for the first fetch).  A file a
  container of a lazily pulled image blocks on is ready as soon as it is
  staged, also when it joined a read-ahead in flight, and is fetched on its
  own at once when only the background completion has it in flight.

- The `kube` commands are no longer part of `velarx`: `velarx-kube play`,
  `down`, `generate` and `apply` (a binary of its own, run by the user as
  `velarx-api` is) do what the `kube` commands of `velarx` did, with the same options but
  `--down` and `--force` of `play`, which are `velarx-kube down` and its
  `--force`.  It is a client of the engine service over varlink (it starts
  one when none answers, as `velarx-api` does; `--engine-socket`,
  `--no-start-engine`, `--config`), links no engine code, and confines itself
  (Landlock ABI 9 required, seccomp: no exec, no file read after it read its
  inputs, TCP only to the port of the API server of an `apply`).  The engine
  has no kube command, no kube interface and no YAML parser; the REST API
  answers 501 to the kube routes, so `podman --remote kube play` is not
  supported, and Quadlet `.kube` files are not supported.  `velarx` has no
  Kubernetes code and no dependency for it.
  The files of a ConfigMap volume are extracted over the volume (a file
  that an earlier play wrote and the ConfigMap no longer has stays).

- The fetcher interface `org.velarx.Fetcher` is the one of the staging
  directories (`Open`, `Layer`, `Probe`, `Get`, `Fetch` by the object
  contract); the interface of chunks in incoming files (`Has`, the chunks
  of a `Fetch`, the pieces of a `Get`) is gone, and so are the content
  sources of the engine's own pull code.
- The P2P service is a fetcher of the list of a pull again
  (`org.velarx.Fetcher`): it stages the files of a layer from the chunks of
  the peers, a layer without a table of contents from the index of a peer
  and its files, the pieces of a shared checkpoint and startup profiles
  (`Get`), and answers only for itself.  A `dir` of `[[sources.external]]`
  is served by `velarx-dir`, a fetcher binary of its own that the engine
  starts (it links no registry or HTTP code), and the example `dircache`
  serves the same on a socket.  What the fetchers before the registry fetcher
  bring counts as bytes from the peers again, in pulls and completions.
  The P2P service fails closed (Landlock ABI 9, fully enforced: abstract
  sockets and signals of its own domain only), and writes only beneath the
  staging of the layers of the store besides its sockets.  The content
  sources of the engine's own pull code are gone.
- A miss of a lazy file that no fetch had in flight reads the files that
  follow it ahead, whoever asks (the image server, or the engine).
- An eager pull of a layer with a table of contents does not replay the
  layer: every file is checked against its entry (the kernel's fs-verity
  measure, or one read of its content) when the layer is committed, and the
  layer is recorded like a lazily pulled one, as `toc:<alg>:<digest>` with
  no diff id and its blob not checked.  The places of its chunks are those
  the verified table gives.
- The registry fetcher fails closed: its front refuses to start on a
  kernel whose Landlock cannot enforce every right of its ruleset (ABI 9),
  and its pull workers on one without ABI 9, instead of running with what
  the kernel has.  Each worker may connect only to the TCP ports of what it
  was started for (443, 80 and the ports of the registry, its mirrors and
  hints, of the proxies, and DNS; one worker per URL, lookaside signature
  or login, which connects to that port only).  `velarx-registry
  --self-test` tries the confinement of a front and of one of its workers
  from inside.  The engine has no registry route of its own any more
  (`velarx pull-worker` is gone; the workers are `velarx-registry
  pull-worker`).
- The signatures of a lookaside storage over http or https, and the
  bodies of URLs (`import` from a URL, the `ADD` of a URL, a remote build
  context), are read by the registry fetcher process (`Get` of
  `signatures` and of `url`), not by the engine.
- The registry fetcher process serves the new fetcher interface and
  `org.velarx.Registry` on one socket: the engine's pulls (manifests,
  configurations, tables of contents, files and whole layers), tags,
  search, login and push go to it; it writes only beneath the staging of
  the store's layers, which the engine hands it when it starts it.  A pull
  into a storage driver's files goes through it too: the files are staged
  for the layer, then copied to the places the driver gives and measured
  there; a layer without a table of contents is unpacked by the fetcher
  and checked by the engine in the staging.  An
  eager pull asks no content source (peers, directory caches) until they
  answer as fetchers of the list.
- A layer without a table of contents (gzip, plain, zstd) is pulled from a
  registry through the fetchers too: the registry fetcher unpacks it into
  the staging directory of the layer, file by file, with a table of
  contents and a tar-split; the engine checks each file and the diff id by
  recreating the stream from them.
- The registry fetcher is a binary of its own, `velarx-registry`, installed
  next to `velarx` like `velarx-api`: the
  engine finds it there, or where `[pull] registry_path` says, and starts it
  under the lock of its socket; its confined pull workers are
  `velarx-registry pull-worker`.  No service manager runs it: it writes
  only beneath the staging directory the engine hands it open as it starts.
- `image rm -f` of an image whose pull ends in the store while its
  containers are removed removes the image (it said nothing and left it).

### Removed

- A pull in progress is in `staging/pulls/<id>` (was
  `staging/lazy/images/<id>`), the EROFS images of its layers in
  `staging/composefs`.  `[pull] lazy_completers` is the number
  of pulls the service completes in the background at once, 0 for none (a
  pull is then completed when a command waits for it).
- The pull job (`[pull] job`, `job_idle_secs`, `job_layer_secs`, `velarx
  pull-job`): the registry fetcher is the confined process that writes the
  files of a pulled layer, into the staging directory of the layer, and the
  engine checks them.  A configuration that sets these keys is refused like
  any unknown key.

- `[pull] confine`: every pull is confined (the fetcher holds the
  credentials, confined workers fetch and decompress); a pull that cannot
  have them fails.  A configuration that sets the key is refused like any
  unknown key.  A content source no longer serves whole layers (blobs),
  which only a pull in the daemon could take.

### Changed

- The network namespace of a container is no longer pinned by a bind mount
  under the state directory (`netns/<id>`, and `netns/rootless-netns` for
  the rootless bridge networks).  The engine makes it and holds its
  descriptor while it sets the network up, the monitor of the container
  inherits one and holds it for as long as the container lives, and the
  runtime joins it as `/proc/PID/fd/N` of the monitor; the kernel destroys the namespace
  and its links with the last descriptor and process in it.  What identifies
  the namespaces is in tables of the store's database, one scope per container;
  the rootless network namespace's holder file is a record of the same tables.  The pasta
  of a container and of the rootless bridge networks is started with
  `--no-netns-quit` (it no longer opens the directory of the descriptors of
  another process, which a policy such as SELinux's can deny: the rootless
  runs failed with `netns dir open: Permission denied`) and so does not end
  by itself with the process of its namespace: the holder of the rootless
  network namespace stops its pasta when it ends, the next holder, the
  release of the namespace and the start of the engine stop one whose holder
  was killed, and the teardown of a container stops its own (after a
  `kill -9` of a monitor, the pasta and the published ports of its container
  stay until the next command that looks at the container, or `rm`).  Only the pooled namespaces
  (`io.velarx.shareableNetworkNamespace`) are still bind mounts.  A
  checkpoint of a container in a network namespace it joins names it as
  `/proc/PID/ns/net`.  Containers started by an earlier build must be stopped
  before the update.

- `ADD` extracts xz and bzip2 archives with the system programs (`xz -dc`
  and `bzip2 -dc`, found in `/usr/bin` or `/bin`) instead of libraries
  built into `velarx`, which no longer links liblzma.  The program is run
  without a shell and with an empty environment, confined (it reads below
  `/usr` and `/lib`, executes only itself, writes nothing, opens no
  connection), and its exit status, its signal or its missing installation
  are errors of the build that name the program (and the package to
  install).  gzip, zstd and plain tar archives are read as before.

- The fetchers' seccomp lists are those of what each does: the directory
  fetcher has no socket and no `accept`, the registry fetcher no `socket`,
  `bind`, `listen` or `connect` (it accepts on the listener it inherited
  when it is shared), the worker spawner no `bind`, `listen`, `accept` or
  stager call, and `velarx-kube` no `bind`, `listen`, `accept`, `linkat`,
  `unlinkat` or `memfd_create`; the fetchers read only `/proc/self` of
  `/proc`, the spawner reads what a worker reads (not the registries
  configuration or the auth files), and the fetchers and the forked helpers
  close the descriptors they were not given for their work.

- The service of the lazy images' files starts before the engine serves,
  has limits of its own (each image server keeps one idle connection), and
  its connections keep the engine service from leaving; a file a container
  misses is waited for as long as it takes (the hangup of the container's
  image server ends the wait), and a peer fetcher that restarted is
  reached again by the next fetch.

- `velarx-monitor` is a package of its own (`velarx-monitor-bin`) that
  depends on the container runtime and not on the engine's services: it
  links 542 crates instead of 619.

- The containers of lazy images ask the engine service of the store for the
  files they lack on ONE socket, `<services>/image-fetch/engine`, naming
  their image and the token of its pull in each call; a service started
  after a crash binds it again, and the containers reconnect to it.  Two
  commands that pull the same image at the same time fetch each layer once:
  an eager pull holds the lease of each layer it lacks
  (`staging/meta/<stem>/lease`) from before it plans what to fetch until the
  layer is recorded.

- The image server of a lazily pulled image no longer reaches any fetcher:
  for a file its image lacks it asks the engine that holds the pull (its
  completer, `org.velarx.ImageFetch` on `<services>/image-fetch/<image>`,
  with the token of the pull), holds the lookup until the engine staged the
  file, and measures it before use.  The misses of every container of the
  image and the background fetch meet in one fetch.  While no engine holds
  the pull a miss is `EIO` at once.  The bundle of a container no longer has
  `lazy.json`, `lazy-tocs.json` and `lazy-chunks/`; a miss no longer reads
  chunks of the store's files itself.

- `pull --lazy` and `run --lazy` of an image with a layer that cannot be
  served lazily (gzip, a table of contents without the fs-verity digest of
  every file, a registry without ranges) fail with `ImageNotLazy`, which names
  each such layer and why, before anything of the image exists; such layers
  are no longer pulled whole inside a lazy pull.

- Every interface of velarx reports version 1 in `GetInfo` (nothing is
  released yet), and the protocol of the chunks between peers is
  `/velarx/chunk/1`.

- An eager pull of a zstd:chunked layer goes through the registry fetcher:
  the table of contents comes with `Probe`, the files the store lacks with
  `Fetch` into the staging directory of the layer (`staging/layers/<stem>`,
  locked by `staging/meta/<stem>/lease`), from where the engine takes them and
  checks the layer against its diff id.  Such a pull reuses whole files of
  the store, no part of a file.

- A lazy pull takes the tables of contents of its zstd:chunked layers from
  the registry fetcher with `Probe` too; the engine no longer reads them
  from the registry ahead of the layers while the configuration is fetched.

- The files of a lazily pulled layer are staged in the one staging directory
  of the layer (`staging/layers/<stem>/files`, under its lease
  `staging/meta/<stem>/lease`, with what the pull knows of the layer in
  `staging/meta/<stem>`), not in a pool shared by every pull
  (`staging/lazy/files` and `staging/lazy/incoming` are gone): the misses of
  the containers and the completion are fetched by the engine through its
  list of fetchers (`Fetch`), a file once per engine process, and an engine
  that finds another one fetching the layer waits for its lease and asks only
  for what is not staged yet.  `system check` reports a staged file its
  layer's table does not name as `unwanted_staged_file` (was
  `unwanted_pool_file`).  A lazy file is no longer asked of the content
  sources of `[[sources]]` (only of the fetchers of `[pull] sources`).

- The calls about a repository of a registry (tags, search, login, and the
  calls of a push) are their own varlink interface, `org.velarx.Registry`,
  served on the socket of the registry fetcher beside `org.velarx.Fetcher`;
  the other fetchers no longer have them to refuse.  There are no aliases
  for the old method names.

- The downloader is now the fetcher: `velarx-registry` replaces `velarx
  downloader registry`, the interface is `org.velarx.Fetcher`, no unit runs
  it, the sockets in the services directory are
  `registry-<digest>/registry.sock` and `p2p-fetcher.sock`, the setting
  `registry_downloader_connections` is `fetcher_connections` and the logs
  of a fetcher an engine starts are `services/registry-<digest>.log`; its
  process title is `velarx-registry`.  There are no
  aliases for the old names.

- The engine service's default `--cgroups` is `split`: it splits its own
  cgroup when it starts (itself in `engine`) and puts each container in
  `[POD-ID/]CTR-ID/container` and its monitor in `[POD-ID/]CTR-ID/runtime`
  next to it, with the ids in full; the runtime and the monitor are made in
  their cgroup (`CLONE_INTO_CGROUP`), with no move to wait for. `unit` is
  gone (it was this layout, named for the unit); `scope` remains for a
  systemd scope per container, and the engine refuses to start with
  `[containers] cgroups = "split"` where it owns no cgroup. `pod create
  --cgroups=split` and the REST API take it. The containers are processes
  of the engine's unit, which now has `KillMode=control-group`: a stop or a
  `systemctl restart` of the unit (or a crash systemd restarts it after)
  stops them, a reload and `velarx system restart` keep them; with `scope`
  they outlive the unit. The `system service` subcommand of podman has no
  special error any more: it is an unknown subcommand.
- `run --rm` returns sooner: the bridge of a network and the `velarx` table of
  nftables stay when the last container of the network leaves, until the
  network is removed (`network rm`, `network prune`) or the host
  reboots, where they were deleted and made again by every run (rootless, the
  rootless network namespace still goes, with them, when no bridge in it has
  a port); the veth of a
  container whose network namespace is released is not deleted one by one, the
  kernel removes it, and the port of the bridge with it, together with the
  namespace (a network disconnected from a running container still deletes its
  interface); a container start asks firewalld for the zone of the subnet of
  its bridge and adds it to `trusted` only when it is in none (a restart or a
  reload of firewalld forgot it), where every start and stop added and
  removed it; and the `--rm` removal of a container asks the OCI runtime for
  a second `delete` (and a `features`) only when the runtime still keeps the
  container (its monitor was killed before it deleted it).
- A command opens the store without writing to it (the open set
  `auto_vacuum` again, a commit with a sync of the log, at every start), and
  the record command of a monitor, the last process of a run, writes the log
  back into the store before its close: the close of the last process holds
  the lock of the file only to remove the log, which the next command's open
  waited for, syncs included.  `run --rm` back to back without a daemon:
  42 to 37 ms with `--network none`, 78 to 58 ms with the default network.
- A rootless container no longer runs without a network when `pasta` is not
  found: pasta is required for rootless containers, and a create (a run, a
  pod, a build `RUN`, a kube play, the CRI) that would use it as the default
  network, or asks for `--network pasta`, fails with the error `NoPasta` (the
  condition of the engine's interface, the same for every frontend), which names
  the directories searched in `$PATH` and the release needed.  A pasta older
  than 2026_10_02, or one whose `--version` names no release, is refused with
  the same error, which says what it printed.  A rootless bridge network
  without pasta is refused with it too.  `--network none` and `host` need no
  pasta.
- Every commit that changes rows of the database (containers, images, layers,
  manifests, volumes, networks) now tells the other processes once it is
  published, and the store service that announces images and layers to peers
  waits on that signal instead of watching the files of the database and
  taking its write lock to wait for a writer.
- `images`, `image inspect`, `system df` and the pull of an image the store
  already has no longer cost more the bigger the image is: the size of the
  uncompressed tar of a layer is recorded when the layer is pulled, instead
  of being worked out again from its tar-split and table of contents by each
  command (a store made by an earlier build is not used: remove it).  A pull of an
  image the store has writes nothing and prints the id the pull answered with
  without inspecting the image, and `ps` and `container inspect` ask the OCI
  runtime only for a container that is recorded as running or paused, and once.
- The P2P service refuses what it used to skip or run without: a listen
  or bootstrap address that is no multiaddress (the QUIC endpoint bound every
  interface when none was left), an overlay that cannot start, announce itself
  or register a container, and the forwarding the helper cannot enable.  A
  failed query of the DHT answers the caller with an error at once.  The peers
  file, the DNS query messages and the container addresses of the overlay
  announcement, which nothing used, are gone; the subnet and the addresses of
  the gossip are typed.  `org.velarx.P2p` no longer reports the DHT mode, the
  routing table size and the counters nothing counted (`Stats` is the chunks
  sent).  A peer that disconnected is no longer listed again by an answer sent
  to it, and a startup profile from a peer is one the file system reads.  The
  chunk protocol has no ranges of a chunk any more (no node asked for one).
- A layer that is pulled whole (gzip, zstd without a table of contents,
  a tar) no longer writes the files the store has: the fs-verity digest of
  each file is measured in the pass that hashes it, and a file whose object
  the store holds is dropped as it is read (a small one is never written) and
  counted as reused, not fetched, in the report of the pull.  A second pull of
  such a layer, or a pull of one that shares files with a stored layer, stages
  nothing the store has.
- What a pull stages waits in its session under names that are no digest
  (`staging/pull-*/tmp-N`): a file gets the name of its fs-verity digest in the
  store only when the commit has measured it, after fs-verity is enabled, so
  a name in the objects is always a file with the digest it is named by.
- What an OCI runtime has is read from its `features` (the runtime-spec
  document), once for each runtime file, not from its `--help` or its file
  name.  crun's own options (the global `--cgroup-manager`,
  `create --config`, `create --no-new-keyring` and the `run.oci.*`
  annotations) are there when the runtime allows the prefix `run.oci.` in
  `potentiallyUnsafeConfigAnnotations`: crun and krun do, runc does not.  A
  runtime whose `features` fail, print nothing or no JSON has none of them.
  So runc is refused for `--cgroups=disabled`, `[containers] keyring =
  false`, `--group-add keep-groups` and `--security-opt seccomp-bpf` (with a
  message that says so; it ignored the last two), gives the RUN steps of a
  rootless build a keyring of their own, and reads the spec of the bundle
  instead of `create --config`; a copy or a wrapper of crun under another
  name gets the options.
- A push that fails the TLS verification of the registry is told from the
  type of the failure, not from the text of any message, and the registry
  of Docker Hub has no token endpoint of its own in the program: the first
  request of a pull learns it from the 401, as for every registry.
- The inspect of a container, `generate kube` and the list of networks of
  the REST API fail with the error when the network setup of a container or
  a network record in the database cannot be read, where they listed the
  container without ports and left the network out.
- A command with no engine service serves the engine service from its own
  process and asks it through the same client as when a service runs, `run`
  and `start` included: there is one path for the commands, with or without a
  service. That service takes a socket pair for each connection, no socket a
  name leads to: no other process can connect to it (an abstract socket could
  be reached by any process of the network namespace, a container of the host
  network included), and nothing is left in `/tmp` by a command that is
  killed. A command a signal
  ends cleans up and exits with 128 plus the signal number.

### Added

- `velarx pull --sources NAME,...`: the fetchers of one pull, in the order
  they are asked, in place of `[pull] sources`.  The engine asks each fetcher
  in turn for what the ones before it did not bring; the registry fetcher is
  the last.

- The image server that serves the layers a container's file system reads keeps
  a log, `image-server.log` in the bundle directory of the container (at most
  1 MiB, emptied first when it would grow over that, so the latest lines are
  kept; mode 0600): the line that names a file the FUSE file system refused at
  an open (`verity chain: BROKEN fuse object ...`, with `--log-level=debug` and
  enforced digests) is there again.
- `--lazy` works with a storage service (`[storage] driver = "varlink"`): the
  engine stages the image and runs its containers from its own files while
  the pull goes on, and when the files are all there pulls the layers into the
  service, which checks them like any pull (the engine copies each file into
  the place the service gave, measures it, and reads every layer back to
  prove it).  An image with a layer that is not a zstd:chunked layer with the
  fs-verity digest of every file is refused before anything is staged, naming
  the layer: pull it without `--lazy`.
- `[pull] job = true` works with a storage service (`[storage] driver =
  "varlink"`): a confined pull job for each fetch of the service writes the
  layer into the files the service passed, and the engine ends it and reads
  each object back before the service is told anything.
- A storage service that says it holds objects (`objects` in its capabilities)
  is asked which of the objects the chunks of its earlier layers are in it still
  has (`HasObjects`), and copies them itself (the `copy` events of a fetch)
  instead of the engine fetching them again; the reference server does.
- `velarx image pulls` lists the lazy pulls in progress (id, names, state,
  progress, the containers made on each, the error of one that stopped) and
  `--cancel ID` cancels one.  `[pull] lazy_complete_fetches` (4),
  `lazy_completers` (2) and `lazy_retry_max_secs` (600) are the settings of
  the background completion of a lazy pull.  `system df -v` counts the pulls
  in progress and the bytes they have staged (`Pulling`, in the store's
  usage), and `velarx-pulls.service` (a system and a user unit) resumes them
  at boot with no command.

- Images whose digests are sha512 are read, checked and shown: every digest
  of an image is one type that carries its algorithm (`sha256:` and 64 hex
  digits, or `sha512:` and 128), and is checked with its own algorithm: the
  manifest, the index and its entries, the configuration, the diff ids, the
  blobs, the table of contents of a zstd:chunked layer and its tar-split, the
  blobs of an OCI layout or archive (`blobs/sha512/HEX`), a typed
  `NAME@sha512:D`, `NAME:TAG@sha512:D` (the tag locates the manifest on a
  registry that addresses its manifests by sha256 only; `D` checks the bytes)
  and `--verify-image sha512:D`.  The chain of trust of a start checks every
  link with the algorithm of the digest that names it, and the debug log
  names it.  The id of an image is the hex of its manifest digest: 128 digits
  for a sha512; an image pulled by a tag is named in the algorithm of its
  configuration, whatever the registry addresses it by.  An image whose layers are sha512 pulls, is stored, runs (the
  kernel's overlay, or FUSE rootless), is verified (`--verify-image sha512:D`,
  `verity=require`), removed, collected and seen by `system check`: one store
  holds the sha256 and the sha512 objects of fs-verity (names of 62 and 126
  digits, `fsverity-sha256-12:` and `fsverity-sha512-12:` in the database),
  two unrelated sets even for the same content.  A mixed image (sha256
  layers under a sha512 manifest, or the reverse) has no merged-tree
  annotation, and a manifest that states one its layers cannot check is
  refused by name.  A layer shared by a sha256 and a sha512 image (the same
  blob) is one layer with a diff id of each.  The fs-verity hash is the one of the image's digests: a store
  whose file system cannot do SHA-512 fs-verity refuses the pull by name.
  The peers serve both kinds (`velarx-chunks/4`).  The EROFS images are `v4`
  files.  `docs/STORAGE.md` has the rules.
- `--digest sha256|sha512` on `build`, `commit`, `import`, `manifest create`
  and `artifact add`, and `[build] digest` in the configuration (`sha256`
  by default; the flag wins; pulls are never affected), make an image whose
  every digest is of that algorithm: the layers (blob, diff id, chunks, files,
  table of contents), the configuration, the manifest, the annotations, the
  fs-verity names of the objects, and an image id of 128 digits for sha512.
  `commit` follows the algorithm of the image of its container.  A sha512
  build on a sha256 base is a mixed image: the base's layers and diff ids stay
  sha256, each link is checked with its own algorithm, and no merged-tree
  annotation is written.  A store whose fs-verity lacks SHA-512 refuses
  `--digest sha512` by name before it makes anything.  `push` to a registry
  of an image with sha512 digests warns once on standard error that a
  registry may refuse it (and never rewrites it to sha256), and a manifest
  list of sha512 images pushed to a registry that takes no manifest by its
  sha512 digest (registry:3; zot takes it) fails by name.
  Any other word than `sha256` and `sha512` is refused by name.

- `--log-level=debug` shows the chain of trust of a start that enforces the
  fs-verity digests as a chain of digests, one `verity chain:` line per link
  where the code checks it, with the digest that vouches and the one it
  vouches for (`D manifest -> C config`, `D manifest -> L layer 1 blob -> E
  annotation`, `layer 1 annotation E == erofs fd E`, `erofs fd ... -> overlay
  verity=require`), from the root (`root typed D`, or the weaker `RECORDED`
  and `NONE`) to the fs-verity digest measured on the EROFS image of each
  layer; it ends with `COMPLETE` and the digests, or `BROKEN <link> expected
  X found Y` at the link that did not hold.  `tests/e2e/verity_chain.py`
  checks that the digests of such a log connect.  Nothing changes at the
  other levels.  A layer image that fails its check is no longer tried again
  through the FUSE file system, which would check it the same way.

- `velarx image generate-sigstore-key --output-prefix PREFIX
  [--passphrase-file FILE]` writes a sigstore key pair, `PREFIX.private`
  (encrypted, mode 0600) and `PREFIX.pub`, in the format of cosign and
  `skopeo generate-sigstore-key`, so signing images needs no other tool.  It
  runs in the command, with no engine, asks for the passphrase twice without
  echo when no file gives it, and replaces no file.
  `docs/SIGNING.md` is a walk through signing and verifying images with it.

- An image named by its digest (`NAME@sha256:D`, a manifest or an index) is the
  root of a chain of trust at every start that enforces the digests
  (`--security-opt verity=enforce`, `[storage] composefs_digests =
  "require"`): the stored manifest (or the index that lists it), the
  configuration blob, the layers' EROFS digests and the settings of the
  container taken from the configuration are hashed back to the digest the
  user typed on the command, never to a row of the store.  `run` takes it
  from the image reference, `start`, `restart`, `container restore`,
  `container clone --run`, `pod start` and `pod restart` take
  `--verify-image sha256:D` (and their REST calls `verify_image`), `kube
  play` the digests of the image references of its YAML; a container
  made from a digest is refused by an enforced start that gives none, and
  `--verify-image` is refused when it cannot be honoured (not a sha256
  digest, a container whose digests are not enforced, a digest no image of
  the container was made from).  The start at boot
  (`velarx-restart.service`) runs `container start --service`, which goes by
  the digest recorded in the container; a unit that `SystemdGenerate` (the
  REST `generate/{name}/systemd`) writes for an enforced container made from
  a digest gives `--verify-image`.  An image whose layers do not all state
  their EROFS digest is refused whenever the digests are enforced, by the
  create of the container and again by every start, naming the layer and
  the option; a Docker create of an image named by a digest whose digests
  are enforced is refused, since a Docker client cannot give the digest at
  the start.

- Every manifest Velarx writes (commit, build, import, a push that rebuilds
  the manifest) states, on each layer descriptor, the fs-verity digest of
  the EROFS image of the layer in the annotation `io.containers.composefs.digest` (a comma separated list of
  `sha256:<hex>` values).  A pull or a load, eager or lazy, fails when a
  stated digest is not that of the image Velarx makes of the layer;
  `system check` compares them too, and `image inspect` shows them in a
  `Composefs` section.  `[storage] composefs_digests = "require"` also
  refuses an image whose layers state none.
- Every start of a container by the engine checks the stored manifest of
  its image against the id of the image and hands the monitor the
  fs-verity digests of the layers from that manifest (in the monitor's own
  configuration, not the bundle): the monitor refuses a layer image that
  measures differently.  `--security-opt verity=enforce` and `[storage]
  composefs_digests = "require"` make this strict: every layer must state a
  digest, a layer image without fs-verity is an error, and the overlay has
  `verity=require`.  The REST API takes `verity_enforce` and the `SecurityOpt`
  string.

### Changed

- The minimum `pasta` is its latest release, 2026_10_02.  Velarx no longer
  asks `pasta --help` whether it has `--map-guest-addr` (the
  `pasta-map-guest-addr` feature marker is gone) and no longer gives an older
  pasta the gateway of the host as `host.containers.internal`.  The network
  rules of a container and of a network are removed with the nftables
  `destroy` messages, which the minimum kernel has.
- The destinations of the bind mounts are no longer rewritten through the links
  of the root of the container when the container is made: the runtime gets
  them as given and resolves them at every start.  A container that replaces
  such a link (`rm /etc; mkdir /etc` in an image with `/etc -> /var/etc`) gets
  the bind mounts in the new directory again after a restart.  Its checkpoint
  works only with a runtime that tells CRIU where the mounts are.
- A lazy image pulled with a storage service no longer takes its files twice
  for good: the engine drops its copy of them (the objects and the EROFS images
  of the layers) when the pull is complete and no container made on the pull
  exists, or when the last such container is removed; a collection finishes
  what was interrupted.  A layer that one completion released from the staging
  area and the service lost is staged again from the engine's copy by the
  completion of a second pull that shares it, instead of failing.
- The root file system and the image mounts of a container are always mounts
  the storage driver makes and the monitor attaches: the monitor serves no FUSE
  file system, opens no image of the store and reads no digest of the bundle.
  Where the kernel does not mount the layers (rootless, `squash`,
  `composefs = "off"`, a lazy image, a kernel mount that failed) the image
  server (`velarx-monitor --image-server`) does, and a server that cannot start
  is a start error that says why.  Whether the kernel mounts an EROFS image from
  a file (Linux 6.12 or later, on a file system it can read the image through)
  is found out when the engine starts and kept for the boot (the marker
  `erofs-file-yes` or `erofs-file-no` in the `features` directory of the run
  root): a host that cannot has every root file system made by the image server,
  with no failed kernel mount at each start, and the log says why.
- A container made by an engine before this change (its bundle has a `composefs`
  plan in `rootfs.json`) does not start: the file is invalid, and the container
  is removed and created again.  Nothing reads or migrates it.
- A container whose image has lost the EROFS image of a layer (composefs)
  does not start and says `the image X is damaged (layer Y has no EROFS
  image): pull it again`.  The layer is marked incomplete: `velarx pull` of the
  image fetches it again, with no download of the files the store has, and
  makes the image; `velarx system check --repair` still makes it from the
  table of contents.  A layer made locally (commit, build, load) is not
  marked: its error names the repair.
- The schema version of the database goes back to 1 and stays there until a
  release starts versioning: a change of the schema edits it in place, so a
  store made by an older build is unusable (it fails at the first statement
  that needs the new shape): delete it.  A store of the earlier versions 2 to 4
  is refused with its version.  Remove that store.
- The schema of the database is raised to version 2 (shared layers of sha256 and
  sha512 objects).  A store made by an earlier build is refused with a message
  naming its version, instead of failing later with a database error: remove
  that store (or use the velarx that made it).  The database of the rootless
  namespaces in the run root (`userns.sqlite`) has a schema version of its
  own too, and the tables of the secrets are made with the store.
- A lazy pull is a pull in progress until it is complete, and the store holds
  only complete layers and images.  What a lazy pull has before that (the
  tables of contents, the files fetched so far) is in `staging/lazy` on the
  file system of the store, and nothing of it is in the database: `images`
  does not list it, `velarx image pulls` does, and a command that wants an
  image says the name is being pulled.  The files are fetched into a pool
  there, sealed with fs-verity before they have their name; when a layer has
  all its files they are written to the disk if `[storage] sync` says (one
  `syncfs`, only for these files, never for the database), linked into the
  store, and one transaction records the layer (a layer without a table of
  contents is replayed against the diff id of the configuration first); the image is recorded with its last
  layer.  A crash in the middle of a download leaves no partial layer in the
  store, and the pool and the tables are resumed.  Two images that share a
  layer commit it once.  `run --lazy` attaches to the pull; `run` without
  `--lazy` completes it first, as fast as it goes, and runs from the store;
  `pull` of the same image joins it, and `rmi` cancels it.  The database
  schema changed (version 3: `images.is_lazy`, `layers.status`, `layers.reuse`
  and the reach columns are gone, a layer has its diff id, a container's image
  has no foreign key): remove the store.
- A lazy pull goes on after the command that made it: the engine service of
  the store (`velarx varlink`, which a command that has no engine service
  finds on the engine's socket or starts there) fetches the files nobody
  reads and commits the layers and the image on a task of its own.  It does not give up: a failure that may pass is retried
  with a backoff, and one that cannot be mended stops it with the staging kept
  and the reason in `velarx image pulls` (`velarx image complete` starts it
  again, with credentials if the registry wants them).  A pull that has no
  process (a reboot, a kill) is resumed by any command of the store (with or
  without a daemon), and by the daemon at start and at every collection
  interval.  The credentials of the command are kept in memory only: a
  completer started again after a kill waits for them (`needs-credentials`).
  A queued completer takes the first slot that is free.  A lazy pull refuses a
  staging area that is not on the file system of the store, and a pooled file
  that is not what its name says is removed and fetched again.  A lazy fetch holds the
  store lock only while its files get their names in the pool, not through
  the download (a `system prune` no longer waits for a whole completion), and
  a cancelled pull takes the files of the pool that no other pull wants with
  it.  `velarx
  lazy-commit` and the monitor's background fetch are gone; a container's
  monitor fetches what the container reads, and no longer records anything.

- In a user namespace the overlay of an image of several layers is mounted
  with `redirect_dir=followdata` where the kernel has that option (proposed
  for the kernel, not in a released one yet), so that it follows the stub of
  every layer into the data-only layer.  On a kernel without it the files of
  the layers above the lowest are served by FUSE, as before.  Images of one
  layer and mounts as root do not use it.
- What Velarx finds the kernel and its tools can do is kept in the run root
  (`--runroot`), in `features/`, as one marker file per feature named
  `<feature>-yes` or `<feature>-no`; no file means not probed yet, and a new
  boot forgets them.  The answer about the stubs of the overlay is
  `features/overlay-datadir-every-layer-yes` or `-no` (was
  `overlay-stubs-every-layer` / `overlay-stubs-lowest-layer`), and what
  `pasta` can do (`--map-host-loopback`) is
  `features/pasta-map-host-loopback-yes` or `-no`, no longer
  `velarx-pasta-features` next to the run root in `$XDG_RUNTIME_DIR` or
  `/run`, which ignored `--runroot`.  The files of the old names are neither
  read nor removed: delete `features/` of the run root to probe again.
- A velarx command without a daemon leaves its store closed: its `-wal` and
  `-shm` files are gone when it ends (also when it fails or a signal ends
  it), as they are when a daemon stops, unless another process still has the
  store open.  A store filled by `velarx pull` can be an additional image
  store of other users, which refuse a store that has a log.  A process that
  is killed still leaves its log, which the next open recovers.  A
  container run with `--rm` leaves the store to its cleanup process, which
  closes it shortly after the command returns.  The user and mount
  namespaces of a rootless user are recorded in `userns.sqlite` in the run
  root (a tmpfs) instead of the store's database, so that a command that
  only reads the store (`velarx images`) writes nothing to it and has
  nothing to write back when it ends.

- A layer is stored under what verified it, so that a zstd:chunked layer has
  one view: a layer whose descriptor has the zstd:chunked labels
  (`manifest-checksum` and `manifest-position`) is pulled through its table
  of contents and stored by its TOC digest (`toc:sha256:...`), a layer pulled
  whole by its blob digest, and neither stands for the other in any lookup
  (a later pull, a load, the parent of a commit, the peers).  When the TOC
  cannot be used (the registry serves no ranges, the descriptor has no
  tar-split) the layer is pulled whole and is a layer of its blob; a TOC
  that is not the bytes its checksum names, a tar-split that is not the
  TOC's, or a TOC whose files are not the configuration's diff id now fail
  the pull instead of pulling the blob whole.  Whether a layer is chunked is
  read from the descriptor only, never from the blob.  The diff id of a
  layer is recorded only once the layer was verified against it: a lazily
  pulled layer has none until its completion.  The EROFS image of a layer of
  a TOC is `composefs/layer-toc-<alg>-<hex>.v4.erofs`, the layers that the store
  service and the peers name are their keys, and `system check` reports a
  layer that is not the one of its descriptor, or says a diff id it does
  not have the proof of, as `layer_identity_mismatch`.  The database schema
  changed: remove the store.
- The fetcher of lazily pulled images is the engine's, and one
  for all the containers: the daemon, or a command without one (`run`,
  `pull`), starts it, the monitors of the containers with lazy layers are
  given an open connection to it, and no monitor starts a
  fetcher of its own any more (a container used to have one each).  It
  is kept by its open connections and leaves as soon as the last one is
  closed, so it outlives a command whose containers still run, and a daemon
  keeps none while it pulls nothing and runs no container with lazy layers;
  a monitor's connection counts as a client of its own against
  `[services] max_per_client`, not against the engine; the commands
  of the same user with the same configuration, environment and binary
  share it (its socket in the services directory is named by a digest of
  them), others never reach it.  A fetcher that dies fails the reads of
  the containers that used it with EIO at once, and the next command starts
  another one.  `[pull] fetcher_connections` (1024) is the most
  connections it serves; what it says goes to
  `services/registry-<digest>.log`.  `run --no-monitor` gets the
  fetchers of its image too.

- A registry that answers the ranges of a zstd:chunked layer with other
  bytes than the TOC of its descriptor says (a chunk that does not
  decompress, or is not its digest, a file that is not its digest, a
  tar-split that is not the TOC's, with `[pull] job` too) fails the pull,
  as podman does, instead of the layer being pulled whole; a registry that
  refuses the ranges, answers them short or without the range it sent still
  makes the layer pulled whole.  A `manifest-position` of another kind of
  manifest than a TOC makes the layer a layer of its blob.  One TOC named by
  two blobs is one layer whose lazy fetches ask the registry of its last
  pull for the blob of that pull, and neither image is reported by `system
  check`; a manifest that names one TOC with two blobs, whose TOC cannot be
  used, gets the layer of each blob.  A gzip layer made of the peers' index
  and its files, whose blob was never hashed, gives way to the layer of
  that blob pulled whole when another image names the blob with another
  diff id, instead of failing that pull.

- A pull never goes without its
  fetcher: when the engine cannot start one (a `services/`
  directory that others can enter or that cannot be made, a socket that
  cannot be bound) the pull fails with an error that names the cause.
  Before, it went on in the process that pulled, with the credentials
  there, and said so only at the debug level.  An engine that cannot give a container
  one warns with the cause (its monitor asks its other fetchers only).
- What else could not be confined fails instead of going on with less: the
  threads of the monitor that read what others send (the FUSE sessions, the
  conversations with the fetchers) and the DNS server of the networks do
  not run on a kernel without Landlock (the pull workers already did not);
  the DNS worker of a root engine that cannot become `nobody`, and a build
  worker that cannot drop its capabilities from the bounding or the ambient
  set, stop with an error.  The workers that download the URLs of `ADD`,
  `import` and `load` have the cgroup and the limits of the pull workers,
  and `[pull] require_cgroup` fails them as it fails a pull.

- A rootless `--security-opt verity=enforce` start of an image of several
  layers works on kernels whose overlay follows the stubs of the lowest layer
  only in a user namespace: the FUSE file system does for the files of the
  layers above what the kernel does with `verity=require`.  It opens the
  object of the file once, below the store and without symlinks, as a
  regular file, measures its fs-verity on that open file, compares it with
  the digest of the stub in the verified EROFS image and serves the reads
  from that same file; a copy without fs-verity, another content, a
  symlink, a FIFO, a directory or a missing object is an I/O error for that
  file, and a file opened before the object was replaced keeps the content
  that was measured.  The debug log of the start says which of the overlay
  and the FUSE file system checks which layers.  The start used to be
  refused.  The digest of the merged tree in the manifest is still made and
  published, and checked at a pull and by `system check`, but a start does
  not use it: it verifies the layers one by one.

- `rm -f` of a running container (and `pod rm -f`, `image rm -f` of one in
  use, the REST API's forced removals) stops it as podman does: with its
  stop signal (SIGTERM by default), waits its stop timeout (10 s by
  default, `--stop-timeout`) or the `-t` given, and only then sends
  SIGKILL, saying so on the standard error (`WARN StopSignal SIGTERM failed
  to stop container X in 10 seconds, resorting to SIGKILL`).  `-t 0` kills
  at once without a signal, a negative `-t` waits as long as it takes, and
  a paused container is killed at once.  It used to kill at once.  `volume
  rm -f` and `network rm -f`, which already stopped the containers so, tell
  the kill too.  The libpod `DELETE /containers/{id}` and `DELETE
  /pods/{id}` use the stop timeout of the container when `timeout` is not
  given (the pod's used none), and Docker's `DELETE
  /containers/{id}?force=1` uses it too (and still ignores `timeout`).  The
  containers of a pod stop together.  A container that others depend on is
  no longer stopped when its forced removal is refused for them.  The CRI's
  removal is not changed: the kubelet stops containers itself.  Containers
  that ignore SIGTERM, as a `sleep` that is the first process of a
  container does, now take the stop timeout to be removed: `-t 0` removes
  them at once.  `rm` without `-f` of a paused container says it is paused
  (it said running), as podman.

- `--security-opt signature=check` refuses an image without a name (built or
  imported untagged, never pulled, asked for by its id), at the create and at
  every start by the engine, as podman's `composefs-verity` branch does
  ("image has no names"); it used to run it.  A container made without the
  option is not affected, and a named image is judged as before.  The
  message of `require` for such an image reads the same.

- `--security-opt signature=require` and `[containers] image_signature =
  "require"` judge the names an image was pulled by as well as its tags, as
  `check` does: an image pulled by its digest only (or untagged after its
  pull) and asked for by its id is judged by that name instead of refused
  as having none, and a name it was pulled by that the policy no longer
  accepts refuses it, as under `check`.

- `ps --external` and `ps --sync` (also `container ls`) and the parameter
  `external` of the libpod container list are refused by name instead of
  ignored: the store has no containers of other tools and the state is
  always read from the runtime (the list takes `sync`, which podman's remote
  client sends for the containers it acts on).  `network connect` and
  `network disconnect` of a network of the `host`, `none` or `overlay`
  driver are refused with an error naming the driver, where they answered
  success and did nothing.

- The overlay of the root file system of a `--rm` container and of the
  container of a build step is mounted `volatile`, as podman and buildah
  do: its writes are not synced to disk (300 `fsync`ed writes of 256 KiB
  in a `--rm` container took 0.26 s instead of 1.85 s).  A crash of the
  machine loses what such a container wrote, and the container is removed
  at the next start of the engine.

- `--rm` containers behave as podman's.  `restart` (and `restart --all`,
  `pod restart`) keeps a `--rm` container: it stopped and was removed, and
  the start failed.  `pod stop` leaves its `--rm` members stopped (`pod
  start` starts them again); `stop` of a `--rm` container that does not run
  (created, or left by `pod stop`) removes it, and so does `stop --all`.  A
  `--rm` container that other containers depend on (`--requires`) is not
  removed as it exits, and its `stop` fails with podman's error.
  `--rm --restart on-failure` restarts the container on a failure and
  removes it when it ends for good; it was never restarted.  `checkpoint` of
  a `--rm` container needs `--export` and removes the container once it is
  exported (it was refused without `--leave-running`, and `--export` alone
  was refused); `restore --import` of its archive makes a `--rm` container
  again.  `checkpoint` and `restore` of several containers say an error
  once, without the name of the container before it.

- `--security-opt signature=check` is kept in the container, as podman's
  `composefs-verity` branch keeps it, and judges the whole signature policy
  again at every start by the engine (start, restart, restore, pod start; a
  restart by the monitor's own restart policy checks nothing): a signature
  rule must be satisfied by a signature stored with the image, a `reject`
  rule refuses, and an image the policy accepts without a signature runs.  A
  key dropped from the policy, or a `reject` rule added for the repository,
  stops the next start of such a container.  A container made without the
  flag is judged at its create only, as before.  `signature=require` and the
  node's `image_signature = "require"` honour `reject` too: a scope with
  `reject` is refused with a message that says the policy rejects the image
  and names the scope (it said that the policy accepts it without a
  signature).  A container made without the flag is judged by the signature
  rules only, as podman runs the images of its store: `reject` refuses its
  pulls, not its create.

- The list in the annotation `io.containers.composefs.digest` is read as
  podman's `composefs-verity` branch reads it: only its `sha256:<64 hex
  digits>` values count, and an empty entry, an entry of another algorithm
  and any other string are ignored, where they failed every pull.  A layer
  whose list has none of the digests of the EROFS image Velarx makes of it
  (an image annotated by podman only, or an annotation that was edited:
  nothing tells them apart) is accepted at the pull and at the start with
  the default `composefs_digests = "check"`, and held against its own record
  like a layer without the annotation.  It is refused, with the layer named,
  where the digests are required: `composefs_digests = "require"`,
  `--security-opt verity=enforce` and `--verify-image`.  A list that has
  Velarx's digest is checked as before.  With the default a pull no longer
  finds an edited digest, and a start no longer refuses a layer whose record
  is none of the digests its manifest states (an EROFS image and its record
  replaced together in the store); the enforced start and `require` do.

### Removed

- The `composefs` kind of the plan of the root file system (`rootfs.json`) and
  the monitor's own mounts of it (its FUSE file system, its checks of the paths
  of the store): the bundle holds the place of a mount descriptor or a directory.

- `images --format '{{.Lazy}}'`, the `Lazy` field of the images of the REST API
  and the staging directory of each container (`<bundle>/staging`): the files
  of a lazy pull go to the pool of the store.

- `[pull] registry_downloader_idle_secs` is gone (the key is unknown now):
  the fetcher an engine starts leaves when its last connection
  closes, not after an idle time; one a service manager holds keeps its
  `--idle-exit`.  `velarx-registry` takes `--shared PATH` and no
  longer `--keep-socket` or `--lifeline-fd`.

- The disk budget of a pull: `[pull] max_pull_gib`, `min_free_mib` and
  `min_free_inodes` are gone (the keys are unknown now).  The disk a pull,
  a load or an import may use is left to the file system and its quotas;
  a write that finds no space fails with the error of the file system and
  what the pull wrote is removed.

- Anything for cgroup v1: the engine (service or in-process), the engine of a
  command and the monitor refuse to start, with one error, when
  `/sys/fs/cgroup` is not a cgroup2 mount (cgroup v1, the hybrid layout).
  `--memory-swappiness`, `--cpu-rt-period` and `--cpu-rt-runtime` of `run`,
  `create`, `update` and `clone` are unknown flags; the REST API refuses a
  swappiness of 0 or more and non-zero real-time CPU values (501 on create,
  400 on update) and still takes the unset values clients send.

### Fixed

- A lazy pull refuses a table of contents that lists a file with another
  size than the store has recorded for its fs-verity digest, or than
  another layer of the image gives it, naming the layer; the image was
  pulled as verified, and `system check` called the store damaged.
- A pull fetches a file of the store again when the object has another
  size than the table of contents gives or, in a store that keeps
  fs-verity, has none (damaged, or replaced by another file), and puts it
  back, so that "pull it again" repairs the image.  The object was taken
  for held by its name, and the layer could not be made from it (the
  merged EROFS failed on every pull).  Only the length of an object
  without fs-verity is looked at: other bytes of the same length are not
  noticed.
- `container commit` keeps the root directory of the container (its mode,
  owner, time and extended attributes) in the image: the layer has the
  entry `./`, as does the layer of every build step (`COPY`, `ADD`, `VOLUME`
  and `WORKDIR` too) over a root that is not a plain directory (mode 0755,
  owned by root, no attributes), on every storage driver and for `build
  --squash`.  The root of the image was a plain directory.
- The EROFS image of a layer whose entry `./` is a hard link is an error;
  making it panicked.
- The files of a pulled layer keep the nanoseconds of their modification
  time (a PAX `mtime` record of a fraction of a second, or before 1970); they
  had whole seconds.  A time before 1970 is kept as far as the table of
  contents holds it (the years 0001 to 9999); the EROFS images of the layers
  are made again in the new format version 5.  A file of a build context
  dated before 1970 has the epoch in the layer it goes to.
- The root directory of a pulled layer has the mode, owner, time and
  extended attributes of the layer's entry `./`, as an extraction gives it;
  it was always a plain directory of mode 0755.  The root directory of a
  container has those of its image's top layer (a plain directory of mode
  0755 owned by root when the layer has no `./`), with the owner its user
  namespace maps, on every storage driver, also with a read-only root.
- A pull whose peers do not answer (a member whose store hangs) or are slow
  from the first byte goes on from the registry within seconds: a request
  waits for a stream to the peer no longer than the idle time (it waited for
  minutes), a group is left to the registry when the peers gave less than
  1 MiB/s since it began (counted as the bytes come), and the peers it still
  waited for are not asked by the groups after it for a minute.
- `restore --import` keeps the log driver and the log options of the
  archive's container, as podman's (not its log path: the file is the new
  container's); it took the default driver.
- The files of an `--rm` container whose row a crash of the machine lost
  (its bundle with the upper layer, its logs, its secrets, the record the API
  kept, and the anonymous volumes its create made, unless another container
  mounts them) are removed: the first command of a boot (an engine of its own
  process, no service needed) does it once, and the engine service does it
  when it starts, under the exclusive lock of the store, taken only when no
  other process holds it, so that a container being made is never taken.  An
  anonymous volume that `rm` without `-v` kept stays.  The service used to
  remove only bundles, without the lock, and a command never did.  A command
  of the same boot costs nothing more.
- The secrets a create resolves before the container is made (`--secret`, the
  `secrets` of the API) are made under the lock of the store, as the rest of
  the create.
- The dials of the providers a lookup of the DHT names are counted where they
  are made (`dials` of the peer-to-peer status missed the one that connected
  before the asker looked).
- A peer-to-peer node with no room to answer is no longer taken for one that
  does not have the chunk: a busy answer (to a probe or to a chunk request,
  over libp2p or QUIC) is neither remembered as "has none" for a minute nor counted as a failure
  of the peer; the next peer is asked, and the busy one again when a chunk
  came in or by the next group.  A QUIC request that finds no serving slot
  in 15 seconds is answered busy, it timed out after 30 and the asker left
  QUIC to that peer for minutes.  `velarx p2p status` shows the busy requests
  of each peer and, new, how the probes, the DHT lookups and the dials came
  out.
- The chunks a peer sent no longer fill the table of the layers it
  announced (about 10 MiB for a peer after one big pull, and a later layer
  announcement was dropped once it was full); that table keeps layers only,
  and drops the oldest of a peer that announced more than 50 000.
- A layer that one peer-to-peer node announces is found by the nodes that are
  not connected to it: the providers the DHT names are dialed (at most three
  for a lookup, within the connection limits) and asked for the chunks by the
  same group of the pull, they were dropped unless already connected.  The DHT now has the TCP address of
  the provider, not only its QUIC endpoint.
- Removing an image of many layers, `system gc` and the release of the copy
  the engine keeps of a lazy image hold the lock of at most 256 layer images
  at a time, all through one shared helper: the release of the copy of more
  layers than the limit of open files failed with `Too many open files`.
- An `--rm` container whose monitor is killed (`kill -9`) after the exit was
  recorded and before the removal was done is removed by the next command that
  opens the store (a listing, a `run` with the same name), with no engine
  service running, and by a running engine service that follows its monitor
  (REST and CRI clients): it stayed `Exited` until a service started.  The
  `--rmi` image of such a container goes in the same transaction as its row,
  so a kill between the two no longer loses it, and a container that is
  removed while another process had already removed its row is not an error.

- `logs --follow` of a running container with the journald driver over the
  REST API (`podman-remote`, Docker clients) follows the journal itself:
  every line once and in the journal's order, up to the end of the container;
  it read the journal once and then the output of the monitor, so a line
  written between the two came twice, and a container that was restarted or
  removed was not followed.

- `logs` of a container with the journald driver has every line it wrote,
  also right after it ended: the journal is synchronized (`journalctl
  --sync`) before it is read, as it takes in what a monitor sends on its own
  time, so `run` then `logs` could show nothing.  One reader of the journal
  serves the command line, the REST API and the logs of a pod; a line written
  in parts across the end of a follow came with its first part twice, and a
  REST client that went away left `journalctl` running until the container
  ended.  Without `journalctl` the journald driver's logs are refused as not
  supported.

- `velarx build` without an engine service (the command's own engine),
  interrupted with Ctrl-C or a TERM while a RUN step runs, stops the step and
  removes its container before it exits, as the engine service does when it
  ends: the RUN process and its container were left running.
- The file of an artifact added to a manifest list is copied into the list
  as it is hashed, and the copy is given the name of its digest after: it
  was hashed in one read and copied (or renamed, taking the file from the
  caller) in another, under the name of its digest, so a file the caller
  changed in between, or a copy cut short, had a name that was not its
  digest.
- A network whose stored options, DNS servers, IP range or routes cannot be
  read is an error wherever it is used; it was read as the defaults (an
  `internal` network lost `internal`, its DNS server came back), skipped by
  `network create` when it checked the subnets and names in use, and leaked
  its bridge and rules on `network rm`.  `network rm` refuses such a network
  and says that `network rm --force` removes it: then its bridge is found by
  the mark Velarx gives it and taken down with what the bridge itself says of
  its subnets.  A default network whose gateway in the configuration is not
  an address is an error, not the first address of the subnet.
- A container whose stored network setup cannot be read fails to start with
  that error instead of starting without a network, and a network of the
  container that cannot be read is an error instead of being left out with a
  warning.  Its stop still stops pasta and the port forwarder and releases
  its network namespace.
- Removing a container whose published host port another container took
  meanwhile removes its other ports: the removal was retried without any
  port, and they stayed in the rules.  Only the rules that are the
  container's go.
- The DNS server of the bridge networks says why it does not serve a network
  (port 53 of the gateway taken, a worker that cannot confine itself) in
  `networks/dns/server.log` of the run root, once per network; it said
  nothing.  The log is emptied when a server starts and finds it over 1 MiB.
  The port forwarder of a rootless bridge network reports a `setsid` or
  limit it cannot set, and no longer spins on a UDP receive error.
- Connecting a running rootless container to a bridge network holds the
  rootless network namespace while it does, as a start does, instead of
  setting the bridge up again when the namespace was released meanwhile.

- A volume filled from an image keeps the file capabilities
  (`security.capability`) of the image's files: the attributes were set before
  the owner, whose change clears the capability.  An attribute that cannot be
  set, or a time, is an error naming the file; only a file system without
  extended attributes, and an attribute this user may not set (a `trusted.`
  one in a rootless engine, said once as a warning), are left out.
- A pull that cannot write its files (no space, an I/O error) fails with that
  error; it was taken as a layer that cannot be pulled by ranges, pulled whole
  behind a note, and failed the same way.
- A socket of the storage service this user may not connect to is a
  permission error naming the socket, not "start the storage service".
- A container record or a record of the base of a vfs copy that cannot be
  read is an error naming the file; it was taken as no record, and the
  record was overwritten or the size of the container was the whole tree.

- The SELinux relabel of a volume or a bind mount (`:z`, `:Z`) is refused for
  the same paths as podman: `/`, `/usr`, `/etc`, `/tmp`, `$HOME` and the
  others of its list, each exactly, with its message (`SELinux relabeling of
  /usr is not allowed`).  A directory below them was refused too, so
  `-v /dev/shm/data:/data:Z`, `-v /usr/local/data:/data:Z` and a volume with
  its store below `/dev/shm` failed, and every home directory of
  `/etc/passwd` was refused, not only `$HOME`.  A link is still checked
  where it leads.

- `cp` out of a container archives character and block devices as entries
  with their numbers and no content (they were left out), running or not,
  and never opens them.  As with podman, `/dev`, `/proc` and `/sys` of the
  container are left out of a copy: a copy of `/` has none of them (it
  carried the kernel's files of `/proc` of a running container), a copy of
  one of them is an empty archive, and a file below them is not copied.
  A volume or a bind mount keeps directories of those names.

- An image mount (`--mount type=image`) is `nodev` (`dev` asks for the
  opposite): a device node of the mounted image does not open in the
  container.  `--device` and CDI devices outside `/dev` are a bind mount of
  the host's node with its cgroup rule, not a node made in the root file
  system.

- The default log driver is podman's: `journald` on a host that runs systemd
  with a journal the user can read (a directory of a machine in
  `/run/log/journal` or `/var/log/journal`), else `k8s-file`.  It was always
  `k8s-file`, so the output of a container was not in `journalctl`.
  `[containers] log_driver` still sets it; a container keeps the driver it
  was created with, and `info` reports the one in force.  The CRI keeps
  `k8s-file`.  As with podman, journald limits the messages of a systemd unit
  (the user manager of a rootless user: every container of the user shares
  the limit), so a container that prints a great deal can lose lines; the
  `k8s-file` driver loses none.

- A rootless user whose environment has no `XDG_RUNTIME_DIR` (`su -`, cron,
  ssh without logind) gets `/run/user/UID` when it is theirs and private,
  else `$TMPDIR/velarx-run-UID`, as podman does; it was `/run/velarx`, which
  is root's, and every command failed with "Permission denied".  A
  `credential-helpers` key of `registries.conf` other than podman's default
  `containers-auth.json` is warned about once (it was read and ignored,
  while `login` kept the passwords in `auth.json`).

- `PODMAN_USERNS` is the default of `--userns` for a container that is not in
  a pod, as podman's (it was ignored without a word).  The refusals of
  `--identity` and `--ssh` name `VELARX_HOST=unix://`, which is read, and no
  longer `CONTAINER_HOST`, which is not.

- The logs of a container in the journal (`logs`, `logs -f`, `pod logs`,
  the REST logs) are the entries of this user only (`_UID`), as podman's:
  any local user could add lines to them with the fields of the container.

- `velarx ps` shows the health after the state, `Up 5 seconds (healthy)`
  (also `(starting)` and `(unhealthy)`), and the `Status` of the list is the
  health, as podman's (the REST list had it empty).

- `images --filter` takes every filter of podman: `containers`, `digest`,
  `intermediate`, `manifest` and `readonly` select instead of matching every
  image, `until=1h` takes a duration, `key!=value` negates, the values of a
  key are all required (those of `reference` are alternatives), and a value
  that makes no sense is refused with libimage's words.  `image prune
  --filter until=` judges the time the image was made, not when it was
  pulled.

- `tag docker.io/foo` names the image `docker.io/library/foo`, `tag NAME@sha256:...`
  and `tag sha256:...` are refused (`tag by digest not supported`; the
  digest was dropped and `:latest` made), and `rmi ID` of an image whose
  configuration was pulled through several manifests (several names) is
  refused as podman refuses `rmi` by ID of an image with several tags.

- After a reboot a container that was only created stays created (it became
  `Exited (0)`; one made ready by `container init` is created again), and a `--rm` container that was only created is kept (every
  `--rm` container was removed): as podman's refresh, only the containers that
  ran are exited, and only a `--rm` container that had exited is removed.

- A pod with `--exit-policy stop` stops when its last container exits also
  without the engine service (the default: nothing stopped the pod, it stayed
  `Degraded` with its infra container running, and the Quadlet `.pod` units
  never went inactive); the record command of the monitor does it, as the
  service did.  `pod inspect` says `CreateInfra: false` for a pod made with
  `--infra=false`, and `pod ps` lists no network for a pod on pasta or without
  an infra container (it said `podman`).

- `kube play` skips a document of a kind it does not play (a Service, a
  StatefulSet...), as podman does, so the output of `kube generate --service`
  plays; it refused it.  The containers get the labels of their pod (`ps
  --filter label=app=x` finds them), and `kube play` sets the labels `io.containers.autoupdate` and
  `io.containers.autoupdate.authfile` of the annotations of the pod (or of a
  container, `KEY/CONTAINER`) and `PODMAN_SYSTEMD_UNIT`, so `auto-update`
  updates the containers of a `.kube` unit.  The nodePort of the Service of
  `kube generate --service` is in the range of Kubernetes, 30000 to 32767
  (it was the published port of the host, which a cluster refuses).

- `inspect` shows the path of `--log-opt path=` as `LogConfig.Path`, `artifact
  add --annotation` annotates the manifest of a new artifact too, the header
  of `stats` is `AVG CPU %`, and `kube apply` and `kube generate` have podman's
  descriptions in their help.

- A look at whether a lazy pull has a completer (`velarx image pulls`, a
  resume) no longer makes a process that starts one at that moment believe
  one runs, and none leaves a directory behind for a pull that was committed
  or cancelled meanwhile (the next pull of that image failed to start).

- A queued completer of a lazy pull takes a slot the moment one is freed
  (it looked once a second), and one that a command waits for fetches at the
  command's speed also when the command found no process to tell.

- Two writers of one state file at once (two API requests on one container,
  a rewrite of a container's OCI configuration during an update, two engines
  that start together) no longer leave it half written or mixed: each writes
  a temporary file of its own and renames it.

- `velarx-cri` started a second time on the socket of one that runs says so
  and exits, instead of removing the socket of the running one; two
  `velarx-cri` or two `velarx-api` started together no longer both listen.
  The CRI socket is `0600` from its creation without a change of the
  process' umask.

- Overlay networking: a container that is prepared and cleaned up at the same
  time (a start retried while the stop of the failed one is under way) can no
  longer end with its veth deleted or with "the container has its veth
  already": the operations on one container go one at a time, a veth left
  over by a cleanup that never came is replaced, and a failure while the
  helper makes the packet socket no longer leaves the veth pair behind.

- `kube play` of YAML with a `FileOrCreate` hostPath, run twice at the same
  time, no longer fails the play that loses the race to make the file.

- `kube play` refuses a `hostPath` with a `..` component, as the API server
  of Kubernetes does: a `DirectoryOrCreate` of `/tmp/x/../../etc/...` made
  the directories wherever the path led.

- The command line takes podman's (pflag's) forms: a negative number after
  an option is its value (`--pids-limit -1`, `--memory-swap -1`,
  `--oom-score-adj -500`, `--cpu-quota -1`, `--memory-swappiness -1`, for
  every option that takes a value), `run --pull never IMAGE` has the
  policy `never` (it took "never" for the image; a bare `--pull` is an error
  as in podman, `build --pull` keeps buildah's bare form), the booleans
  `--sig-proxy`, `kube play --start`, `--tls-verify` and `events
  --stream`/`--no-trunc` take no value after a space, `ps --last -1` (and 0)
  lists all, and `pull` takes several images (one that fails is said and
  the next is pulled, as podman's).  `build --pull=false` is
  `never` (it was `missing`; the REST build's Docker `pull=false` stays
  "missing"), the policies are read in any case with podman's other names
  (`ifmissing`, `ifnewer`, an empty one is `missing`) and an unknown one
  says `unsupported pull policy`.

- The exit status and words of the commands given too few or too many
  arguments are podman's: `start` with no container is an error (125, it
  was silent), `network rm`, `volume rm` and `secret inspect` with nothing
  to remove or show are errors, the missing or surplus operands say
  `requires at least 1 arg(s), only received 0`, `accepts 2 arg(s),
  received 1`, `accepts between 1 and 2 arg(s), received 3`, `accepts at
  most 1 arg(s), received 2`, `` `velarx version` takes no arguments ``,
  an option's value that is not a number says `invalid argument "x" for "--pids-limit"
  flag: strconv.ParseInt: parsing "x": invalid syntax` (a negative number
  for an unsigned one: `strconv.ParseUint`), `rm`, `stop`, `kill`
  and the like say `you must provide at least one name or id`, `-m 1x` and
  `-p 99999:80` use go-units' and podman's words (`invalid value for memory:
  invalid suffix: 'x'`, `parsing host port: port numbers must be between 1
  and 65535 (inclusive), got 99999`) and `network inspect` of a missing
  network names it first.

- `container restore --tcp-close` is refused by name (it was an unknown
  option; only `--tcp-established` is restored).

- `tools/parity-report` reads velarx's "unknown flag" as an option velarx does
  not know (it counted every unknown option as refused).

- Containerfiles are read as buildah reads them.  A continuation line keeps
  its leading white space (`echo hello\` and `   world` ran `echo helloworld`),
  an empty line inside a continued instruction no longer ends it, a UTF-8 byte
  order mark at the start is skipped, a here-document of a file with Windows
  line endings loses its carriage returns, and `COPY` and `ADD` expand the
  variables of `--chown`, `--chmod`, `--checksum` and `--keep-git-dir`
  (`--chown=${UID}`).  `${NAME%pat}`, `${NAME%%pat}`, `${NAME#pat}`,
  `${NAME##pat}`, `${NAME/pat/word}` (and `//`, `/#`, `/%`), `${NAME:?word}`
  and nested `${A:-${B}}` are expanded (they were an empty string, silently),
  with the patterns of the shell; the quotes and escapes of the word of
  `${NAME:-"a b"}` are taken out (they were kept); a form that is none, like
  `${NAME-word}`, is an error naming it, as is a nesting deeper than 64 (a
  deep one overflowed the stack); `${NAME:?word}` is no error when `NAME` is
  set.  `STOPSIGNAL` refuses a name that is no signal.  `build -f` given
  several times joins the files into one Containerfile (only the last was
  used).  `<Containerfile>.dockerignore` or `.containerignore` is read before
  the ignore file of the context, and the ignore file the command line
  applies (`--ignorefile` too) is the one the build's `COPY` applies: the
  context's hid files from `COPY` with `--ignorefile`, a Containerfile outside
  of the context or several `-f`, and with neither `-f` the ignore file of a
  `Dockerfile` the build did not use was read.  `COPY --from` keeps the
  owners of the files of the other stage or image, as buildah's (they were
  root's), and a directory copied to a directory the image has (`COPY dir
  /etc`) leaves it as it is: it took the mode, owner and times of the
  source directory (a `dir` of mode 0700 made `/etc` 0700); one the image
  lacks is made as a missing parent is.

- Short names are resolved as podman resolves them.  Without a
  `registries.conf` Velarx searched docker.io, quay.io and ghcr.io without
  an alias table (`pull fedora` was docker.io/library/fedora, a name that
  only quay.io or ghcr.io had was pulled from there).  Now the table of
  aliases of podman's containers-common is built in (`alpine`, `fedora`,
  `podman`...; a file removes one with `name = ""`), there is no
  unqualified search registry unless a `registries.conf` names some, and a
  name that is no alias is refused with podman's words (`short-name "foo"
  did not resolve to an alias and no unqualified-search registries are
  defined in ...`).  `short-name-mode = "enforcing"` still refuses a name
  with several candidates, naming it, as there is no terminal to ask.  The
  README no longer says the opposite.

- With SELinux, a bind mount with a relabel (`:z`, `:Z`, the CRI's
  `SelinuxRelabel`) relabels the file systems mounted below the directory
  too (a tmpfs on a subdirectory, as a pod's volume has), as the container
  sees them with it; it used to stop at the file system of the directory, so
  the container could not write to them.  Only a whole file system is: a bind
  mount of a directory or a file below the directory is left alone (it shows
  a directory of the host, which a bind mount from the same file system
  relabeled before, as the device did not tell it), as are the mounts of the
  kernel's state (`/proc`, `/sys`, cgroups) and a file system that is also
  mounted on a directory that is never relabeled.  `tests/cri/critest.sh` runs the benchmarks of critest with
  `CRITEST_BENCHMARK=1`, and fails when the suite does not run at all.

- The REST API answers the removal, stop and wait routes as podman 5.8.9
  does. Removing a running container, one that has a dependent, a pod with
  running containers or a network in use is a 500 (it was a 409 or a 400) and
  the message of the pod lists an error for each container and the infra
  container. A `timeout` below zero is a 400 for the removal and stop of
  libpod and the removal of a pod (it was taken as "none"), a volume or a
  network with a parameter it cannot read answers as podman does, and the
  Docker `stop?t=-1` waits without a limit. The libpod report of a container
  removal has the `Id` alone, libpod's image report leaves out the lists with
  nothing in them, a wait with an interval Go cannot read is a 500 with Go's
  words and one with an unknown condition answers 0, and Docker's routes read
  a boolean as Docker does ("yes" is true).

- The REST API answers as podman 5.8.9 does in four places the podman test
  suite checks: its version is `5.8.9` (it said 6.1.3), a push of Docker's
  API that fails answers podman's stream (`{"error": ..., "errorDetail":
  {"message": ...}}`, status 500) and no longer an error document (an image
  that is not there is podman's 404 document, `failed to find image NAME`),
  the stats of a container of podman's own route
  (`/libpod/containers/ID/stats`) name it `Id` and `online_cpus` counts the
  CPUs the container may run on (`--cpuset-cpus`), not those of the host, and
  the inspect of a container that is created and not initialized has no
  `ResolvConfPath`, `HostnamePath` and `HostsPath`.

- A wait for the next exit of a container whose exit was seen and not yet
  recorded when the wait began (a container that exits at once, waited for
  right after its start) waits for the exit after it, as podman's, instead
  of answering with the one before the wait.

- The errors of the system in a registry's connection are in podman's words
  (`connection refused`, not `Connection refused (os error 111)`), which
  scripts match.

- An image whose manifest digest is sha512, pushed by a tag, is put by that
  digest too, so the registry knows `NAME@sha512:D`, the name `velarx` shows
  (a registry names a manifest put by a tag with its sha256).  A registry that
  refuses it (registry:3) keeps the tag, and a warning line says that
  `NAME@sha512:D` will not resolve there; the push by the digest keeps failing
  by name; `push --all-tags`, `manifest push` and `artifact push` say it the
  same way.  zot takes it, and so did Docker Hub (checked with one public
  repository).
- A sha512 blob that registry:3 claims to have mounted from another repository
  (it does not link it) is uploaded, not left out of the image.
- A database error is said once, in the words of SQLite or of the check that
  refused it, not as `database error: Other("...")` followed by the same text
  as its causes.

- `velarx secret ls` aligns its columns on their widest cell, as podman: a
  time such as "Less than a second ago" no longer runs into the next column.

- The cache of registry hints can no longer send the credentials of a pull
  to another host: a cached token realm is taken only if it is the
  registry's own host and port, with credentials or without (before, a pull
  whose credentials were not known up front took a realm of any host from the
  cache file).  The realm of another host is learned from the registry's own
  answer, as when there is no cache; the built-in token endpoint of Docker
  Hub still serves anonymous pulls.

- A command that starts no pull worker (`rm`, `ps`, `inspect`, the cleanup
  that runs when a container ends) no longer connects to the systemd
  manager nor makes a cgroup to confine pull workers: where the workers go
  is decided when the first one starts, on a thread that may block.  A
  `create --cgroups=disabled` with no daemon that has to pull the image no
  longer puts the pull workers in scopes of the manager (`run` already
  did not).  A `--cgroups=disabled` container is now served without
  touching either, from its `create` or `run` to its `rm`.
- A manifest fetched by a reference that is not a `sha256:` digest was not
  checked against it; a reference with a colon is now checked with its own
  algorithm, or refused.

- A read-only additional image store is no longer written to: a rootless
  Velarx, which has every permission over the owner's files inside its user
  namespace, made `db.sqlite-shm` and `db.sqlite-wal` in it.  Its database is
  opened without locks and without those files, so the store must be closed
  cleanly by its owner (a daemon that stopped): one whose log has changes
  that are not in the database (a command without a daemon leaves them, a
  daemon that runs has them) is not used, and the log says what its owner
  does.  A store with a live writer is not supported yet.

- The fetcher that the engine starts is bound however long the
  path of the daemon's socket is (a
  `--socket`, `$XDG_RUNTIME_DIR` or test directory longer than about 70
  bytes): it was not started, and the pull went without it.
- The monitor opens the EROFS image of each layer once, by a name that is no
  symlink and from the descriptor of its directory, measures its fs-verity
  digest on that descriptor and mounts or serves that open file: nothing
  between the check and the use can put another file at the path.  An image
  that is not a regular file is refused; the engine and `system check` open
  the images the same way.
- `run --rm` and `create --rm` with a restart policy other than `no` and
  `on-failure` are refused with podman's error, as podman refuses them; they
  were accepted, and the container was never restarted.
- A signature made by cosign 3 (`"optional": null` in its payload) is no
  longer refused with "`optional` is not a JSON object".
- The error for an image whose manifest states no EROFS digest under
  `--security-opt verity=enforce` no longer says to pull the image again (that
  does not help); it names the push that writes a manifest with them (one in
  another compression than that of the layers).
- A refusal for a missing signature under a `sigstoreSigned` requirement says
  when registries.d sets no `use-sigstore-attachments` for the image, so that
  its signatures were not looked for.
- A ^C at a passphrase or password prompt (`push`, `login`, `image
  generate-sigstore-key`) no longer leaves the terminal without echo.
- The `optional` part of a signature payload is read as containers/image
  reads it: a timestamp written as an integral float is accepted, a creator
  that is not a string is refused.
- Rootless containers started again right after they exited, against an
  engine daemon, no longer fail now and then with `pasta failed: TUNSETIFF
  ioctl on /dev/net/tun failed: Permission denied`, nor, with published
  ports, with `Address already in use`: the daemon took the pasta that the
  cleanup of the last run stopped for one that died, and started it again,
  on the namespace of the next run or on the ports it was to publish.  A
  pasta that dies while its container runs is still started again.

- A rootless container no longer reaches the services bound to the host's
  loopback through `host.containers.internal` (169.254.1.2): it is the
  address of the container's namespace on the host, as with podman
  (`--network pasta:--map-host-loopback,ADDRESS` opens the loopback, and
  `pasta:--map-gw` is understood).  `--network slirp4netns` was run by pasta
  and is refused by name, as is `--security-opt label=nested`, which was
  accepted and did nothing.  pasta gets `--no-map-gw`, and
  a `--dns-forward` or `--map-guest-addr` of `--network pasta:OPTIONS` is the
  name server of resolv.conf and the `host.containers.internal` of
  /etc/hosts (the defaults were written, and name resolution failed).

- Named and anonymous volumes are mounted `nosuid,nodev` (`suid`, `dev` ask
  for them), a rootless container in the host network has `/sys/kernel`
  masked, and a rootless `--privileged` container is given no host `/dev/ptmx`
  or virtual console and no longer opens every device of the host to decide
  whether it can use it.  A rootless `--privileged --network host` container
  started no more ("mount `sysfs`: Operation not permitted"): its `/sys` is a
  writable bind of the host's, as podman's.

- `--restart` takes podman's values only (`no`, `never`, `always`,
  `on-failure[:N]`, `unless-stopped`): a typo, a count with another policy and
  a count that is not a number are refused.  `--mount type=devpts` works,
  and `/dev/pts` is mounted with `gid=5` where the container's user namespace
  maps that group (the terminals belong to `tty`).

- `logs --since` and `--until` take the date forms of podman (`2026-11-01`,
  `2026-11-01T10:00:00`, `2026-11-01+01:00`; no zone is UTC).  `container
  export` prints no progress.  `top` shows the host's ids for `huser` and
  `hgroup`, and the times of `etime` and `time` as podman writes them
  (`749ms`, `1m5s`).

- On a bridge network a container is also known by its short id and its
  `--hostname`, a published port of a rootless bridge network answers on IPv6
  too, `--network-alias` without a bridge network is refused as in podman, and
  `Config.ExposedPorts` of `inspect` has one key for each port of an exposed
  range.

- `--add-host NAME:host-gateway` writes the address of
  `host.containers.internal`, `NAME;NAME2:IP` adds several names, and a value
  that is not an address (`bad:notanip`, `a=1.2.3.4`) is refused.  The
  `--add-host` entries come first in `/etc/hosts`, so that they override the
  generated ones and those of the base file.

- `/etc/hosts` starts from the host's `/etc/hosts` by default
  (`[containers] base_hosts_file` empty, as its documentation said), a
  container with pasta has its host name and name on the address pasta gives
  it, one with `--network none` has them on the loopback, and `--network
  host` takes the host's hostname and has `host.containers.internal`.

- `/etc/resolv.conf` takes the host's search domains and options, a pasta
  container the servers of the host after the forwarder, `--dns`,
  `--dns-search` and `--dns-option` apply with `--network host`, `--dns-search
  .` writes no search line, and a host whose only resolver is local
  (systemd-resolved, NetworkManager's dnsmasq) hands over the servers of its
  upstream file.  A container with no usable server still gets 8.8.8.8 and
  8.8.4.4, as podman's does.  The lines are in podman's order (search,
  nameserver, options), a `--network host` container gets the host's
  servers, search domains and options rather than a copy of the file, and
  `--read-only` makes `/etc/hosts`, `/etc/hostname`, `/etc/resolv.conf` and
  `/run/.containerenv` read-only too.

- A container has a pids limit of 2048 by default (`[containers] pids_limit`,
  podman's; 0 or less for none; not the RUN steps of a build nor a CRI
  container), and `--memory` without `--memory-swap` allows as much swap as
  memory instead of an unlimited swap (`run`, `create`, `update` and the REST
  create routes, as podman's).

- `inspect` shows `EffectiveCaps`, `BoundingCaps`, `ProcessLabel`,
  `MountLabel`, `AppArmorProfile` and the `Ulimits` the container runs with,
  the `io.podman.annotations.*` that podman records (also in the OCI
  configuration), and `systemd` as the `CgroupManager` of a container in a
  systemd scope.

- `--cidfile` is removed when the container is removed, by `rm` and by `--rm`.

## [0.1.0] - 2026-11-03

The first release.

**There is no compatibility between 0.x releases.** The
database and the on-disk formats (the store layout, the configuration file),
the command line and the varlink and REST interfaces may change in any
release, without a migration: the store layout and the configuration file
carry no version yet, so do not run two versions on one store, and after an
upgrade expect to start from an empty store.  See "Status" in
[README.md](README.md).

Linux only, tested on x86_64 with Linux 6.8 or later; a binary needs the
glibc it was built against or a newer one (a Fedora 44 build needs glibc
2.39).

### Added

- `cp` out of a container that is not running checks the fs-verity digest of
  the files of the store it reads, as a running container does: with
  `fsverity_require` a file without it is an I/O error.
- Rootless, the files of an image are checked against their fs-verity digest
  each time they are opened where the store has fs-verity, as root: the
  monitor's FUSE server serves the metadata of the layers (the stubs with
  their `user.overlay` attributes) and the kernel's overlay opens the files
  through the store and checks them (`verity=on`, or `require` with
  `fsverity_require`).  A file of the store replaced by another, or by a copy
  without fs-verity, is not served.  A store on a file system whose blocks are
  smaller than 4096 bytes is mounted with `verity=off`: its fs-verity digests
  are not those that name the files.
- `fsverity_require` on a file system whose blocks are smaller than 4096
  bytes is refused at the pull and at the start of the service, naming the
  block size: its fs-verity digests are not those that name the files.
- A container of a lazy image on a store with fs-verity reads its files, as
  root and rootless: its overlay has `verity=off` and the FUSE server checks
  the files it serves; as root the overlay refused every file fetched into a
  staging without fs-verity, or served by the FUSE server (EIO).  With
  `fsverity_require` the overlay checks the files (`verity=require`) where
  the staging of the container is on the file system of the store, else
  every file goes through the FUSE server, which checks it, as root too.
- A runtime of `[runtimes]` can be a table, `[runtimes.NAME]` with `path` and
  `args`: the options go to the runtime of that name only (two names may be
  one program), after those of `[server] runtime_args` (gVisor's `runsc`
  rootless needs `--rootless` and `--ignore-cgroups`).  The runtime handlers of the CRI report the features
  of their own runtime (user namespaces, recursive read-only mounts) from its
  `features`, no longer the same for all.
- `pod create` and `pod update` take podman's block IO limits
  (`--blkio-weight`, `--blkio-weight-device`, `--device-read-bps`,
  `--device-write-bps`) for the cgroup of the pod, as a systemd slice or as
  `io.max` and the weight files, and the libpod routes take `blockIO`;
  `pod inspect` shows them.  The members of a pod, and a container that joins
  a `--ipc shareable` one, share its `/dev/shm`; `--ipc shareable` is the
  default of a plain container, as podman's, so `--ipc container:ID` joins any
  container (the /dev/shm goes when the container exits), but a `--ipc
  private` one, which cannot be joined, as podman says; `--ipc none` has no
  /dev/shm.  `create --user nosuch` (or an unknown group) makes the
  container and the start says so, as podman's.  A health check is an event
  each time (the events file stays bounded by its rotation).  `pod create
  --infra=false` ignores `--infra-image`, `--infra-command` and
  `--infra-conmon-pidfile`, as podman's command line does.  `exec` has no
  `--sig-proxy` (podman's has none): the command goes on when its client is
  interrupted; to a file or a pipe its output comes as the command writes it
  (it came at the end).  `container inspect` shows `ImageDigest`; `--tz ZONE` links `/etc/localtime`
  to the zone file of the image when it has one; `top` takes `huser`,
  `hgroup` and `hpid`; the `id`, `name` and `ctr-ids` filters of `pod ps` are
  regular expressions; the records of a container's log file carry the local
  time with its offset, as conmon writes them (`logs -t` shows them so);
  `logs --follow` of a journald container says, as podman's, that it needs the
  journald events backend.
- Checkpoint and restore: `--print-stats` prints podman's document (the
  durations and what CRIU measured, the same names and layout) for `container
  checkpoint` and `container restore`, and `printStats` is taken by the libpod
  routes; `checkpoint --pre-checkpoint` dumps the memory of a container that
  goes on running, and `checkpoint --with-previous` builds on it (CRIU's
  incremental dump).
- More podman parity: `build --stdin` (the standard input of the command is
  the one of the RUN steps; the build routes of the API have none); `:U` (and
  `chown=true`) gives a mount to the user again at every start of the
  container, when its owner is another; with `--userns=keep-id` (or another
  user the image lacks) the passwd and group entries are written in the
  `/etc/passwd` and `/etc/group` of a container whose root file system is
  writable, so that the file is its own (it can be replaced, it shows in `diff`
  and `commit`) and not a mount; `pod create --infra=false` (a pod with no infra
  container: its containers share no namespace, the pod is their cgroup and
  their group); the cgroup of a pod made by a command is a systemd slice with
  the pod's limits (`pod inspect` shows its path; it goes when the pod stops
  and comes back with the next start); `commit --config FILE`; `--mount
  type=glob` and `type=ramfs`; the `z` and `Z` options of `--mount`; the
  `build --logsplit` (with `--logfile`, the output for each platform goes to
  `FILE_OS_ARCH`); the
  `stopped` health status of a container whose stop ended a check
  (`healthcheck run` prints it), `--health-on-failure` refused without a
  health check, and the `health_status` field of an event; a container that a
  stop or a failed health check is stopping shows `stopping` in the commands
  of other processes too.
- Podman's REST API test suite runs to its end (36-quadlets left out): `network
  create --opt isolate=true|strict` is taken (the bridges of velarx never
  forward to each other; `isolate=false` is refused); a commit with a
  message in the OCI format is refused on the command line and the libpod
  route, as podman's; an invalid subnet of `networks/create` is 500, a failed
  login says `401 Unauthorized`, a quiet build of the Docker route tells the
  bare image ID, `Entrypoint: []` of the Docker route drops only the
  entrypoint of the image, a container with no command is made.
- Changed to podman's ways: a limit of 0 (`--memory=0`, `--cpu-quota=0`) is
  none; `--log-opt max-size` counts in powers of 1000 (`7.069m` is 7069000
  bytes); `--log-driver json-file` is kept as it was given; an unknown user
  or group of the image exits with 126 and says `no matching entries in
  passwd file` (`group file`); a rootless `--oom-score-adj` below the current
  one is raised to it with a warning, no longer refused.
- Podman parity of the command line: `pull --all-tags`; `pod clone` copies
  the containers of the pod; the infra container of a pod is named after
  the first 12 characters of the pod ID, and cannot be removed without its
  pod (`rm --depend` and `rm -a` remove the pod); the operations on a pod
  (start, stop, kill, pause, restart, remove) run one after the other; a
  flag takes a glued `true` or `false` (`--all=true`); `events` prints whole
  IDs by default (`--no-trunc`) and its templates read the attributes;
  `--cidfile` replaces what a file that is there has once the container is
  made (and leaves it as it was when it is not); podman's words for a bad pod
  namespace, exit policy, ulimit, a missing network, a hostname in a pod's
  UTS namespace, a flag without its value and an unknown flag; a template
  field that the event does not have is an error, as podman's.
- The root file system of a container has podman's `/etc/mtab` (a link to
  `/proc/mounts`) when its image has none; a tmpfs (`--tmpfs`, `--mount
  type=tmpfs`) starts with what the image has there (`tmpcopyup`, unless
  `notmpcopyup`) and is no longer `noexec` by default, as podman's.
- `cp` to and from a container that does not run reaches its volumes and
  bind mounts; a copy named as a link goes where the link points.
- A commit or a build step keeps the removal of an engine file the image
  has (`/etc/hostname` removed in a `RUN`).
- Registry calls through the downloader: `push`, `tags`, `search`, `login`
  and the inspection of remote manifests are made by the registry downloader,
  so the command or engine process opens no connection to the registry and
  reads no credentials; the credentials of a command (also for `pull` and
  the completion of lazy layers) reach the downloader in a sealed memory
  file, never in a message and never on a disk. Listing tags now follows all
  pages. `artifact push` and the `/auth` route of the Podman API (its
  password now in a pipe of the call to the engine) go through the
  downloader too, also with `--tls-verify=false` for a registry that
  registries.conf does not mark insecure (as podman, on the word of the
  command, with only the credentials the command passes). A
  registry downloader that keeps running reads a `login` or `logout` made
  since it started; `search` asks a registry's catalog with the
  credentials; the credentials of a registry never go to another host its
  upload session names.
- `docker-archive:` and `oci-archive:` can be read from a pipe given as a
  path (a FIFO, `/dev/fd/N`): the archive is opened once and, when it cannot
  be read twice, copied first to a temporary file, as podman does.
- Engine and command line: a container engine for Linux, as root or
  rootless, modelled on podman's command line (`velarx container run`,
  `velarx run`, pods, volumes, secrets, manifests, checkpoint and restore
  (as root; a restored container on a bridge, CNI or pasta network gets its
  network set up again, as at a start), health checks, `kube play`, `kube generate`, `kube apply` and `kube down`,
  auto-update, Quadlet through podman's generator).  A command runs the
  engine in its own process, as podman does; the engine service
  (`velarx varlink`, the varlink interface `org.velarx.Engine`) is used
  only when a command names it (`--socket`, `--url`, `--remote`,
  `VELARX_HOST`).  Every container is owned by a small `velarx-monitor`
  process that outlives the command; it follows the container process, and
  the commands of `exec`, through pidfds: an exit is seen the moment it
  happens, with no polling, and a signal never reaches a process that took
  the number of one that is gone.  An `exec` reports the exit status of
  its command, however fast it ends; a status the monitor could not have
  is an error that says so, never a made-up code.
  `velarx-client` is the thin client of the engine.
- Containers: OCI runtimes such as `crun`; the `--cgroups` modes
  (`enabled`, with a systemd `scope` or `unit`, `no-conmon`, `split`,
  `disabled`); user namespaces (`--userns`, `--uidmap`,
  id-mapped mounts); CDI devices; kernel keyrings; wait conditions as
  podman's.
- Following logs: the engine follows any number of logs (`logs -f`, the
  REST API) with one inotify instance, so the limit of a user
  (`fs.inotify.max_user_instances`) is not used up by followers; a log
  truncated in place is read again from its start.  A reader that does not
  read the output of a container for `[containers] client_stall_secs`
  loses that output but not the session: it still gets the exit status
  (`run --rm` piped into a stuck reader exited 125 with "no such
  container"), and the engine logs a warning naming the container.  A
  reader that is only slow gets all the output of a container that exited
  (the monitor kept it for 2 s, and read what the pipes of the container
  held for 1 s).
- Input of a session: through the REST API (attach, exec) and the CRI
  (exec, attach), the input of a command goes in order and beside its
  output: a command that takes its input only as its output is read, as
  `cat`, no longer waits for its client until the client is dropped with
  its output cut short, and input sent before a container started no longer
  comes after later input.  A client that sends its input before the
  container starts has 1 MiB of it read then (the rest waits).
- Images: OCI images written, OCI and Docker schema 2 images read (`load`
  reads the archives of `docker save` and of `podman save`, and so does
  `pull docker-archive:FILE[:REF|:@N]`, podman's selector: a reference or the
  N-th entry of the archive's `manifest.json`; writing the format stays
  refused); builds
  from a Containerfile with buildah's features (`RUN --mount`, here-documents,
  `build --secret`, `--ssh`, `--build-context`, reproducible builds,
  squashing, `COPY --parents`, `COPY/ADD --exclude`, a cache of the steps in
  a registry with `--cache-from` and `--cache-to`, `--layer-label`,
  `--cpp-flag`, SBOMs made by a scanner image, `--output` on the build
  routes, whose `outputs`, `sbom-output` and `sbom-purl-output` are absolute
  paths of the engine's host) and entitlements for what goes beyond the sandbox of a step.  As
  buildah does, a RUN step keeps what it writes in a VOLUME of the image
  (`--compat-volumes` gives Docker's behaviour), and the images carry the
  label `io.velarx.version` (not with `--timestamp` or
  `--source-date-epoch`; `--identity-label` decides).
- Storage: a content-addressed store of the files of the layers (fs-verity
  digests), composefs root file systems (an EROFS image per layer, served
  through FUSE when rootless), lazy pulls of zstd:chunked images,
  `velarx system check`, `df` and `prune`.
- Networking: bridge networks, `host`, `none`, macvlan, pasta for rootless,
  a DNS server for container names, CNI networks for a daemon running as
  root; static routes (`network create --route`), a static IPv6 address and
  MAC address per network (`network connect --ip6 --mac-address`), and
  `network reload` to apply the firewall rules of running containers again.
- `container clone` and `volume reload` (which
  has nothing to do: there are no volume plugins); velarx-api takes the
  static MAC address and the IPv6 address of a network connect. The record
  the engine keeps of a container's request has its secrets by name, no
  longer the value of an environment secret.
- `velarx-p2p`: an optional peer-to-peer service that shares layers, chunks
  and checkpoints between nodes, and an overlay network (not
  tested between two real nodes; its name server for the containers answers
  over UDP and over TCP, as podman's does, so a truncated answer is retried
  and served); other content sources as separate
  processes on a Unix socket (`org.velarx.Downloader`).
- `velarx-api`: podman's REST API (libpod and Docker's routes) as a
  frontend of the engine (compatibility is measured, not
  complete); docker-compose (v2) and podman-compose run a project with a
  built image, a health-checked dependency, a network with aliases and a
  named volume against it.
- `velarx-cri`: a Kubernetes CRI server on the engine, with CNI pod networks
  (run and tested as root only, as a kubelet does:
  `make cri-tests` runs its tests, critest and a kubelet among them).
- What Velarx does not implement is refused with an error, never ignored:
  options, configuration keys, API fields and `kube play` and CRI fields.
  The fields of the bodies of the API (the container, pod, network, volume
  and manifest routes, exec, commit and update) are checked against the
  types of podman by a test, as its query parameters are: the ones Velarx
  has no support for (for instance `personality.flags`, the `kernel` memory
  limit, `cpu.burst`, the `uidMappings` of a mount, the extra settings of a
  network of a pod, a `Healthcheck` of a commit
  configuration) are refused naming them (501), and the Docker update takes
  `Ulimits`, the Docker create `EnvMerge`, `UnsetEnv`, `UnsetEnvAll`,
  `BindOptions.NonRecursive` and the subpath of an image mount, the libpod
  create `cni_networks` and the OCI `resource_limits.unified`, a pod the
  size of an automatic user namespace and anonymous volumes, and a libpod
  volume `UID` and `GID`.  A second address of a family, or addresses on
  more than one network, of a create are refused (they were dropped).
  Docker's create attaches every network of its endpoints (it kept the
  first of `--network a --network b`), and the create and `network connect`
  take an endpoint's `IPAddress` as a static address, as podman does.
  Docker schema 1 images, foreign layers and the Docker output formats are
  refused; OCI is all that is written.
- Packaging and project: systemd units, man pages and shell completions
  (`make man`), an RPM spec (`contrib/velarx.spec`),
  `make dist` for the source tarball with its SHA256SUMS, a `Makefile` as the
  single entry point for build, test, e2e, fuzz and install, fuzz targets of
  the parsers of untrusted bytes, a size budget per binary, a threat model
  (docs/THREAT-MODEL.md).
- Documentation: an architecture overview (docs/ARCHITECTURE.md), a
  roadmap (docs/ROADMAP.md) and a table of supported platforms in the README (x86_64
  only; aarch64 is untested and unsupported).
- Concurrency: commands that act on one object at the same time are
  serialised where it matters.  Starting, removing, initialising and
  restoring a container take the container's start lock, a stop waits for
  a start under way and then stops what it made, and an exit is recorded
  for the run it belongs to; the engine stops accepting before it
  answers a restart, finishes the calls that change something on every
  stop, and a frontend waits for a stopping engine by an event; network
  subnets and automatic host ports are chosen where they are recorded;
  garbage collection keeps the files a lazy container fetched; changes of
  a manifest list and of the extra state of a container are written only
  if nothing changed meanwhile; a pull holds the store lock for its check
  and its commit, not its download; a pod being removed takes no new
  container.  Waits that an event can end (the daemon of the tests, the
  scope of a container, the supervisor of pasta, the answers of peers,
  `events --stream`, the hold of the engine) no longer poll.
  The state of a pod is recorded from what its containers are after every
  start, stop, kill, pause or unpause, of the pod or of one container, so a
  start that lands while the pod stops is not overwritten; a pull's lease is
  held by a lock the kernel drops when the pull ends, so a pull killed with
  SIGKILL leaves nothing to wait for; a command started while a pull
  downloads, or a collection meanwhile, no longer removes the files of that
  pull (it failed with "No such file or directory"); `events --stream`
  follows the journal's cursor or the offset in the events file, so an event
  kept late is shown however late and the stream keeps nothing per event; a
  run whose container another command removed meanwhile exits 125, not 127.
  `events --stream` of a command without a service waits for the journal's
  directory to be made, not for a timer, and says so when no place keeping the
  events can be watched.
- With `--log-driver passthrough` the container writes straight to the output
  of the command.  Where SELinux does not let the container write to it (a
  file of the user's opened with `>`: the container gets /dev/null and its
  output is lost, as with podman), `run` and `start` now say so and name the
  way out (a pipe, a terminal, `--security-opt label=disable`).  Permissive
  mode or a permissive domain no longer gives this warning or the one about
  the sockets of a unit.  In a user unit, `journalctl -u` leaves out the
  lines of a process that exits before the journal reads them (the journal
  finds the unit by the writer's cgroup, for any program, container or not);
  `SyslogIdentifier=` and `journalctl -t` find them all (GAPS.md).
- A container monitor holds no inotify instance (it polls the `memory.events`
  file of the cgroup), and any other process one at most for all its waits
  (the engine waits for the cgroup of every container it starts, an events
  stream for the event log), so containers of root no longer run out of
  `fs.inotify.max_user_instances` after a few dozen, nor do starts at once;
  when that limit or `fs.inotify.max_user_watches` is reached anyway the
  error names it.
- A file with holes in a build context is part of the build: `COPY` and
  `ADD` of it used to fail with "No such file or directory", because the
  context tar the command line makes (and GNU tar `--sparse` in every one
  of its formats) stores such a file as a sparse entry the unpack skipped.
  Sparse entries are now unpacked into a file with the same holes, for a
  build context, `cp` into a container and the import of a volume (a file
  is limited to 64 GiB, the build's byte limit for a context; a map that
  is out of order, overlapping, or longer than the file is refused, and
  so is a file of more than 32768 pieces in the old GNU format, which
  the tar library reads in a time that grows with the square of them).
  `import` of a tar with sparse files writes them whole into its layer,
  as podman's import does (it used to fail for the old GNU format and,
  for the pax ones, to import the packed data under the name GNU tar
  gives it for other readers); a layer that is pulled or loaded with a
  sparse entry of a pax format is refused, as one of the old GNU type
  already was.
- `top` and `stats` read the cgroup the container was made in, wherever the
  engine made it (a systemd scope, the cgroup tree of the service, a split
  unit), with the cgroups below it: `top` no longer lists only the process
  tree, `stats` no longer reports zeros.  `top` of a `--cgroups=disabled`
  container fails as podman's does; `stats` of a container that runs in the
  cgroup of its monitor fails instead of reporting that cgroup.
- `cp` into and out of a running container made with `--rootfs` works: its
  root was refused as not the container's.
- The health check of the service asks the database, and `info` reports
  FUSE passthrough only where the kernel lets the engine use it (Linux 6.9
  and the administrator of the host).
- `kube play` refuses a label, an annotation or a ConfigMap or Secret value
  that is a list or a map, as podman does (it made an empty string of it),
  and reads a plain number, boolean or time as podman does (`1.10` is `1.1`,
  `0x1F` is `31`, `TRUE` is `true`, `.inf` is refused).
- A log rotation that cannot take its lock moves no file: the output goes
  on into the current log, the error is reported, and the rotation is tried
  again later.
- The API service and the downloaders no longer sleep after a failed
  accept: a connection that went away (or that a firewall refused) is
  followed by the next at once; out of descriptors or memory, they accept
  again when a connection ends, and at the latest after a second; only a
  listener that is no socket any more stops the API service.
- CRI: the lists of stats (`ListContainerStats`, the stats of a pod) leave
  out a container that cannot be sampled instead of failing for all.
- Rootless, a `newuidmap` or `newgidmap` that fails (or sub ids that are
  listed for the user in `/etc/subuid` and `/etc/subgid`, which are looked
  up by the user's name or numeric id, as the helpers do) stops the start
  with what the helper said, where it mapped only the user's own id for the
  whole boot; with no sub ids listed only that id is mapped, as before.
- Whether an OCI runtime takes `--cgroup-manager`, `create --config` and
  `--no-new-keyring` is read from its help, not from its file name, so a
  runtime installed as `crun` that is runc, or a wrapper, gets the options it
  takes; one that cannot be run is an error that names it.
- `firewalld` is told of a bridge network over the system bus, without
  `busctl`; a file the monitor or the FUSE server is still writing in the
  store is kept by a lock its writer holds, and the garbage collection
  removes the temporary files of dead writers whatever their age; the
  monitor of a container is told alive by a lock it holds, not by the name
  of a process; a container that waits for its `run` client to attach starts
  at the attach, and at the latest after 30 seconds if no client comes; a
  stack of mounts on a network namespace pin or a stale image mount is
  detached as often as the mount table lists it; a shareable network
  namespace is not given to another container while a container joined it;
  an image the FUSE server cannot read whole (a link without its target, a
  damaged directory) answers an I/O error, not an empty link or a short
  directory, and so do the copy and the export of such an image (they listed
  an empty directory); a socket in an image is a socket.
- A file copied out of an image keeps the nanoseconds of its time.
- The DNS server of bridge networks starts again: its worker could not read
  its bounding set under the filter of its keeper, and every name lookup of
  a container failed.
- Rootless, the error of a failing `newuidmap` or `newgidmap` says what the
  helper said.
- A bridge network whose teardown cannot read what the database has of the
  container keeps the namespace of the container pinned and says so: the
  next teardown undoes the host side.

### Fixed

- A reference `NAME@sha256:...` whose digest the store does not have no longer finds
  the `latest` of that name: the image is not known.

- A file fetched for a lazy image never gets its name in the
  staging without fs-verity where the file system has it: a process that
  forked while the file was written kept the kernel from enabling it, and the
  file was staged all the same, so that an overlay with `verity=on` refused
  it (EIO).  The fetch waits for that process to let go of the file, and
  fails if it does not in time.  The overlay now checks the staging of a lazy
  image on the file system of the store without `fsverity_require` too.
  A pull of the service waits the same way, where it stored the file
  without fs-verity in a store that has it (a warning), which the overlay
  then refused.

### Security

- The process that serves container DNS may use only the system calls it
  needs (an allow-list): it can no longer create namespaces or use the new
  mount API, `bpf`, `keyctl` and the like if it is compromised, nor open a
  UNIX socket to the services of the machine or become another user than
  nobody.  A worker of it that dies no longer stays as a zombie.  The
  confined pull, peer-to-peer, API and CRI helpers and the monitor refuse a
  `clone` that makes a namespace, and a few more calls (`open_by_handle_at`,
  `name_to_handle_at`, `personality`, `open_tree_attr`, `quotactl_fd`; the
  monitor also `setxattrat`, `removexattrat` and `file_setattr`).
- A new store is private (directories 0700, database 0600).
- Nothing listens on the network unless you ask for it: the engine, the API
  and the CRI server serve unix sockets, their TCP listeners bind the
  loopback only; published ports and a started `velarx-p2p` do listen
  (README, "Status").
- A registry that is not on a private address cannot send the client to one
  (a token realm or a redirect) unless its block of `registries.conf` says
  `allow-private-addresses = true`; a TCP listener of `velarx-api` needs a
  bearer token or an explicit `allow_unauthenticated = true`; the overlay subnet of a node comes
  from a hash of its peer id in a range of up to a /8 (a /10 by default),
  a peer may only claim one of its own, and a subnet that two peers claim is
  routed to neither of them.
- The seccomp filters of the pull workers, the pull job, the registry downloader,
  `velarx-p2p`, its overlay helper and the API and CRI servers are allow-lists:
  they name the calls the process makes, with the arguments of the ones that
  could do more, and refuse the rest (a call of a newer kernel answers
  `ENOSYS`, as on an older kernel). Archives with a sparse entry of the old GNU
  format cost memory and time in proportion to their size, not to the size of
  the file they describe.
- Image labels cannot choose the unit that auto-update restarts; build
  credentials are passed on request only; a checkpoint archive is passed as
  a descriptor; the CRI server ends when the engine is gone.
- The workspace forbids `unsafe_code` outside `velarx-sys`, which holds the
  system calls; there, an `unsafe` block without a SAFETY comment fails
  the lint.
- Importing a checkpoint archive is a decision of the user: archives are not
  authenticated (docs/THREAT-MODEL.md).
