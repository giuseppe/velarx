<!-- SPDX-License-Identifier: Apache-2.0 -->
# Threat model

What velarx protects, whom it trusts, what each kind of adversary can and
cannot do, and what is left.  A statement without a mechanism is a
limit, not a guarantee.

## What is protected

* **The host**: its files, processes and network, from a container and from
  what an image, a registry or a peer sends.  The engine runs as root (or as
  a user, rootless) and is the most privileged code on the path of every
  byte that comes from outside.
* **The store**: the files of the images (`<root>/objects`), the database
  (`db.sqlite`), the table of contents and the tar-split of each layer
  (`<root>/layers`, checked against the digests of the database whenever they
  are read), the containers' state, volumes, secrets and credentials.
  What is in the store is run as the container's root file system.
* **The control of the engine**: whoever can send requests to the API
  controls the containers, and as root can run anything on the host (a
  container with `--privileged` or a host bind mount is the host).
* **Secrets in transit and at rest**: registry credentials, `secret`
  values, the swarm key of the peer-to-peer network.
* **What the user pulls and runs** (privacy toward the sources; toward the
  members of the swarm a digest is the capability, see "The peer-to-peer
  swarm").

## Who is trusted

| Party | Trusted for | Why and where |
| --- | --- | --- |
| root of the host | everything | owns the store, the sockets, the configuration |
| the user of a rootless engine | the engine of that user | the engine runs as that user; `SO_PEERCRED` checks (below) |
| the configuration files (`config.toml`, `registries.conf`, `policy.json`, hooks, credential helpers, runtime path) | all of it | they name programs the engine runs with its privileges; they are the administrator's, and are read as such |
| the OCI runtime (`crun`) and the kernel | the isolation of containers | velarx sets up the specification; the runtime and the kernel enforce it |
| the processes of velarx of the same user (daemon, monitors, fetchers, the peer-to-peer service) | each other, through private sockets | a socket directory of mode 0700 and `SO_PEERCRED` of both ends: `crates/base/src/ipc.rs`, `crates/proto/src/serving.rs` |
| the members of the peer-to-peer swarm (the holders of the swarm key, or the nodes with a certificate of the authority) | to ask only for what it needs and not to misbehave: it is served any object whose digest it names, and there is no defence against a member that floods, hoards or claims what it does not have | admission is the boundary ("The peer-to-peer swarm"); what a member sends is still checked by digest, and a member is removed by revocation or a new key |
| the storage service of `[storage] driver = "varlink"` | what the files of a container's root file system are, and keeping what it was given, like the OCI runtime | it is run by the user of the engine or by root (`SO_PEERCRED` on every connection) and is chosen by the administrator in `config.toml`; everything else it says is checked ("A storage service") |

Not trusted: images (content, configuration, labels, annotations), registries
and everything they send (manifests, tokens, redirects, blobs), content
sources, nodes that are not admitted to the peer-to-peer swarm, the processes
of a container, and the other users of the host.

## Trust boundaries

```
  registry ──https──►  pull worker (Landlock + seccomp, no store access) ─┐
  content source ──unix socket (0600, SO_PEERCRED)──► engine (checks digests) ──► store
  peer ──libp2p/QUIC──► velarx-p2p (Landlock + seccomp, no caps) ──unix──┘      │
                                                                                 ▼
  client ──unix socket (varlink)──► engine ──► monitor (one per container) ──► OCI runtime ──► container
```

Everything on the left of the engine is untrusted (a member of the swarm is
trusted not to misbehave, not for its bytes), and is handled by a
process that has given up what it does not need before it reads the first
byte (below).  Those processes are not adversaries: they are confined because
a hostile image or source may exploit a bug in the code that parses it, and
what they hand over is checked because they can have bugs.  The engine bounds
lengths before allocating and verifies every digest.

## Adversaries

* **A malicious image** controls the layers, the configuration and the
  annotations. A confined pull worker (Landlock and seccomp, no access to
  the store) downloads and inflates the layers; the tar stream is parsed
  by the front of the fetcher, which is confined too and writes only in the
  staging it was handed, not by the engine: names, extension
  headers, extended attributes and entry counts are bounded; `..`, NUL and
  sparse files are refused; the attributes of the overlay file system
  (`overlay.*` in any namespace) and values over 64 KiB are dropped, and
  the other attributes are data of the image (a file capability,
  `security.capability`, is kept: it grants nothing past the bounding set
  of the container); decompression is cut at `max_inflate_ratio` times the
  compressed size and at `max_layer_gib`.
  The worker resolves no name: it asks the fetcher's front on a channel
  (a host name of at most 253 bytes, 16 questions at a time, at most 32
  addresses in an answer), and the front asks a runner it forked before
  it confined itself.  The runner reads files and opens sockets, as the
  name service of the host needs, and writes, executes and mounts nothing
  (`nobody` with no capability for a root engine).  A compromised worker
  can have it resolve any host name (a channel of bytes to a name server,
  as the ports it may connect to are) and keep 16 of its 64 places busy;
  the check of the addresses it gets (`allow-private-addresses`) is the
  worker's own.
  A front whose runner dies ends (it cannot fork another once it is
  confined), and the engine starts a new fetcher for its next need.
* **A malicious or compromised registry or content source** is verified:
  the manifest by policy, the configuration and layers by digest and diff id,
  chunks by their hash, files by fs-verity digest.  A layer with a table of
  contents (zstd:chunked) is held to that table, which the manifest vouches
  for, and never to the diff id: the diff id the image gives is recorded as
  its claim and is checked only if the stream of the layer is made again.
  A layer without a table of contents may come from the sources as an index
  (the table and tar-split a node recorded) and the files the store lacks: the
  index is a claim, each file is checked against the fs-verity digest it is
  asked by, and the stream made again from the tar-split and the files must
  hash to the diff id of the configuration before anything of the layer is
  named or recorded; its blob is never hashed (recorded so), and a wrong
  index is asked for once more, of another peer, and then costs the pull of
  the blob.  A source cannot make a pull wrong, only slower, and a circuit
  breaker skips one that fails.
* **The chain of trust of a pull** starts at what the user names: a digest
  (`name@digest`) is checked against the manifest or index it names, and
  each step against the one above it (the platform's manifest against the
  index, the configuration and layers against the manifest, the files of a
  zstd:chunked layer against the table its annotation names, every file
  against the fs-verity digest the engine measured).  A tag is taken
  from its registry, or, with `[pull] names` listing another source (the
  peers), from the newest signed record of the name and tag: a signature
  made for exactly that name and tag by a key the policy accepts for it,
  whatever its age, so a name whose policy asks for no signature is never
  resolved by a peer, and a peer is believed for nothing it did not get
  signed.  Records of the same time that name two digests are an error.  The
  peers serve what a digest names, and the signatures kept with it.  What is off the
  chain is recorded as a claim and never names anything: the diff id of a
  zstd:chunked layer, the content digest of a file the table also gives an
  fs-verity digest, the blob of a layer made from an index (a node that asks
  for the layer by that blob checks it against its own diff id), and the
  places of chunks, which whoever copies one checks.  The file a record
  names is the one the engine opened or measured, never one a claim names.
* **A dual view image** has a layer whose table of contents (zstd:chunked),
  which the manifest vouches for, and whose tar stream describe different
  filesystems: other names, modes or contents, a file only in one of them.
  A tool that reads the table and one that reads the stream then see
  different images.  A layer with zstd:chunked annotations is pulled through
  its table or not at all: its entries and its EROFS image are the table's,
  every file is checked against it, and its tar-split, which makes the tar
  again for a push, must describe the same entries.  Nothing falls back to
  the stream: a registry that serves no ranges gives the blob as the
  transport of the table's ranges, and a layer whose table cannot be used
  (annotations that name no table this reads, no tar-split, no fs-verity
  digest for a file, a tar-split or bytes that are not the table's, a source
  without ranges such as an archive) is refused with an error that names it,
  and nothing of it is stored.  A lazy pull stages a layer and runs
  containers on it once every byte is checked against the table, and
  replays its tar-split at the completion, which commits nothing of a pull
  whose tar-split is not the table's.  A layer whose descriptor names a
  binary table (`table-checksum`) has a third description, which velarx
  pulls it by alone, with the same rules: its JSON table and the table
  velarx reads may differ as the table and the stream may, and nothing
  falls back from one to the other.  The binary table is parsed in the pull
  in user space, every record checked before it is used; the EROFS image
  is always made here from its checked values.  Only a layer without the
  annotations is read as a stream.  The image of a layer is what an extraction of its
  entries in their order makes: a hard link names the file its target is at
  that point of the archive, and a layer whose entry has a parent that is not
  a directory there, or that turns a directory into another type, is
  refused.
* **A node outside the peer-to-peer swarm**: see "The peer-to-peer swarm"
  below.
* **A storage service** (`[storage] driver = "varlink"`) is chosen by the
  administrator and trusted like the OCI runtime: it makes the files a
  container runs on. The engine does not take its word for anything else and
  bounds and validates every reply.
* **A compromised container** gets the defaults: the default capability
  set, the default seccomp profile, masked and read-only paths, an AppArmor
  profile and SELinux labels where enabled, a pid limit. Rootful containers
  have no user namespace unless `--userns` asks for one, so an escape of the
  kernel's or the runtime's isolation is root on the host.  The monitor
  mounts the root file system `nodev`; whether the container's root keeps
  the flag is the OCI runtime's doing, and Velarx does not repair it.  crun
  older than 1.31 does not keep it (crun 1.30 remounts the root without its
  flags on kernels with `OPEN_TREE_NAMESPACE`, 7.0 and later, and every
  crun before 1.31 with `--read-only`): with such a crun and a root engine
  the container root has no `nodev`, so a device node of an image, or one
  made with `CAP_MKNOD`, opens any device the device cgroup allows (any
  device with `--cgroups disabled`).  crun 1.31 keeps the flags (commits
  2594140d and 775d4c65); runc 1.5.2 keeps them except with `--read-only`.
* **An imported checkpoint** (`container restore --import`) carries process
  images that `crun restore` restores as root unchecked: importing an archive
  from someone else is running their code as root.
* **The monitor's socket** (`org.velarx.Monitor`, mode 0700 directory) accepts
  only the monitor's user and root (`SO_PEERCRED`), with bounded calls,
  connections and idle time.
  Landlock's signal scope (ABI 6, Linux 6.12) keeps the confined threads of
  the monitor from signalling other processes; their filter denies `kill`
  and `pidfd_send_signal` but not `tgkill`, `tkill`, `rt_sigqueueinfo` or
  `rt_tgsigqueueinfo`. On a kernel before 6.12, older than the one Velarx
  needs, a thread taken over first could signal any process the monitor
  may.
* **A local unprivileged user** cannot reach the sockets of a root engine
  (0660 root:root in a 0700 directory). `velarx-api` serves TCP only with
  `--listen tcp://` and does not start without a bearer token
  (`[api] token_file`), a client CA (`tls_client_ca`: only clients with a
  certificate it signed are served) or the explicit
  `allow_unauthenticated = true`, which lets every local user control the
  engine.  TLS 1.3 is on with `tls_cert` and `tls_key`; without it, on an
  address that is not loopback the token crosses the network in clear text.
* **A writer of the store** (its user, or root) controls what that engine
  runs: fs-verity makes accidental or low-privilege changes fail, it is no
  defence against whoever owns the store.  At every start by the engine the
  stored manifest is hashed against the image id and the layer images are
  held to the digests it states ([STORAGE.md](STORAGE.md)); where the store
  has fs-verity and the image was made from a digest or has an accepted
  signature the chain is held by default, to the digest the engine recorded
  where the manifest states none (a writer who edits the record and the
  image together is not caught); with `--security-opt verity=enforce` or
  `[storage] composefs_digests = "require"` an image without those digests
  is refused, so the image, its record and the bundle cannot be changed
  together and believed.  The writable layer of a container is outside
  the chain in every mode and the engine never mounts it as a lower
  layer: a writer of the store can change what a container sees there,
  and `run --rm` by digest starts from the image alone.
* **A client of the API** that can connect is an administrator of the
  engine: there are no per-user permissions. The REST and CRI frontends are
  separate confined processes that decode requests and call the engine over
  its private socket; they have no access to the store or the credentials.

## The peer-to-peer swarm

`velarx-p2p` is off unless it is started and named as a source.  libp2p (TCP)
carries membership, discovery and announcements; QUIC (UDP) carries all the
data.  Admission is the boundary: a node without the swarm key or a valid
certificate is refused before anything is served, and the members are trusted
not to misbehave (there are no rate limits, quotas or caps against a member;
one that misbehaves is removed by revocation, or by a new key).  Everything a
peer sends is still checked by digest, since a store can be damaged, and the
service is confined (Landlock, seccomp, no capabilities, no exec): a peer can
make a pull slower, not wrong, and cannot run anything on the node.  Who is a
member:

* **The swarm key** (the default).  The libp2p transport is wrapped in a
  pre-shared key handshake and every QUIC connection proves the key before
  anything is served.  The key file must be 0600 (or
  `VELARX_P2P_SWARM_KEY`).  Whoever holds the key is a full member: there is
  no per-node credential.  The identity file (`identity_path`) keeps a node
  the same peer across restarts.  Removing one node means a new key on every node and a restart of all.
* **A certificate authority** (`ca_path` and `certificate_path`,
  `velarx-p2p ca ...`).  A node's certificate is an X.509 certificate for the
  ed25519 key of its identity file (so for its peer id) with a name, an
  optional zone and a role (`both`, `serve`, `pull`).  QUIC is mutual TLS: a
  peer without a valid certificate fails in the handshake, before any
  stream; on libp2p the certificates are exchanged after Noise and must be for
  the peer id Noise proved.  There is no fallback to the swarm key, which may
  still be set as an outer layer of the TCP transport only.  The checks are
  the chain to one of the authorities of `ca_path` (several at once: that is
  how an authority is replaced), validity, revocation, `allow_names` and
  `allow_peers`, and the role (a `serve` node is not served, a `pull` node is
  not asked for data).  A refusal is a typed error, counted
  (`admission_refused` of `velarx-p2p status`) and logged.  A node whose own certificate is for another key, expired,
  or not signed by its `ca_path` does not start.
  * **The key of the authority** is made by `ca init` on the operator's
    machine and stays there: no setting names it, so a compromised node can
    neither sign nor revoke.
  * **Revocation** is by peer id: `ca revoke` signs a list of every peer
    revoked so far, with a number that only grows.  A node reads
    `revocation_path` when it changes, and two admitted nodes hand each other
    their whole lists: a newer list signed by one of the node's authorities is
    adopted, in memory only, so every node's file must still get every list
    (the file is what survives a restart).  A revoked peer is refused at once
    and its connections are closed at the next sweep (`ca_sweep_secs`, 10 s),
    which also cuts off expired certificates.  A revoked key does not come
    back unless the authority signs a newer list without it (a node that
    adopts such a list warns): a new key needs a new certificate.  The
    number is what orders the lists, so an authority whose state was rolled
    back signs numbers that nodes already hold, and the nodes ignore those
    lists: keep the state of the authority (the directory of `ca init`)
    durable.  A list that is set and cannot
    be read or is not valid stops the start; one that cannot be read later
    keeps the last good list (a warning).  `revocation_max_age_secs` (0: off)
    makes the node admit nobody new when the file was not read for that long
    (fail closed; a file with an invalid list does not count as read).
  * **Rotation**: certificates are short (`ca sign --days`, 30 by default)
    and renewed by signing again; the certificate and `ca_path` files are read
    again when they change, with no restart.  A node whose certificate
    expired is refused by the others and disconnected at their next sweep;
    it never falls back to anything weaker.
* **A digest is the capability.**  One swarm is one trust domain, with the
  key and with an authority, and a member is trusted as another process of
  the node is: it may ask for anything, and it is served every object the
  node holds, in its store or in its read-only stores, that it names by
  digest (a file by its fs-verity digest, a chunk, the index of a layer, a
  manifest, an index, a configuration, a startup profile), whatever brought
  it: a pull with credentials or without, a build, a commit.  There is no
  per-image or per-layer rule.  What keeps an image to the nodes that have
  it is that its digests are not known (a node that sets `serve_names`
  tells a member which digest a name and tag has, to a member that guesses
  the name: it is off by default): the fs-verity digest of a file and
  the digest of a chunk or a layer are known to whoever has the content, its
  manifest or its table of contents, and the digest of a manifest to whoever
  was given it.  A member learns a digest when a pull asks the peers for it
  (with credentials or not), when the image is public, when the user gives
  it, or when a node lists its images (`announce_images`).  With a manifest
  it can fetch the whole image from any node that holds it.  It can also
  test whether a node holds a digest it knows, in a probe or in the filter
  of the layers (`advertise_layers`, on by default, which is not a list), and
  so learn what the node pulled.  Certificates say who a node is, not what it
  may see.  **Do not put nodes of different trust in one swarm**: an image
  that must not reach every member needs a swarm of its own, or a node that
  does not run `velarx-p2p` (with an authority, a `pull` certificate: the
  node asks and is not asked).  Everything a member sends is still checked on
  the node that receives it, as what any source sends.  A node that pulls
  through the peers also gives them the files it has staged so far (each
  checked by its chunk digests and its fs-verity name, and by the asker
  again), before the layer is complete and in the store, and the layer is
  told in the filter from the first file.
* **The peer layer**: wrong bytes are refused by digest.  Every dial goes
  through one filter that refuses addresses that can
  never be a peer's: loopback, link-local, multicast, reserved addresses and
  the node's own interfaces; private ranges
  are allowed (`dial_allow` lets through, the bootstrap peers are exempt).  The
  overlay network is a process of its own (`velarx-p2p overlay`), a node of a
  swarm of its own (the same key or authority, its own identity and port, no
  content), and the process that talks to peers about layers has no
  capability.  A subnet that two peers claim is routed to neither.  The
  kernel forwards between the containers of a node, and each host veth has a
  strict reverse-path filter (`rp_filter`) so that a container cannot send
  with another one's address; it holds when `net.ipv4.conf.all.rp_filter` is
  0 or 1 (the larger of the two settings applies, and 2 is loose).  A
  container name resolves to the container of the first peer that claimed it,
  as the node heard them, for as long as that peer claims it (a node that
  starts when both claim it takes the smaller container id), the log tells of
  the collision, and `name.<peer id>` reaches the container of one peer.
* With `mdns = true` the node announces itself on the local network.

## Denial of service

Bounded: the size of what a pull writes and holds in memory, decompression,
the entries and names of an archive, the number of tasks of
a pull worker, the datagrams of the notify socket.  Not bounded: what a
container itself does within its cgroup limits, and the load a trusted client
of the API can cause.

## A store without fs-verity

Every file is still checked once before it is named: the engine computes its
fs-verity digest (and its content digest where that is what is known) as it
copies or commits it, so the objects are the same as in a store with
fs-verity.  What is lost is the kernel's check at every read: nothing keeps
a file from changing after that, the overlay does not check what a container
reads, and the store's integrity rests on its permissions ("A writer of the
store").  A file of the staging of a lazy pull, written by a fetcher and not
yet in the store, is hashed on the descriptor that is served each time it is
opened (by the FUSE file system, and when it is copied out of the image) and
once more when the completion commits it.

Where the kernel measures nothing, a file is named unread in two cases only:
a file the engine wrote itself and hashed as it was written (the digest is
the one a replay proved), and a file the engine verified and handed over (it
read it before).  A producer that kept a descriptor open for writing can
change the second after that read, as it can change any file linked after one
check; a file of another producer with a replay's digest is read and compared
like any other.  With `fsverity_require` nothing is named without the
kernel's measure, and an object of the store that the kernel does not measure
is an error, not a file reported as linked.

## Configuration choices that lower the guarantees

| Setting | Effect |
| --- | --- |
| `[storage] fsverity = false` or a file system without it | no kernel re-check of files; integrity relies on permissions |
| `[storage] composefs_digests = "check"` (the default) | a manifest without the digests of the EROFS images of its layers is accepted and its layers are held against their records; so is a manifest whose list has no digest of the EROFS image Velarx makes (another writer's, or one that was edited: nothing tells them apart, and the other writers' values in a list are ignored), which before failed the pull. A list that has Velarx's digest is always checked. `"require"`, and `--security-opt verity=enforce` for one container, make the start strict (see "A writer of the store") |
| `[storage] verity_chain = "auto"` (the default) | the chain held by default covers changes to the **files** of the store (corruption, a writer limited to the object and layer files); it is no defence against a writer of the database, who can clear `sealed`, change the digest recorded for a layer or set `verity=off` on a container: only the node's `[storage] composefs_digests = "require"`, in a configuration file outside the store, holds against that.  `verity_chain = "require"` refuses a start that cannot be held |
| `[storage] verity_chain = "off"` or `--security-opt verity=off` | the chain of trust is not held by default (the digest or signature of the image down to its files, where the store has fs-verity): an EROFS image replaced by a copy without fs-verity is mounted unmeasured; refused where the digests or signatures are required |
| `[storage] driver = "vfs"` | fs-verity is checked **when a layer is pulled only** (`VerityEnforcement::PullOnly`): the root file system of a container is a plain copy of the layers, whose files carry no digest, so nothing holds them to one while the container runs, and no kernel `verity=` or FUSE open check exists for it. The copy is private to the container (a directory of its bundle, which only the engine's user can write, opened without following a link and mounted `nodev`), so the exposure is the integrity of the store between the pull and the copy: the objects are checked against the digests at the pull, and where the store has fs-verity each object that has it is measured again as it is copied (an ioctl: the kernel keeps the digest), so one replaced by a file with another digest is refused, and with `fsverity_require` one without fs-verity is refused too; on a file system without fs-verity (XFS, the reflink case) an object replaced by something that can write the store, before a copy is made, is copied as it is (`system check` measures them again unless `--quick`); the copy itself carries no fs-verity (a reflink does not carry it over). The tables of contents the copies are made from (`vfs/tocs`) are in the same store, written atomically, and `system check` compares each with the layer's record (`toc_differs`, made again by `--repair`). Where SELinux is on, the copy gets the container's file label when it is made (no mount labels it, as an overlay's `context=` does), and the labels of the image (`security.selinux`) are never set. A copy is made from the objects and the tables of contents directly: there is no second tree in the store (no directory of a layer, none for a user namespace) that could differ from them. `fsverity_require`, `composefs_digests = "require"` and `--security-opt verity=enforce` are an error with vfs (never silently weakened); `[storage] fsverity_best_effort = true` accepts them as the checks at pull and nothing more, and `info` says "checked at pull only". The chain of trust of a start (the manifest, the layer digests the monitor holds the images to) is not run, since there are no images to hold. The copy gets the owners of the image translated by the container's mapping: a process that may chown to any id (root, or the rootless engine in its user namespace) writes it, and an image whose owners the mapping does not cover is refused, never given other ids; no hard link of an object is made, since the owner would change the shared inode |
| `[storage] vfs_ignore_chown_errors = true` | the files of a container of the vfs driver are all owned by the user of the engine where it may not give them the image's owners, so a container that relies on the owners of its files (a service that checks the owner of its configuration) sees none of them |
| `[storage] fsverity_best_effort = true` | a driver that checks fs-verity at pull only (vfs) is run with the settings that enforce it at run time: the pull is strict, and nothing is checked after it |
| `[api] allow_unauthenticated` | an API without authentication on its TCP port (a loopback port unless another address is named) |
| starting `velarx-p2p`, `mdns` (the settings of the p2p source) | every object of the store is served by digest to the holders of the swarm key, or the nodes with a certificate of the authority, and the pulls tell them the digests they ask for |
| `ca_path` and `certificate_path` (the settings of the p2p source) | admission by certificates instead of the shared key; `private_key_path` may be left out; the key of the authority (`velarx-p2p ca init`) is the root of trust of the swarm and must stay off the nodes; the revocation list and the sweep decide how fast a node is removed |
| `allow_names`, `allow_peers`, `revocation_max_age_secs` (the settings of the p2p source) | who of the authority's nodes is admitted at all, and when a stale revocation list stops admissions |
| `announce_images = true` (the settings of the p2p source) | the node lists all its images with their names, and publishes its layers in the DHT: every member, and anyone with the swarm key, can walk and fetch everything the node holds; off (the default), only the digests a peer already knows can be asked for or tested |
| `advertise_layers = false` (the settings of the p2p source; on by default) | the node tells no filter of its layers: the peers cannot test them offline, and probe the node instead |
| `--privileged`, `--security-opt seccomp=unconfined`, host namespaces, devices | the container is as powerful as the host allows |
| a CRI container whose security context names no seccomp profile (neither the typed profile nor the deprecated path) | it runs with no seccomp filter, as the CRI API defines an empty profile; the kubelet names one (`RuntimeDefault`, or `Unconfined` when it wants none), a client that leaves it out does not. A sandbox that names none, and a container with no security context at all, keep the default profile |
| `[build] insecure_entitlements` (`network.host`, `security.insecure`) | a build step may use the host network (or a network namespace by its path, `--network=ns:PATH`) or run privileged when the request allows it too (`velarx build --allow`); the REST build routes cannot say `allow`, so there the list alone decides. The entitlements cover what a Containerfile can ask for and the network of the build; the run options of the request (`-v`, `--device`, `--cap-add`, `--security-opt`, `--pid`, `--ipc`, `--uts`, `--cgroupns`, `--userns`, on REST `volume`, `devices`, `addcaps`, `nsoptions`) are the client's choice as for `run`, need no entitlement and apply to every RUN step: with `--pid host` on an engine run as root the RUN steps, whose commands come from the untrusted Containerfile, see the processes of the host and can signal them |
| `insecure = true` of a registry in `registries.conf`, `--tls-verify=false` | the certificates of the registry, of the token endpoint it names and of the CDN it sends a blob to are not checked (the flag covers every host the registry names, not the registry alone), and each is offered the client certificate of the registry; the registry and its token endpoint are sent the credentials of the call, or else those the registry fetcher has stored for the registry, as for a verified request; plain http is allowed to the registry and its token endpoint |
| `allow-private-addresses` of a registry in `registries.conf` | the registry can make the engine send requests to local addresses (token realm, redirects, CDN). The addresses that are refused unless the registry is itself on one (every address it was reached at is) or this is set: IPv4 `0/8`, `10/8`, `100.64/10`, `127/8`, `168.63.129.16` (the host service of Azure), `169.254/16` (the metadata services), `172.16/12`, `192.0.0.0/24`, `192.0.2.0/24`, `192.168/16`, `198.18/15`, `198.51.100/24`, `203.0.113/24`, `224/4`, `240/4`; IPv6 `::`, `::1`, `100::/64`, `2001::/32`, `2001:2::/48`, `2001:db8::/32`, `fc00::/7`, `fe80::/10`, `fec0::/10`, `ff00::/8`, `64:ff9b:1::/48`, and the addresses that embed an IPv4 one that is refused (`::a.b.c.d`, `::ffff:a.b.c.d`, `::ffff:0:a.b.c.d`, `64:ff9b::/96`, `2002::/16`). The table is `crates/addr-core/src/lib.rs`. A network that runs DNS64 on the local-use prefix `64:ff9b:1::/48` must set this for its registries; NAT64 under a prefix of the operator's own cannot be recognised; and with `HTTP_PROXY` or `HTTPS_PROXY` set the proxy resolves the names, so this check does not apply to them |
| a `[[registry.mirror]]` of `registries.conf` | the mirror is asked before the registry and sees which image is pulled; what it serves is held to the digest like the registry's (for a mirror for digests only, which is asked by the digest and never by a tag, a mismatch skips that mirror only). It is insecure by its own entry only, and may reach private addresses if the block of its own location or the block that lists it says so (`allow-private-addresses`; the block of a registry that does not list it gives it nothing). The credentials of `--creds` go to the endpoints on the host that was named and to its token endpoint, never to a mirror on another host nor to a realm such a mirror names, nor to a registry a `location` moved to another host; those have what is stored for their own host. A prefix ends at a component, so `example.com` governs no registry on a port |
| `[storage] driver = "varlink"` with a service the administrator does not trust | the service makes the files every container of the store runs on, sees what is pulled, and as root is root; the engine checks what it can ("A storage service") and nothing holds a running container's files to a digest. The socket is checked to be the engine's user's or root's, not that the program behind it is the one expected (`name` helps) |
| `additional_image_stores` | other stores are trusted for the files they hold and for their database; nothing is written to them, whatever their permissions (the database is opened `immutable=1`), and a store whose owner has not closed it cleanly is not used |

## How this is checked

The properties above are exercised by the unit and integration tests of the
packages named, the end-to-end scripts under `tests/e2e` (confinement of the
fetcher, the pull workers, the user namespace tree), and the fuzz targets in
`fuzz/`.  The lint tests in `src/testing.rs` check the rules about `unsafe`.
This document is reviewed with every change to a privileged path of the table
above.
