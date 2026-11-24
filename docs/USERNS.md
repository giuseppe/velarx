<!-- SPDX-License-Identifier: Apache-2.0 -->
# User namespaces, id mappings and volumes

How a container sees its users and its files, and how to choose.  The
options are `--userns`, `--uidmap`, `-v ...:U` and `:idmap`.

## Two kinds of daemon

* **root**: the daemon runs in the initial user namespace.  The ids of a
  mapping are host ids.  It uses the host's directories (`/var/lib/velarx`,
  `/run/velarx`, `/etc/velarx/config.toml`), not those of `HOME` or
  `XDG_*` (which `sudo` keeps).
* **rootless**: the daemon, and the engine of every command that has no
  daemon, put themselves in a user namespace in which they are root: `0` is
  the user, `1..N` the sub ids of `/etc/subuid` and `/etc/subgid` (set up
  with `newuidmap` and `newgidmap`, which must succeed; with no sub ids listed
  for the user only `0` is mapped).  Every
  container is a child of that namespace, so **the ids of a mapping are ids
  of the daemon's namespace**: `--uidmap 0:1:1000` maps the container's root
  to the first sub id, not to the host uid 1.  There is one such namespace
  per user and boot (below).

## The user namespace of the rootless user

All the rootless processes of a store live in **one user namespace and one
mount namespace of it** per user and boot, so that a command can join the
namespaces of a container (`--network container:X`, `--pid`, pods, `cp`,
the bridge networks).  Nothing holds them but the processes that live in
them (the monitors, the engine service, the helpers): there is no pause
process.  A command joins them with `setns` before it has a thread; which
namespaces they are and which processes hold them is recorded in the
store's database (`namespaces`, `holders`), checked by device, inode and
file handle, so a recycled pid or inode is never joined.  When no holder
lives, the next command makes a new pair.

The mounts of the host reach the namespace (`/` is made `rslave`): a disk
mounted on the host after the namespace was made is seen by the commands
that join it later, and an unmount on the host is seen too; what a process
of the namespace mounts stays in it.

Not supported: `velarx container mount` of a rootless container (a mount
ends with the last process of its mount namespace).  The network namespace
of a container is held by the descriptors of its monitor, not bind mounted;
that of the rootless bridge networks by `velarx netns-holder`, started with
the first container on a bridge network and stopped with the last.

A container with no `--userns` (`host`) runs in the namespace of the daemon:
as root in the initial one; rootless, as root of the daemon's namespace
(`/proc/self/uid_map` shows `0 UID 1`, `1 SUBUID N`).

## `--userns`

| value | the container sees |
|---|---|
| (none), `host` | the namespace of the daemon |
| `auto[:size=N,uidmapping=C:H:S,gidmapping=C:H:S]` | a new namespace with `size` ids (default: the highest id the image uses plus one, at least `auto_min_size` = 1024, at most `auto_max_size` = 65536), taken from the first free ids of the pool |
| `private` | like `auto:size=allocation_size` (65536) |
| `keep-id[:uid=N,gid=N,size=N]` | rootless only: the user keeps its number: `0 1 U`, `U 0 1`, `U+1 U+1 S-U` (`U` the uid, `S` the sub ids; the numbers of the default user are in `/proc/self/uid_map`) |
| `nomap` | rootless only: all the sub ids from `0`, the user is not mapped |
| `container:ID` | the user namespace of the running container `ID` |
| `ns:/proc/PID/ns/user` | the user namespace of a process |

`uidmapping=` and `gidmapping=` of `auto` (`CONTAINER:[@]PARENT[:SIZE]`) are
used exactly as given: the automatic ranges take other ids, but a mapping
asked for by hand may use parent ids that another container already holds
(podman does the same: it is a forced mapping).

`--uidmap`/`--gidmap` (`[+ug]CONTAINER:[@]PARENT[:SIZE]`, repeatable, several
triples per value) give the mappings by hand and imply `private`; one of them
alone implies the other.  A leading `+` removes what the earlier entries map
at those ids; `@ID` is an id of the outside of the daemon's namespace.
Rootless, `--uidmap +0:@UID:1` maps the user to `0` and all the sub ids above
it.  `--subuidname`/`--subgidname` (root) use the ranges of that user of
`/etc/subuid`.  `--userns` and `--uidmap` exclude each other.

### Where the ids of `auto` come from

* root: the `[userns] uid_ranges`/`gid_ranges` of the configuration, or, when
  there are none, the entry of `auto_user` (default `containers`) in
  `/etc/subuid` and `/etc/subgid`.  Add `containers:786432:65536`.
* rootless: the sub ids of the daemon's namespace (`1..N`).

The range is never one that another container uses: the ids in use are those
of the mappings of every container in the database (explicit ones included),
the ranges reserved by an allocation, and the containers that are
being created.  Nothing is stored apart from the container, so removing a
container frees its range; concurrent creates get disjoint ranges.

## The image under a mapping

Layers are never copied.  Their files are the objects of the store, named by
their fs-verity digest in `<store>/objects`, and the root file system is made
of EROFS images of the metadata.  As root, the
kernel mounts the image of each layer (idmapped to the user namespace of the
container, if it has one, together with the objects) and checks the digest of
every file it opens.  Where the kernel does not mount them (rootless, or the
image still being fetched) the image server of the mount serves the EROFS images
of the layers by FUSE, a directory per layer under an overlay in the user namespace, and
the owners of the files are translated in
the server: the owner `c` of a file is shown as the
parent id of the container id `c`.  An owner that
the mapping does not cover is not given a wrong id: the container does not
start (`image has files owned by uid 33, which is not mapped`; the storage driver
refuses it at the create already) unless
`[userns] squash_unmapped_owners = true`, which shows such files as owned by
the root of the container.  This is also what happens rootless without
`newuidmap`: an image whose files have other owners needs sub ids.  The upper
directory of the overlay belongs to the root of the container.

## Volumes

Volumes, bind mounts and their options (`ro`, `z`/`Z`, `U`, `idmap`,
`nocopy`...) are accepted; `:idmap` with `U` is refused (the ids
would be mapped twice).

* **Image mounts**: `--mount type=image,source=IMAGE,destination=/path[,subpath=/dir]`
  mounts the merged file system of the image, read only, with the ids of the
  container; the sub path is looked up inside the image (a link cannot lead
  out of it).  An image that a container mounts cannot be removed.
