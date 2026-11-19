<!-- SPDX-License-Identifier: Apache-2.0 -->
# Velarx

Velarx is a container engine for Linux written in Rust, fast and secure,
with a chain of trust. It runs containers as root or rootless.

The name is coined from Latin *velox* ("swift") and *arx* ("citadel",
fortress); it is pronounced VEL-arks.

It is experimental software: nothing is compatible between versions, so after
an upgrade start from an empty store (`/var/lib/velarx`, or
`~/.local/share/velarx` rootless).

* **Chain of trust.** A signature policy (`policy.json`, sigstore or GPG)
  covers the manifest, the manifest's digests cover the configuration and
  the layers, and every file is checked against its digest and stored by its
  fs-verity digest. Where the file system has fs-verity, the kernel checks
  the files on every read and each start checks the layer images against the
  manifest.
* **Lazy pulls.** `--lazy` fetches only the table of contents of a
  zstd:chunked image; the files are fetched when a container reads them.
* **Peer-to-peer layer sharing.** The optional `velarx-p2p` service lets nodes
  pull layers from each other before asking the registry; what a peer sends
  is checked like what a registry sends.
* **Confinement.** The helpers that parse what the network sends (pull
  workers, fetchers) run under Landlock and seccomp.
* **No daemon needed.** `velarx` runs each command in its own process;
  `velarx varlink` is an optional engine service.
* **Interfaces.** A REST API for existing podman and Docker clients
  (`velarx-api`), a Kubernetes CRI server (`velarx-cri`) and `play`, `down`,
  `generate` and `apply` of Kubernetes YAML (`velarx-kube`).

## Quick start

```sh
velarx image pull docker.io/library/alpine:latest
velarx run --rm alpine echo hello
velarx container create --name box alpine sleep 3600
velarx container start box
velarx container exec -it box sh
```

Pull and run an image lazily. It must be zstd:chunked with the fs-verity
digest of every file, as `velarx image push --compression-format zstd:chunked`
writes it (a zstd:chunked layer is only ever pulled through its table of
contents, lazily or not, and one that cannot be is refused):

```sh
velarx image pull --lazy registry.example/app:chunked
velarx run --lazy registry.example/app:chunked
```

A registry that does not serve range requests gives the blob whole, and the
files are still those of the table. If a layer does not qualify, the pull
fails and says which layer and why.

Serve the REST API:

```sh
velarx-api &
```

With systemd, `systemctl --user enable --now velarx-engine.socket
velarx-api.socket` starts the engine and the API on the first request.
`velarx --help` lists the commands; the man pages are made by `make man`.

## Building and installing

You need Rust 1.99 (pinned in `rust-toolchain.toml`; use rustup where the
distribution has an older one), `pkg-config`, and the development packages of
sqlite, zstd and openssl, plus `protoc` for `velarx-cri`. On Fedora:

```sh
sudo dnf install git make gcc pkgconf-pkg-config sqlite-devel \
    libzstd-devel openssl-devel protobuf-compiler rust cargo
make
make man licenses-binary
sudo make install-files PREFIX=/usr
```

`make help` lists the targets. `make` builds every program (`velarx-cri`
only when `protoc` is installed):

| Binary | Role |
| --- | --- |
| `velarx` | the engine and the command line; `velarx varlink` is the engine service |
| `velarx-client` | the command line as a thin client of the engine service |
| `velarx-monitor` | the process that owns one container |
| `velarx-registry` | the confined process that talks to registries, started by the engine |
| `velarx-dir` | the fetcher of a directory content source, started by the engine |
| `velarx-api` | the REST API as a frontend of the engine |
| `velarx-p2p` | the peer-to-peer service |
| `velarx-kube` | `play`, `down`, `generate` and `apply` of Kubernetes YAML |
| `velarx-cri` | the Kubernetes CRI server |

## Requirements

* Linux on x86_64 with Linux 7.3 or later, cgroup v2, EROFS, overlayfs and
  Landlock. The tests run on Fedora 44; other distributions are untested and
  aarch64 is unsupported.
* crun 1.30 or later on `PATH`.
* Rootless: `pasta` 2026_10_02 or later (package `passt`), `newuidmap` and
  `newgidmap` with sub ids, and `/dev/fuse`.
* systemd is optional; without it containers run without scopes and resource
  limits are refused.
* Optional: a file system with fs-verity (ext4, btrfs, f2fs).

Velarx reads its own configuration only: `config.toml`
([config.toml.example](config.toml.example)) and, in the formats of
containers-policy.json(5) and containers-registries.conf(5), `policy.json`
and `registries.conf` in `/etc/velarx` or `~/.config/velarx`.
It never reads `/etc/containers`. Without a `policy.json` every image is
accepted and no signature is verified.

## Peer-to-peer

As root: create a swarm key once, copy it to every node, write
`/etc/velarx/p2p.toml` ([crates/p2p/p2p.toml.example](crates/p2p/p2p.toml.example)
has every setting) and start the service, or enable `velarx-p2p.service`:

```sh
velarx-p2p generate-key /etc/velarx/swarm.key
```

```toml
private_key_path = "/etc/velarx/swarm.key"
listen_addresses = ["/ip4/<lan-ip>/tcp/4001"]   # the default is the loopback
bootstrap_peers = ["/ip4/<peer-ip>/tcp/4001/p2p/<peer-id>"]
```

```sh
velarx-p2p &
velarx p2p status
```

The data goes over QUIC on the UDP port of the same number: open TCP and
UDP 4001 between the nodes. Then add the service as a content source in
`config.toml`:

```toml
[[sources.external]]
name = "peers"
socket = "/run/velarx/services/p2p-fetcher.sock"
peer = true

[pull]
sources = ["peers", "registry"]
```

Nothing listens on the network until you set `listen_addresses`. See
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) for what a member of a swarm can
do.

## Documentation

* `interfaces/*.varlink`: the varlink interfaces.
* [docs/STORAGE.md](docs/STORAGE.md): the store and its guarantees.
* [docs/SIGNING.md](docs/SIGNING.md): signed images.
* [docs/USERNS.md](docs/USERNS.md): user namespaces and id mappings.
* [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md): what is protected and from whom.
* [docs/CRI.md](docs/CRI.md): the CRI server.
* [CHANGELOG.md](CHANGELOG.md): what changed in each release.

## License

Velarx is licensed under the [Apache License, version 2.0](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to build, test and send a
change. Contributions are accepted under the license above with the
[Developer Certificate of Origin](https://developercertificate.org/): sign
your commits with `git commit -s`.
