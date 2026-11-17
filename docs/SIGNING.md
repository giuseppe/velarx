<!-- SPDX-License-Identifier: Apache-2.0 -->
# Signed images with Velarx

Signing the images you publish and requiring signatures on the images you
run.  The examples use a plain HTTP registry on `localhost:5077` and two
rootless users, a publisher and a consumer.

## What a signature gives you, and what not

Velarx signs and verifies with **sigstore keys**, the format of `cosign
generate-key-pair` and `skopeo generate-sigstore-key`: an ECDSA P-256 key
pair, the private key encrypted with a passphrase.

What `push --sign-by-sigstore-private-key` makes is a signature over the
**manifest** of the image (its digest, and the name it is published under).
The manifest names the configuration and every layer by digest, so one
signature covers the whole image: change a layer, the configuration or the
manifest and the digest is another one, which the signature does not name.
The manifest of an image Velarx made also states, for each layer, the
fs-verity digest of the layer's EROFS image (`io.containers.composefs.digest`,
composefs digests), so the signature
covers those digests too, and a node that checks them at the start of a
container ties the files it runs to the signature.

What it does not give you, as [THREAT-MODEL.md](THREAT-MODEL.md) says:

* **No keyless signing.** `--sign-by-sigstore` (Fulcio, Rekor) is refused by
  name, as are `--sign-by-sq-fingerprint` and image encryption
  (`--encryption-key`, `--decryption-key`).  A verifier can still check.
  Velarx signs with a sigstore key, or with GPG
  ([below](#gpg-signatures)); the policy can also hold the certificate kinds
  of `sigstoreSigned` (`fulcio`, `rekorPublicKeyPath`, `pki`) when written
  by hand, so an image signed keyless by `cosign` is verified, and this
  document uses keys only.
* **No signing of a sha512 image yet.** A push that signs an image whose
  manifest digest is a sha512 is refused before anything is pushed
  (`signing an image with a sha512 manifest digest is not supported yet`):
  the attachment tag of a signature is the text of the digest, and
  `sha512-` and 128 digits do not fit a tag.
* **Not "this is the newest".** A signature says that this manifest was
  signed.  Whoever controls the registry (or the node's store) can put back an
  older manifest, correctly signed, under the same name.
* **No revocation.** A key that leaked stays valid for every image it signed
  until the consumers drop it from their policy (key rotation).
* **No check of the content of a policy-accepted image.** Where the policy
  needs no signature (the default policy accepts everything), nothing is
  verified, and Velarx says nothing about it.

## Generate a key pair

`velarx image generate-sigstore-key` runs in the command, with no engine and
no service, and does what `skopeo generate-sigstore-key` does: it writes
`PREFIX.private` (the encrypted private key, mode 0600) and `PREFIX.pub` (the
public key, mode 0644).  It never overwrites a file, and it prints only the
names it wrote.

The passphrase is read from `--passphrase-file` (its first line, as
`--sign-passphrase-file` reads it), else asked for twice on the terminal
without echo:

```console
$ velarx image generate-sigstore-key --output-prefix acme --passphrase-file passphrase.txt
Key written to "acme.private" and "acme.pub"
```

The files are the ones cosign and skopeo make and read.  The private key is
encrypted (scrypt and the NaCl secretbox): it may be kept in a secret store
as long as the passphrase is kept elsewhere.

## Build and push a signed image

An image to sign: a Containerfile built with `velarx build`.  Any image will
do, one you built, committed, imported or pulled.

```console
$ cat Containerfile
FROM localhost:5077/base/alpine:3
RUN echo "release 1.0" > /etc/acme-release
$ velarx build -t localhost:5077/acme/app:1.0 .
STEP 1/2: FROM localhost:5077/base/alpine:3
Pulling localhost:5077/base/alpine:3
Making the images of the layers (EROFS)
STEP 2/2: RUN echo "release 1.0" > /etc/acme-release
new layer compressing
new layer complete 2.5 KB
Merging the layers (EROFS)
Making the images of the layers (EROFS)
--> a9e08971b3c9
COMMIT localhost:5077/acme/app:1.0
b87c666fe32bf6c22de2a898f16c55ac585eab25e530499381d6e68c9bc0fe11
```

A push that signs needs two things: the key (`--sign-by-sigstore-private-key`
and, unless it is typed at a terminal, `--sign-passphrase-file`), and a place
for the signature.  Velarx stores a sigstore signature as an
**attachment in the registry**: an image `NAME@sha256:D` gets a second image
`NAME:sha256-D.sig` next to it.  The place is switched on in `registries.d`
(`~/.config/velarx/registries.d/*.yaml` rootless, `/etc/velarx/registries.d/`
for the system); without it:

```console
$ velarx image push --sign-by-sigstore-private-key ../keys/acme.private --sign-passphrase-file ../keys/passphrase.txt localhost:5077/acme/app:1.0
Error: registry error: Pushing signatures to a Docker Registry is not supported, and there is no applicable signature storage configured: set use-sigstore-attachments in registries.d
```

With the file (a registry or a repository can be the key of `docker:`), the
signature is made and pushed after the manifest:

```console
$ cat ~/.config/velarx/registries.d/acme.yaml
docker:
  localhost:5077:
    use-sigstore-attachments: true
$ velarx image push --sign-by-sigstore-private-key ../keys/acme.private --sign-passphrase-file ../keys/passphrase.txt localhost:5077/acme/app:1.0
Pushing the manifest
Signing
Pushed: localhost:5077/acme/app:1.0
Digest: sha256:a9e08971b3c958fd3f96f4c40cac431e3d3113a77d191be912c12738fd433a29
Blobs: 2 uploaded, 1 mounted, 0 already there
$ curl -s localhost:5077/v2/acme/app/tags/list
{"name":"acme/app","tags":["1.0","sha256-a9e08971b3c958fd3f96f4c40cac431e3d3113a77d191be912c12738fd433a29.sig"]}
```

The tag list of the repository shows the attachment next to the tag.  The
signature is over the digest the push printed.  A pusher needs the
`use-sigstore-attachments: true` line, and so does every consumer that
checks signatures from that registry (see [the consumer](#the-consumer-require-the-signature)).

## GPG signatures

`push --sign-by KEY` and `image sign --sign-by KEY IMAGE...` make GPG
signatures in containers/image's simple signing format, the ones skopeo and
podman make with `--sign-by` and that `signedBy` rules of `policy.json`
verify (the policy and the check of the consumer are those of the sections
below, with `"type": "signedBy", "keyType": "GPGKeys", "keyPath": FILE`; the
key file is the output of `gpg --export`).  They are stored not in the
registry but in the **signature storage** of `registries.d`: files
`REPOSITORY@sha256=HEX/signature-N` below the `lookaside-staging` (else
`lookaside`) directory of the registry's entry, by default
`~/.local/share/containers/sigstore` (`/var/lib/containers/sigstore` for
root), or the directory of `image sign --directory DIR`.  The consumer reads
them from the `lookaside` URL of its own `registries.d`, so that directory
is published by a web server, or copied.

The signing is done by the **`gpg` program of the user**, which Velarx runs
in the command (never in the engine or in `velarx-api`): the secret keys, the
agent and the passphrase prompt are gpg's, and Velarx reads no secret key
itself.  `--sign-passphrase-file FILE` is given to gpg for a key that has a
passphrase (loopback pinentry); the signature is over the manifest digest
and the name (its tag, or `latest`) of the image.  `image sign` signs the
manifest the registry has for the name (`docker://` is accepted), so push
first; with `push --sign-by` it is the manifest just pushed.  GPG verification
is Velarx's own (the packets are parsed in the process, OpenSSL does the
mathematics: no gpg program is needed to verify).  `--sign-by` is not
supported with `--all-tags`, for a `dir:` destination or for `manifest push`.

## Publish the public key

Give `acme.pub` to the people and machines that will check the image, by a
channel they trust: your site over TLS, a package, the configuration management
of the nodes.  Whoever can replace the file can replace the policy, so the
channel is the weak point of the scheme.  The private key and the passphrase
do not leave the publisher.

## The consumer: require the signature

The consumer's policy is `~/.config/velarx/policy.json` (rootless) or
`/etc/velarx/policy.json`.  Without one, every image is accepted and nothing
is verified: here is an image from the same registry pulled before any
policy, and removed again:

```console
$ velarx image pull localhost:5077/acme/imposter:1.0
Trying to pull localhost:5077/acme/imposter:1.0...
Merging the layers (EROFS)
Making the images of the layers (EROFS)
09edfdc0b1f23433f09d735d34d88ff0da298aa92c8d4e9747a284bcc41a53aa
$ velarx image rm localhost:5077/acme/imposter:1.0
Untagged: localhost:5077/acme/imposter:1.0
Deleted: 09edfdc0b1f23433f09d735d34d88ff0da298aa92c8d4e9747a284bcc41a53aa
```

`image trust set` writes the policy and the `registries.d` file that makes
the lookups of signatures happen, and `image trust show` shows the result.
The key file is read at every pull, so keep it where it stays (the path is
put in the policy as an absolute one):

```console
$ velarx image trust show
TRANSPORT   NAME      TYPE     ID   STORE
all         default   accept
$ velarx image trust set -t sigstoreSigned -f keys/acme.pub localhost:5077/acme
$ velarx image trust show
TRANSPORT    NAME                  TYPE             ID                                                   STORE
all          default               accept
repository   localhost:5077/acme   sigstoreSigned   /home/consumer/keys/acme.pub   (attachments)
$ cat .config/velarx/policy.json
{
  "default": [
    {
      "type": "insecureAcceptAnything"
    }
  ],
  "transports": {
    "docker": {
      "localhost:5077/acme": [
        {
          "keyPath": "/home/consumer/keys/acme.pub",
          "type": "sigstoreSigned"
        }
      ]
    }
  }
}
$ cat .config/velarx/registries.d/localhost:5077-acme.yaml
docker:
  localhost:5077/acme:
    use-sigstore-attachments: true
```

Now the three cases: the image signed by the key, an image with no signature
at all, and an image signed by another key (the `imposter`, made with a second
key pair):

```console
$ velarx image pull localhost:5077/acme/app:1.0
Trying to pull localhost:5077/acme/app:1.0...
Merging the layers (EROFS)
Making the images of the layers (EROFS)
b87c666fe32bf6c22de2a898f16c55ac585eab25e530499381d6e68c9bc0fe11
$ velarx image pull localhost:5077/acme/unsigned:1.0
Trying to pull localhost:5077/acme/unsigned:1.0...
Error: registry error: Source image rejected: a signature was required, but no signature exists
$ velarx image pull localhost:5077/acme/imposter:1.0
Trying to pull localhost:5077/acme/imposter:1.0...
Error: registry error: Source image rejected: cryptographic signature verification failed
$ velarx image list
REPOSITORY               TAG         IMAGE ID      CREATED        SIZE
localhost:5077/acme/app  1.0         b87c666fe32b  2 seconds ago  8.71 MB
```

A refused image is not stored.  The same policy can be written by hand
(`policy.json` is the format of containers-policy.json(5)); `sigstoreSigned`
takes `keyPath`, `keyPaths`, `keyData` and `keyDatas`, and `signedIdentity`
(the default is that the signature names the image's own reference).  The policy
is applied whenever an image is pulled from a registry (`pull`, and `run`,
`create` or `build` fetching one); `--signature-policy FILE` replaces the
policy for the command (not with an engine service, which has its own).  An
image loaded, imported or built is not judged then: the next section says
how its containers are.

## Require signatures for every container of a node

By default (`image_signature = "policy"`) the policy is judged when the
container is created, and not again at its starts: the `signedBy` and
`sigstoreSigned` rules for each name of the image must accept a signature
stored with it.  An image whose rules ask for no signature runs, which is
every image outside the scopes you wrote such rules for; a `reject` rule
refuses pulls only, and does not stop a container of an image already in the
store (a policy whose default is `reject` would otherwise refuse every image
built or loaded on the node).

`--security-opt signature=check` judges the **whole** policy at the create,
keeps that in the container and judges again at **every start** by the
engine (start, restart, restore, pod start), with the policy of that moment:
a signature rule must be
satisfied by a signature stored with the image, `reject` refuses (also an
image built or loaded here, under a default of `reject`), and an image the
policy accepts without a signature (`insecureAcceptAnything`) runs.  A key
dropped from the policy, or a `reject` rule added for the repository, stops
the next start of such a container.  A container made without the option is
judged at its create only.  An image without a name (no tag, asked for by
its id, never pulled) has no scope to judge: under `check` it is refused
("image has no names"), at the create and at every
start (so a container whose image lost its last tag after the create does
not start again); a container made without the option runs it.  Every name
counts: a tag, or a name the image was pulled by, `repository@digest` ones
included, also one whose tag was removed since (the policy has a scope, at
least the default, for each).

Two options require a signature instead, checked when the container is
created and at every start by the engine, with the policy of that moment (a
restart by the monitor's restart policy keeps the mounted file systems and
checks nothing again, for `check` as for `require`):

* `--security-opt signature=require` for one container;
* `[containers] image_signature = "require"` in `config.toml` for the node.

They require that a `signedBy` or `sigstoreSigned` requirement of the policy
accepted a signature for **every name** of the image, the same names `check`
judges: its tags and the names it was pulled by (an image pulled by its
digest only, and run by its id, is judged by `repository@digest`).  An image
with no name (no tag, never pulled, asked for by its id) and an image the policy accepts without a signature
(`insecureAcceptAnything`) are refused; so is an image whose scope has a
`reject` rule, with the message that the policy rejects it.  A container
can only tighten the node's value:

```console
$ velarx run --rm --security-opt signature=require localhost:5077/acme/app:1.0 cat /etc/acme-release
release 1.0
$ velarx image pull localhost:5077/base/alpine:3
Trying to pull localhost:5077/base/alpine:3...
Making the images of the layers (EROFS)
320994c3b997e2ec6433f717f153e108023c5bec8fefa8d76b83451d16d05ea8
$ velarx run --rm --security-opt signature=require localhost:5077/base/alpine:3 true
Error: image error: registry error: localhost:5077/base/alpine:3: the signature policy (/home/consumer/.config/velarx/policy.json) accepts it without a signature, and --security-opt signature=require
$ velarx run --rm --security-opt signature=bogus localhost:5077/acme/app:1.0 true
Error: invalid --security-opt signature value "bogus", must be "check" or "require"
```

With `image_signature = "require"` in the configuration of the node:

```console
$ cat .config/velarx/config.toml
[containers]
image_signature = "require"
$ velarx run --rm localhost:5077/acme/app:1.0 cat /etc/acme-release
release 1.0
$ velarx run --rm localhost:5077/base/alpine:3 true
Error: image error: registry error: localhost:5077/base/alpine:3: the signature policy (/home/consumer/.config/velarx/policy.json) accepts it without a signature, and [containers] image_signature is "require"
$ velarx run --rm --security-opt signature=check localhost:5077/acme/app:1.0 true
Error: --security-opt signature=check: [containers] image_signature is "require", a container cannot ask for less
```

The images mounted in a container (`--mount type=image`) are judged too.  The
infra image of a pod is judged too, and the pause image Velarx builds
(`localhost/velarx-pause`) has no signature: on a node that requires
signatures, or whose policy asks a signature of that name (a `default` rule
of `sigstoreSigned`, say), set `[containers] infra_image` to a signed
image.  A container made with `--rootfs` has no image and is not checked.

## Troubleshooting

| What you see | Why, and what to do |
| --- | --- |
| `Pushing signatures to a Docker Registry is not supported, and there is no applicable signature storage configured: set use-sigstore-attachments in registries.d` | Add `use-sigstore-attachments: true` for the registry. |
| `Source image rejected: a signature was required, but no signature exists` | The image has no signature (or none in the attachment of the registry: a cleaner may have deleted it). |
| `... no signature exists (registries.d sets no use-sigstore-attachments for ..., so sigstore signatures are not looked for)` | This node's registries.d does not look for the attachments of that registry: `image trust set` writes the file, or add `use-sigstore-attachments: true` by hand. |
| `Source image rejected: cryptographic signature verification failed` | There are signatures and none is by a key of the policy (an imposter, a rotated key, or a second `-f` that made the policy need both keys). |
| `Source image rejected: signature for identity "..." is not accepted` | The signature names another reference: cosign signs the repository (use `signedIdentity` `matchRepository`), or the image was signed under another tag. |
| `... the signature policy (...) accepts it without a signature, and --security-opt signature=require` (or `[containers] image_signature is "require"`) | The image is not covered by a `sigstoreSigned` or `signedBy` rule; pull it again under a policy that has one, or change the policy. |
| `composefs digest: layer 1 of N (...): its EROFS image has the fs-verity digest ..., the manifest says ... (io.containers.composefs.digest), and [storage] composefs_digests is "require"` (at a start: `... is recorded with the fs-verity digest ..., the manifest says ..., and --security-opt verity=enforce`) | The digests are required and none of the values the manifest states is that of the layer; edited or made by another writer (podman's digests are another format).  Pull it again from its publisher; if it persists the manifest is not the publisher's.  Where nothing requires the digests such a list is accepted. |
| `Error: ...: the signature policy (...) rejects it (scope ...)` | A `reject` rule of the policy applies to the name of the image, at the create or the start of a container made with `--security-opt signature=check` or `require` (or under `image_signature = "require"`). |
| `... states no EROFS digest (io.containers.composefs.digest), and [storage] composefs_digests is "require"` (or `--security-opt verity=enforce`; `states no sha256:<hex> or sha512:<hex> EROFS digest` when the annotation has only values of other writers) | The manifest is another writer's (or older Velarx's) and states none of Velarx's.  A push with a `--compression-format` other than that of its layers (`zstd:chunked` for gzip layers, `gzip` for zstd ones) writes a manifest with the digests; a push in the same compression keeps the manifest as it is.  Or set the digest check to `"check"`. |
| `composefs digest: the digests of the EROFS images are enforced and the image ... has no fs-verity` | The store is on a file system without fs-verity (or the layer image was replaced by a copy); use a store on ext4 with `-O verity`, btrfs or f2fs. |
| `crun: the EROFS image ... cannot be measured (it has no fs-verity) and the digests are enforced` | At the start: the layer image of a container made before was replaced by a file without fs-verity. |
