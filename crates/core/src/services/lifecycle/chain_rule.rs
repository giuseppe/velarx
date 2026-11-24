// SPDX-License-Identifier: Apache-2.0
//! Which chain of trust a start holds an image to, from what is known of the
//! image and of the node.  The chain from the digest (or the signature) to
//! the files is held by default where the file system supports it and the
//! image gives a root of trust; what the node and the container ask for by
//! name (`composefs_digests = "require"`, `--security-opt verity=enforce`)
//! is the manifest's own digests, as before.

use crate::services::image::seal::Enforcing;

/// What is known of one image of a container when it starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Facts {
    /// What the node and the container ask for by name.
    pub asked: Enforcing,
    /// `[storage] verity_chain = "require"`: an image that cannot be held is
    /// refused, not run.
    pub require: bool,
    /// Why the chain is not held by default: `--security-opt verity=off`,
    /// or `[storage] verity_chain = "off"` (refused where the node or the
    /// container asks for the manifest's digests or a signature: never set
    /// with `asked`).
    pub off: Option<&'static str>,
    /// The driver holds the images and the files to their digests while a
    /// container runs (not one that checks them at pull only).
    pub driver: bool,
    /// `[storage] fsverity` is not off: the store seals its files.
    pub fsverity: bool,
    /// The image is all in the store (not a lazy pull in progress).
    pub complete: bool,
    /// Every layer of the image was made with fs-verity (`layers.sealed`):
    /// the store had it, so a layer that cannot be measured now is refused.
    pub sealed: bool,
    /// The container (or the image mount) was made from a digest, which the
    /// image is hashed back to again.
    pub digest: bool,
    /// The signature policy of now accepts the signatures the pull kept.
    pub signed: bool,
}

/// What a start holds an image to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    /// Nothing, and why.
    Off(&'static str),
    /// The digests of the manifest, strictly, because it was asked for (the
    /// reason is that of [`Enforcing`]).
    Manifest(Enforcing),
    /// The digests the engine recorded for the layers, from the root of
    /// trust the image has.
    Record(Root),
    /// The chain cannot be held and the node requires it: the start is
    /// refused, with why.
    Refuse(&'static str),
}

/// What the chain of an image by default hangs from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Root {
    /// The digest the container was made from.
    Digest,
    /// The signature the policy accepts.
    Signature,
}

/// The mode of an image.  The manifest's digests asked for by name are held
/// whatever else is known (their own checks refuse what they cannot hold);
/// by default the chain is held when every layer can be, and the image has a
/// root of trust: a digest, else an accepted signature.  An image named by a
/// tag that no signature vouches for is held to nothing.
pub(super) fn mode(f: &Facts) -> Mode {
    if f.asked != Enforcing::No {
        return Mode::Manifest(f.asked);
    }
    match by_default(f) {
        Mode::Off(why) if f.require => Mode::Refuse(why),
        held => held,
    }
}

fn by_default(f: &Facts) -> Mode {
    if let Some(why) = f.off {
        return Mode::Off(why);
    }
    if !f.driver {
        return Mode::Off("the driver checks the digests at pull");
    }
    if !f.fsverity {
        return Mode::Off("fs-verity is off");
    }
    if !f.complete {
        return Mode::Off("lazy image");
    }
    if !f.sealed {
        return Mode::Off("layer made without fs-verity");
    }
    match (f.digest, f.signed) {
        (true, _) => Mode::Record(Root::Digest),
        (false, true) => Mode::Record(Root::Signature),
        (false, false) => Mode::Off("no digest or signature"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: Facts = Facts {
        asked: Enforcing::No,
        require: false,
        off: None,
        driver: true,
        fsverity: true,
        complete: true,
        sealed: true,
        digest: true,
        signed: true,
    };

    /// Every combination of the facts: only what was asked for by name
    /// holds the manifest's digests; the rest holds the record from a root
    /// of trust when the file system, the driver, the layers and the image
    /// all allow it; else nothing, for the first reason that applies.
    #[test]
    fn the_rule_holds_the_chain_exactly_where_it_can() {
        for asked in [Enforcing::No, Enforcing::Node, Enforcing::Container] {
            for bits in 0..256u32 {
                let b = |n: u32| bits & (1 << n) != 0;
                let f = Facts {
                    asked,
                    require: b(7),
                    off: b(6).then_some("verity=off"),
                    driver: b(0),
                    fsverity: b(1),
                    complete: b(2),
                    sealed: b(3),
                    digest: b(4),
                    signed: b(5),
                };
                let want = if asked != Enforcing::No {
                    Mode::Manifest(asked)
                } else if f.off.is_some() {
                    Mode::Off("verity=off")
                } else if !f.driver {
                    Mode::Off("the driver checks the digests at pull")
                } else if !f.fsverity {
                    Mode::Off("fs-verity is off")
                } else if !f.complete {
                    Mode::Off("lazy image")
                } else if !f.sealed {
                    Mode::Off("layer made without fs-verity")
                } else if f.digest {
                    Mode::Record(Root::Digest)
                } else if f.signed {
                    Mode::Record(Root::Signature)
                } else {
                    Mode::Off("no digest or signature")
                };
                let want = match want {
                    Mode::Off(why) if f.require => Mode::Refuse(why),
                    held => held,
                };
                assert_eq!(mode(&f), want, "{f:?}");
            }
        }
    }

    /// The rows of the table, one by one.
    #[test]
    fn each_row_of_the_table() {
        assert_eq!(mode(&ALL), Mode::Record(Root::Digest));
        let by_tag = Facts {
            digest: false,
            ..ALL
        };
        assert_eq!(mode(&by_tag), Mode::Record(Root::Signature));
        let unsigned = Facts {
            signed: false,
            ..by_tag
        };
        assert_eq!(mode(&unsigned), Mode::Off("no digest or signature"));
        let no_fsverity = Facts {
            fsverity: false,
            ..ALL
        };
        assert_eq!(mode(&no_fsverity), Mode::Off("fs-verity is off"));
        let required = Facts {
            require: true,
            ..no_fsverity
        };
        assert_eq!(mode(&required), Mode::Refuse("fs-verity is off"));
        let lazy = Facts {
            complete: false,
            ..ALL
        };
        assert_eq!(mode(&lazy), Mode::Off("lazy image"));
        let old = Facts {
            sealed: false,
            ..ALL
        };
        assert_eq!(mode(&old), Mode::Off("layer made without fs-verity"));
        let pull_only = Facts {
            driver: false,
            ..ALL
        };
        assert_eq!(
            mode(&pull_only),
            Mode::Off("the driver checks the digests at pull")
        );
        let asked = Facts {
            asked: Enforcing::Container,
            complete: false,
            ..by_tag
        };
        assert_eq!(mode(&asked), Mode::Manifest(Enforcing::Container));
        let off = Facts {
            off: Some("--security-opt verity=off"),
            ..ALL
        };
        assert_eq!(mode(&off), Mode::Off("--security-opt verity=off"));
    }
}
