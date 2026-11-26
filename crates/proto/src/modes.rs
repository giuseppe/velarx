// SPDX-License-Identifier: Apache-2.0
//! The modes of a container as the request that makes it carries them:
//! the namespaces (`--pid`, `--ipc`, `--uts`, `--cgroupns`, `--userns`,
//! `--network`) and the cgroups (`--cgroups`).
//!
//! A mode is a word, or a word with an argument (`container:ID`,
//! `ns:PATH`).  Each is an enum that reads the text once, where it enters
//! (the command line, the podman API, the CRI, a pod document), and shows
//! as the same text, so the varlink wire (`string`), the stored
//! configuration and every output that names a mode are what they were
//! when the field was a `String`.  A text that is no mode is a [`ModeError`]
//! at the place that read it, not a value to compare with later;
//! [`NetworkMode`] is the exception: every text is one (a network is named
//! by any word).

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// A text that is no mode of the kind `what` names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeError {
    /// What the text was read as: `namespace`, `user namespace`, `cgroups`
    pub what: &'static str,
    /// The text
    pub text: String,
    /// What was expected
    pub expected: &'static str,
}

impl fmt::Display for ModeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid {} mode `{}`: {}",
            self.what, self.text, self.expected
        )
    }
}

impl std::error::Error for ModeError {}

/// What a mode needs to be a varlink `string`, serde text and a `FromStr`.
macro_rules! text_mode {
    ($ty:ty) => {
        impl FromStr for $ty {
            type Err = ModeError;
            fn from_str(text: &str) -> Result<Self, ModeError> {
                Self::parse(text)
            }
        }

        impl Serialize for $ty {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let text = std::borrow::Cow::<str>::deserialize(d)?;
                Self::parse(&text).map_err(serde::de::Error::custom)
            }
        }

        #[cfg(feature = "proxy")]
        impl zlink::introspect::Type for $ty {
            const TYPE: &'static zlink::idl::Type<'static> = &zlink::idl::Type::String;
        }
    };
}

/// The PID, IPC, UTS or cgroup namespace of a container (`--pid`, `--ipc`,
/// `--uts`, `--cgroupns`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum NsMode {
    /// Nothing was asked for (the empty text, or `default`): the default of
    /// the kind
    #[default]
    Default,
    /// `pod`: the namespace of the pod (podman's word; a container that is
    /// in no pod, or whose pod does not share the namespace, has none)
    Pod,
    /// `private`: a namespace of its own
    Private,
    /// `shareable`: a namespace of its own that others may join (the IPC
    /// default)
    Shareable,
    /// `none`: a namespace of its own with no `/dev/shm` (IPC only)
    Off,
    /// `host`: the namespace of the host
    Host,
    /// `container:ID`: the namespace of another container
    Container(String),
    /// `ns:/PATH`: the namespace pinned at a path
    Ns(String),
}

impl NsMode {
    /// The mode `text` is.
    pub fn parse(text: &str) -> Result<Self, ModeError> {
        Ok(match text {
            "" | "default" => Self::Default,
            "pod" => Self::Pod,
            "private" => Self::Private,
            "shareable" => Self::Shareable,
            "none" => Self::Off,
            "host" => Self::Host,
            _ => match (text.strip_prefix("container:"), text.strip_prefix("ns:")) {
                (Some(id), _) if !id.is_empty() => Self::Container(id.to_string()),
                (_, Some(path)) if path.starts_with('/') => Self::Ns(path.to_string()),
                _ => {
                    return Err(ModeError {
                        what: "namespace",
                        text: text.to_string(),
                        expected: "private, shareable, none, host, pod, container:ID or ns:/PATH",
                    })
                }
            },
        })
    }

    /// A namespace the container does not own: the host's, another
    /// container's or one at a path.
    pub fn is_joined(&self) -> bool {
        matches!(self, Self::Host | Self::Container(_) | Self::Ns(_))
    }

    /// The container whose namespace this is (`container:ID`).
    pub fn container(&self) -> Option<&str> {
        match self {
            Self::Container(id) => Some(id),
            _ => None,
        }
    }
}

impl fmt::Display for NsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => Ok(()),
            Self::Pod => f.write_str("pod"),
            Self::Private => f.write_str("private"),
            Self::Shareable => f.write_str("shareable"),
            Self::Off => f.write_str("none"),
            Self::Host => f.write_str("host"),
            Self::Container(id) => write!(f, "container:{id}"),
            Self::Ns(path) => write!(f, "ns:{path}"),
        }
    }
}

text_mode!(NsMode);

/// The user namespace of a container as `--userns` asks for it.  The options
/// of `auto` and `keep-id` (`size=N,uidmapping=...`) are for whoever knows
/// the ids of the engine; they are read there.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum UsernsChoice {
    /// `host` (also `default` and the empty text): none of its own
    #[default]
    Host,
    /// `private`: a user namespace of the configured size
    Private,
    /// `nomap`: the user is not mapped
    NoMap,
    /// `auto`, or `auto:OPTIONS`
    Auto(Option<String>),
    /// `keep-id`, or `keep-id:OPTIONS`
    KeepId(Option<String>),
    /// `ns:/PATH`: the user namespace pinned at a path
    Ns(String),
    /// `container:ID`: the user namespace of another container
    Container(String),
}

impl UsernsChoice {
    /// The choice `text` is.
    pub fn parse(text: &str) -> Result<Self, ModeError> {
        let (word, opts) = match text.split_once(':') {
            Some((w, o)) => (w, Some(o)),
            None => (text, None),
        };
        let bad = |expected| ModeError {
            what: "user namespace",
            text: text.to_string(),
            expected,
        };
        let no_opts = |c: Self| match opts {
            None => Ok(c),
            Some(_) => Err(bad("this mode takes no options")),
        };
        match word {
            "" | "default" | "host" => no_opts(Self::Host),
            "private" => no_opts(Self::Private),
            "nomap" => no_opts(Self::NoMap),
            "auto" => Ok(Self::Auto(opts.map(str::to_string))),
            "keep-id" => Ok(Self::KeepId(opts.map(str::to_string))),
            "ns" => match opts {
                Some(p) if p.starts_with('/') => Ok(Self::Ns(p.to_string())),
                _ => Err(bad("`ns:` needs the absolute path of a user namespace")),
            },
            "container" => match opts {
                Some(c) if !c.is_empty() => Ok(Self::Container(c.to_string())),
                _ => Err(bad("`container:` needs a container")),
            },
            _ => Err(bad(
                "host, private, nomap, auto, keep-id, ns:/PATH or container:ID",
            )),
        }
    }

    /// The namespace of the host: the container has none of its own.
    pub fn is_host(&self) -> bool {
        *self == Self::Host
    }

    /// The choice of podman's SpecGenerator (`userns`: `nsmode` and
    /// `value`): none for a mode it has that is not one here, an error for a
    /// value the mode does not take (the text `nsmode:value` is read as
    /// `--userns` is).
    pub fn from_spec(nsmode: &str, value: &str) -> Option<Result<Self, ModeError>> {
        Some(Ok(match nsmode {
            // (podman ignores the value of these)
            "" | "default" | "host" => Self::Host,
            "private" if value.is_empty() => Self::Private,
            "no-map" if value.is_empty() => Self::NoMap,
            "path" => return Some(Self::parse(&format!("ns:{value}"))),
            "auto" | "keep-id" | "container" if value.is_empty() => {
                return Some(Self::parse(nsmode))
            }
            "auto" | "keep-id" | "container" => {
                return Some(Self::parse(&format!("{nsmode}:{value}")))
            }
            _ => return None,
        }))
    }

    /// The `nsmode` and `value` of the SpecGenerator that
    /// [`Self::from_spec`] reads as this choice.
    pub fn to_spec(&self) -> (&'static str, String) {
        let opts = |o: &Option<String>| o.clone().unwrap_or_default();
        match self {
            Self::Host => ("host", String::new()),
            Self::Private => ("private", String::new()),
            Self::NoMap => ("no-map", String::new()),
            Self::Auto(o) => ("auto", opts(o)),
            Self::KeepId(o) => ("keep-id", opts(o)),
            Self::Ns(path) => ("path", path.clone()),
            Self::Container(id) => ("container", id.clone()),
        }
    }
}

impl fmt::Display for UsernsChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let with = |f: &mut fmt::Formatter<'_>, word: &str, opts: &Option<String>| match opts {
            Some(o) => write!(f, "{word}:{o}"),
            None => f.write_str(word),
        };
        match self {
            Self::Host => f.write_str("host"),
            Self::Private => f.write_str("private"),
            Self::NoMap => f.write_str("nomap"),
            Self::Auto(o) => with(f, "auto", o),
            Self::KeepId(o) => with(f, "keep-id", o),
            Self::Ns(path) => write!(f, "ns:{path}"),
            Self::Container(id) => write!(f, "container:{id}"),
        }
    }
}

text_mode!(UsernsChoice);

/// `scope`: the containers of the engine service are in a systemd scope
/// each, outside its unit (the other placement, next to the engine in its
/// delegated cgroup, is `--cgroups=split`: [`CgroupsMode::Split`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupMode {
    /// A systemd scope per container, outside the engine's unit.
    Scope,
}

impl CgroupMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scope => "scope",
        }
    }

    pub fn parse(text: &str) -> Result<Self, ModeError> {
        match text {
            "scope" => Ok(Self::Scope),
            _ => Err(ModeError {
                what: "cgroup",
                text: text.to_string(),
                expected: "scope",
            }),
        }
    }
}

impl fmt::Display for CgroupMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

text_mode!(CgroupMode);

/// The `scope` of a container or a pod where none is the empty
/// text, as it is kept (`#[serde(with = "cgroup_mode_word")]` on an
/// `Option<CgroupMode>`): the empty text reads as none, like the empty text
/// of every other mode.
pub mod cgroup_mode_word {
    use super::CgroupMode;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(mode: &Option<CgroupMode>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(mode.map_or("", CgroupMode::as_str))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<CgroupMode>, D::Error> {
        match Option::<std::borrow::Cow<str>>::deserialize(d)?.as_deref() {
            None | Some("") => Ok(None),
            Some(word) => CgroupMode::parse(word)
                .map(Some)
                .map_err(serde::de::Error::custom),
        }
    }
}

/// `--cgroups`: how a container is placed in the cgroups.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CgroupsMode {
    /// Nothing was asked for (the empty text): the default of the engine
    #[default]
    Unset,
    Enabled,
    Disabled,
    /// The monitor is not given a cgroup of its own
    NoConmon,
    /// The cgroup is split: a command in a systemd unit splits the unit's
    /// cgroup; the engine service splits its own at its start, and its
    /// containers are `[<pod>/]<id>/container` next to its `engine`
    Split,
    /// `enabled`, in a systemd scope of the manager
    Scope,
}

impl CgroupsMode {
    pub fn parse(text: &str) -> Result<Self, ModeError> {
        Ok(match text {
            "" => Self::Unset,
            "enabled" => Self::Enabled,
            "disabled" => Self::Disabled,
            "no-conmon" => Self::NoConmon,
            "split" => Self::Split,
            "scope" => Self::Scope,
            _ => {
                return Err(ModeError {
                    what: "cgroup",
                    text: text.to_string(),
                    expected: "enabled, disabled, no-conmon, split or scope",
                })
            }
        })
    }

    /// The mode and the `scope` the value asks for: `scope` is `enabled`.
    pub fn split(self) -> (Self, Option<CgroupMode>) {
        match self {
            Self::Scope => (Self::Enabled, Some(CgroupMode::Scope)),
            m => (m, None),
        }
    }

    /// Nothing was asked for.
    pub fn is_unset(&self) -> bool {
        *self == Self::Unset
    }

    /// The mode a container with none asked for has: `enabled`.
    pub fn or_enabled(self) -> Self {
        match self {
            Self::Unset => Self::Enabled,
            m => m,
        }
    }
}

impl fmt::Display for CgroupsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unset => "",
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::NoConmon => "no-conmon",
            Self::Split => "split",
            Self::Scope => "scope",
        })
    }
}

text_mode!(CgroupsMode);

/// How a network names a provider: `provider:NAME`.
pub const PROVIDER_PREFIX: &str = "provider:";

/// The `--network` mode of a container.
///
/// The mode is a word (`host`, `none`, `bridge`, `pasta`...) or a word with
/// an argument (`container:ID`, `ns:PATH`, `provider:NAME`, `bridge:NAME`,
/// `pasta:OPTIONS`); anything else names a network.  [`NetworkMode`] is
/// lossless: every text reads as a mode and a mode shows as the text it was
/// read from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum NetworkMode {
    /// Nothing was asked for (the empty text): the default network
    #[default]
    Unset,
    /// `default`
    Default,
    /// `private`: a namespace of its own, as podman's
    Private,
    /// `pod`: the network of the pod
    Pod,
    Host,
    /// `none`: a namespace with no network
    Off,
    /// `bridge`, or `bridge:NAME`
    Bridge(Option<String>),
    /// `pasta`, or `pasta:OPTIONS`
    Pasta(Option<String>),
    /// `container:ID`: the network of another container
    Container(String),
    /// `ns:PATH`: the namespace pinned at a path (not checked to be absolute
    /// or to exist: that is for whoever joins it)
    Ns(String),
    /// `provider:NAME`: the network of a network provider
    Provider(String),
    /// A network by name (`cni:NAME`, a list `a,b`, anything else)
    Network(String),
}

impl NetworkMode {
    /// The mode `text` is.  Every text is one.
    pub fn parse(text: &str) -> Self {
        match text {
            "" => Self::Unset,
            "default" => Self::Default,
            "private" => Self::Private,
            "pod" => Self::Pod,
            "host" => Self::Host,
            "none" => Self::Off,
            "bridge" => Self::Bridge(None),
            "pasta" => Self::Pasta(None),
            _ => {
                if let Some(name) = text.strip_prefix("bridge:") {
                    Self::Bridge(Some(name.to_string()))
                } else if let Some(options) = text.strip_prefix("pasta:") {
                    Self::Pasta(Some(options.to_string()))
                } else if let Some(id) = text.strip_prefix("container:") {
                    Self::Container(id.to_string())
                } else if let Some(path) = text.strip_prefix("ns:") {
                    Self::Ns(path.to_string())
                } else if let Some(name) = text.strip_prefix(PROVIDER_PREFIX) {
                    Self::Provider(name.to_string())
                } else {
                    Self::Network(text.to_string())
                }
            }
        }
    }

    /// The network namespace of the host.
    pub fn is_host(&self) -> bool {
        *self == Self::Host
    }

    /// A network namespace the container does not own: the host's, another
    /// container's or one at a path.
    pub fn is_joined(&self) -> bool {
        matches!(self, Self::Host | Self::Container(_) | Self::Ns(_))
    }

    /// Whether a container made with the networks `networks` (a list of
    /// modes, each a word) or, with none, the mode `mode`, is in `wanted`.
    pub fn has(networks: &[String], mode: &Self, wanted: &Self) -> bool {
        if networks.is_empty() {
            mode == wanted
        } else {
            networks.iter().any(|n| Self::parse(n) == *wanted)
        }
    }

    /// The word for a network namespace that takes no port mappings of its
    /// own (`host`, `none`, another container's, one at a path), as podman
    /// names it when it drops them.
    pub fn without_ports(&self) -> Option<&'static str> {
        match self {
            Self::Host => Some("host"),
            Self::Off => Some("none"),
            Self::Container(_) => Some("container"),
            Self::Ns(_) => Some("path"),
            _ => None,
        }
    }

    /// The modes of a list `a,b`: each piece, trimmed, read as a mode (a
    /// mode that is no list is one piece).  The options of pasta and those
    /// of a network (`NAME:OPTIONS`, `bridge:OPTIONS`) are a list of their
    /// own: each is one piece.
    pub fn pieces(&self) -> Vec<Self> {
        match self {
            Self::Pasta(_) | Self::Bridge(Some(_)) => vec![self.clone()],
            Self::Network(n) if Self::options_of(n).is_some() => vec![self.clone()],
            m => m
                .to_string()
                .split(',')
                .map(|piece| Self::parse(piece.trim()))
                .collect(),
        }
    }

    /// NAME and OPTIONS of a network `NAME:OPTIONS` (`cni:NAME` has none).
    fn options_of(network: &str) -> Option<(&str, &str)> {
        network.split_once(':').filter(|(name, _)| *name != "cni")
    }

    /// The network a piece of a list of networks names, without its
    /// options: NAME of `NAME:OPTIONS`, `bridge` of `bridge:OPTIONS`, any
    /// other piece itself.
    pub fn network_name(piece: &str) -> &str {
        match Self::parse(piece) {
            Self::Bridge(Some(_)) => "bridge",
            Self::Network(_) => Self::options_of(piece).map_or(piece, |(name, _)| name),
            _ => piece,
        }
    }

    /// NAME of `provider:NAME`.
    pub fn provider(&self) -> Option<&str> {
        match self {
            Self::Provider(name) => Some(name),
            _ => None,
        }
    }
}

impl fmt::Display for NetworkMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let with = |f: &mut fmt::Formatter<'_>, word: &str, arg: &Option<String>| match arg {
            Some(arg) => write!(f, "{word}:{arg}"),
            None => f.write_str(word),
        };
        match self {
            Self::Unset => Ok(()),
            Self::Default => f.write_str("default"),
            Self::Private => f.write_str("private"),
            Self::Pod => f.write_str("pod"),
            Self::Host => f.write_str("host"),
            Self::Off => f.write_str("none"),
            Self::Bridge(name) => with(f, "bridge", name),
            Self::Pasta(options) => with(f, "pasta", options),
            Self::Container(id) => write!(f, "container:{id}"),
            Self::Ns(path) => write!(f, "ns:{path}"),
            Self::Provider(name) => write!(f, "{PROVIDER_PREFIX}{name}"),
            Self::Network(name) => f.write_str(name),
        }
    }
}

impl Serialize for NetworkMode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for NetworkMode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = std::borrow::Cow::<str>::deserialize(d)?;
        Ok(Self::parse(&text))
    }
}

#[cfg(feature = "proxy")]
impl zlink::introspect::Type for NetworkMode {
    const TYPE: &'static zlink::idl::Type<'static> = &zlink::idl::Type::String;
}

#[cfg(test)]
mod tests;
