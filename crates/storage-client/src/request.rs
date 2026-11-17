// SPDX-License-Identifier: Apache-2.0
//! The parameters of the calls of `org.velarx.Storage`.  The client sends them
//! typed and borrowed (no JSON value is built: `S` is `&str`, `V` a slice,
//! `A` a reference), and the server reads the same types owned (`String`,
//! `Vec`, the value).

use crate::proto::{self, Owner};
use serde::{Deserialize, Serialize};
use velarx_wire::varlink::Method;

/// The interface the requests are calls of.
pub const INTERFACE: &str = "org.velarx.Storage";

/// `impl Method` of a request: the one place a method of the interface is
/// named.  `more`: the call answers more than once.
macro_rules! method {
    ($ty:ident $(<$($g:ident),+>)?, $name:literal, $reply:ty $(, $more:ident)?) => {
        impl$(<$($g: Serialize),+>)? Method for $ty$(<$($g),+>)? {
            const INTERFACE: &'static str = INTERFACE;
            const NAME: &'static str = $name;
            $(const $more: bool = true;)?
            type Reply = $reply;
        }
    };
}

/// A request that several methods take, as the request of one of them: the
/// same parameters, its own type, so that the type says the method.
macro_rules! named {
    ($ty:ident of $base:ident, $name:literal, $reply:ty) => {
        #[derive(Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $ty<S>(pub $base<S>);
        method!($ty<S>, $name, $reply);
    };
}

/// Who the driver is and what it does: the first call of a connection.
#[derive(Serialize, Deserialize)]
pub struct GetInfo {}
method!(GetInfo, "GetInfo", proto::Info);

/// A call with no parameters.
#[derive(Serialize, Deserialize)]
pub struct ListStores {}
method!(ListStores, "ListStores", proto::StoresReply);

#[derive(Serialize, Deserialize)]
pub struct OfStore<S> {
    pub store: S,
}

#[derive(Serialize, Deserialize)]
pub struct OfContainer<S> {
    pub store: S,
    pub container: S,
}

#[derive(Serialize, Deserialize)]
pub struct OfImage<S> {
    pub store: S,
    pub image: S,
}

#[derive(Serialize, Deserialize)]
pub struct HasLayers<S, V> {
    pub store: S,
    pub layers: V,
}

#[derive(Serialize, Deserialize)]
pub struct HasObjects<S, V> {
    pub store: S,
    pub objects: V,
}

#[derive(Serialize, Deserialize)]
pub struct BeginPull<S, V> {
    pub store: S,
    pub pull: S,
    pub layers: V,
}

#[derive(Serialize, Deserialize)]
pub struct ReadObjects<S, V> {
    pub store: S,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pull: Option<S>,
    pub ranges: V,
}

#[derive(Serialize, Deserialize)]
pub struct OfPull<S> {
    pub store: S,
    pub pull: S,
}

#[derive(Serialize, Deserialize)]
pub struct Commit<S, V> {
    pub store: S,
    pub pull: S,
    pub layers: V,
}

#[derive(Serialize, Deserialize)]
pub struct CreateRoot<S, V, A> {
    pub store: S,
    pub container: S,
    pub workdir: S,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<S>,
    pub layers: V,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<Owner>,
    pub ask: A,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_limit: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateImageVolume<S, V, A> {
    pub store: S,
    pub container: S,
    pub index: u32,
    pub image: S,
    pub layers: V,
    pub ask: A,
}

#[derive(Serialize, Deserialize)]
pub struct MountImage<S, V> {
    pub store: S,
    pub layers: V,
}

#[derive(Serialize, Deserialize)]
pub struct Mounts<S, A, V> {
    pub store: S,
    pub container: S,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<A>,
    pub volumes: V,
}

#[derive(Serialize, Deserialize)]
pub struct Check<S, V> {
    pub store: S,
    pub image: S,
    pub layers: V,
    pub full: bool,
}

#[derive(Serialize, Deserialize)]
pub struct Repair<S, V> {
    pub store: S,
    pub layers: V,
}

#[derive(Serialize, Deserialize)]
pub struct Collect<S> {
    pub store: S,
    pub keep_length: u64,
}

method!(HasLayers<S, V>, "HasLayers", proto::HasReply);
method!(HasObjects<S, V>, "HasObjects", proto::ObjectsReply);
method!(BeginPull<S, V>, "BeginPull", proto::PullEvent, MORE);
method!(ReadObjects<S, V>, "ReadObjects", proto::Read, MORE);
method!(Commit<S, V>, "Commit", proto::Ack);
method!(CreateRoot<S, V, A>, "CreateRoot", proto::Created, MORE);
method!(CreateImageVolume<S, V, A>, "CreateImageVolume", proto::VolumeCreated, MORE);
method!(MountImage<S, V>, "MountImage", proto::Ack);
method!(Mounts<S, A, V>, "Mounts", proto::MountsReply);
method!(Check<S, V>, "Check", proto::Checked, MORE);
method!(Repair<S, V>, "Repair", proto::Repaired, MORE);
method!(Collect<S>, "Collect", proto::Collection, MORE);

named!(Abort of OfPull, "Abort", proto::Ack);
named!(WritableRoot of OfContainer, "WritableRoot", proto::Ack);
named!(Size of OfContainer, "Size", proto::SizeReply);
named!(Exists of OfContainer, "Exists", proto::ExistsReply);
named!(RemoveRoot of OfContainer, "RemoveRoot", proto::Ack);
named!(RemoveImage of OfImage, "RemoveImage", proto::Ack);
named!(Usage of OfStore, "Usage", proto::UsageReply);
named!(Status of OfStore, "Status", proto::StatusReply);
named!(DropStore of OfStore, "DropStore", proto::Ack);

/// The methods this module has requests for, and the names of their
/// parameters as a request serializes them (with every optional one given):
/// what the contract test compares with the interface.
#[cfg(test)]
pub(crate) fn served() -> Vec<(&'static str, Vec<String>)> {
    fn of<M: Method>(m: &M) -> (&'static str, Vec<String>) {
        let value = serde_json::to_value(m).expect("a request serializes");
        let keys = value
            .as_object()
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default();
        (M::NAME, keys)
    }
    let (s, v) = ("s", [1u8]);
    vec![
        of(&HasLayers {
            store: s,
            layers: v,
        }),
        of(&HasObjects {
            store: s,
            objects: v,
        }),
        of(&BeginPull {
            store: s,
            pull: s,
            layers: v,
        }),
        of(&ReadObjects {
            store: s,
            pull: Some(s),
            ranges: v,
        }),
        of(&Commit {
            store: s,
            pull: s,
            layers: v,
        }),
        of(&Abort(OfPull { store: s, pull: s })),
        of(&CreateRoot {
            store: s,
            container: s,
            workdir: s,
            image: Some(s),
            layers: v,
            owner: Some(Owner { uid: 0, gid: 0 }),
            ask: 0u8,
            size_limit: Some(1),
        }),
        of(&CreateImageVolume {
            store: s,
            container: s,
            index: 0,
            image: s,
            layers: v,
            ask: 0u8,
        }),
        of(&Mounts {
            store: s,
            container: s,
            root: Some(0u8),
            volumes: v,
        }),
        of(&MountImage {
            store: s,
            layers: v,
        }),
        of(&WritableRoot(OfContainer {
            store: s,
            container: s,
        })),
        of(&Size(OfContainer {
            store: s,
            container: s,
        })),
        of(&Exists(OfContainer {
            store: s,
            container: s,
        })),
        of(&RemoveRoot(OfContainer {
            store: s,
            container: s,
        })),
        of(&RemoveImage(OfImage { store: s, image: s })),
        of(&Check {
            store: s,
            image: s,
            layers: v,
            full: true,
        }),
        of(&Repair {
            store: s,
            layers: v,
        }),
        of(&Usage(OfStore { store: s })),
        of(&Status(OfStore { store: s })),
        of(&GetInfo {}),
        of(&ListStores {}),
        of(&DropStore(OfStore { store: s })),
        of(&Collect {
            store: s,
            keep_length: 0,
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Every method the interface serves has exactly one request type, and its
    /// fields are the parameters of the method.
    #[test]
    fn every_served_method_has_one_request_with_its_parameters() {
        let definition = include_str!("../../../interfaces/org.velarx.Storage.varlink");
        let described = velarx_wire::varlink::described_methods(definition);
        let served = served();
        for (name, params) in &described {
            let found: Vec<_> = served.iter().filter(|(n, _)| n == name).collect();
            assert_eq!(found.len(), 1, "{name} has {} request types", found.len());
            let have: BTreeSet<_> = found[0].1.iter().cloned().collect();
            let want: BTreeSet<_> = params.iter().cloned().collect();
            assert_eq!(have, want, "the fields of the request {name}");
        }
        for (name, _) in &served {
            assert!(
                described.iter().any(|(n, _)| n == name),
                "{name} is not a method of the interface"
            );
        }
    }
}
