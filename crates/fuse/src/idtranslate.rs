// SPDX-License-Identifier: Apache-2.0
//! Translation of the owners of an image to the ids of a user namespace.

use velarx_base::idmap;
use velarx_proto::pod::IdMapping;

/// How the owners of the files of an image become ids of the namespace
/// of the daemon: the image id `c` is shown as the parent id of the mapping of
/// the container.  An owner that the mapping does not cover is never given a
/// wrong id: the image does not start (`unmapped`), or, if asked to, such
/// files are shown as owned by the root of the container.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IdTranslate {
    pub uid: Vec<IdMapping>,
    pub gid: Vec<IdMapping>,
    pub squash: bool,
}

impl IdTranslate {
    /// The id the kernel has no user for.
    pub const NOBODY: u32 = u32::MAX;

    fn map(&self, maps: &[IdMapping], id: u32) -> u32 {
        idmap::to_parent(maps, id)
            .or_else(|| self.squash.then(|| idmap::to_parent(maps, 0)).flatten())
            .unwrap_or(Self::NOBODY)
    }

    pub fn uid_of(&self, id: u32) -> u32 {
        self.map(&self.uid, id)
    }

    pub fn gid_of(&self, id: u32) -> u32 {
        self.map(&self.gid, id)
    }

    /// The first of the owners `uids` and `gids` of an image that the
    /// mapping cannot represent, as `("uid", 33)`.
    pub fn first_unmapped_owners(
        &self,
        uids: impl IntoIterator<Item = u32>,
        gids: impl IntoIterator<Item = u32>,
    ) -> Option<(&'static str, u32)> {
        if self.squash {
            return None;
        }
        uids.into_iter()
            .find(|u| idmap::to_parent(&self.uid, *u).is_none())
            .map(|u| ("uid", u))
            .or_else(|| {
                gids.into_iter()
                    .find(|g| idmap::to_parent(&self.gid, *g).is_none())
                    .map(|g| ("gid", g))
            })
    }
}

impl IdTranslate {
    /// Why an image whose files have the owners `owners` (uids, gids) cannot
    /// be shown with this mapping, if it cannot: the words of the error of
    /// the one who refuses to start it (the storage driver, the FUSE file
    /// system), the same for all.
    pub fn unmapped_owners_error(&self, owners: &(Vec<u32>, Vec<u32>)) -> Option<String> {
        let (kind, id) =
            self.first_unmapped_owners(owners.0.iter().copied(), owners.1.iter().copied())?;
        Some(format!(
            "the image has files owned by {kind} {id}, which is not mapped in the user namespace \
             (map more ids: /etc/subuid, /etc/subgid and newuidmap, or a bigger --userns range)"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(c: u32, h: u32, n: u32) -> IdMapping {
        IdMapping {
            container_id: c,
            host_id: h,
            size: n,
        }
    }

    #[test]
    fn test_owners_are_translated() {
        let t = IdTranslate {
            uid: vec![m(0, 100000, 1000)],
            gid: vec![m(0, 200000, 100), m(100, 0, 1)],
            squash: false,
        };
        assert_eq!((t.uid_of(0), t.uid_of(999)), (100000, 100999));
        assert_eq!(t.uid_of(1000), IdTranslate::NOBODY);
        assert_eq!((t.gid_of(5), t.gid_of(100)), (200005, 0));
        assert_eq!(t.gid_of(101), IdTranslate::NOBODY);
        let squash = IdTranslate {
            squash: true,
            ..t.clone()
        };
        assert_eq!(squash.uid_of(5000), 100000);
        assert_eq!(squash.gid_of(5000), 200000);
    }

    #[test]
    fn test_unmapped_owners_are_found() {
        let owners = (vec![0, 33, 70000], vec![0, 42]);
        let unmapped =
            |t: &IdTranslate| t.first_unmapped_owners(owners.0.clone(), owners.1.clone());
        let identity = IdTranslate {
            uid: vec![m(0, 0, 1)],
            gid: vec![m(0, 0, 1)],
            squash: false,
        };
        assert_eq!(unmapped(&identity), Some(("uid", 33)));
        let wide = IdTranslate {
            uid: vec![m(0, 1, 65536)],
            gid: vec![m(0, 1, 65536)],
            squash: false,
        };
        assert_eq!(unmapped(&wide), Some(("uid", 70000)));
        let ok = IdTranslate {
            uid: vec![m(0, 1, 100000)],
            gid: vec![m(0, 1, 50)],
            squash: false,
        };
        assert_eq!(unmapped(&ok), None);
        let small_gid = IdTranslate {
            uid: vec![m(0, 1, 100000)],
            gid: vec![m(0, 1, 40)],
            squash: false,
        };
        assert_eq!(unmapped(&small_gid), Some(("gid", 42)));
        // Squashing accepts anything.
        assert_eq!(
            unmapped(&IdTranslate {
                squash: true,
                ..identity
            }),
            None
        );
    }

    #[test]
    fn the_error_of_unmapped_owners_names_the_owner_and_the_remedy() {
        let t = IdTranslate {
            uid: vec![m(0, 1, 100)],
            gid: vec![m(0, 1, 100)],
            squash: false,
        };
        let why = t.unmapped_owners_error(&(vec![0, 133], vec![0])).unwrap();
        assert!(why.starts_with("the image has files owned by uid 133, which is not mapped"));
        assert!(why.contains("/etc/subuid"), "{why}");
        assert!(t.unmapped_owners_error(&(vec![0, 99], vec![5])).is_none());
        let squash = IdTranslate { squash: true, ..t };
        assert!(squash
            .unmapped_owners_error(&(vec![500], vec![500]))
            .is_none());
    }
}
