// SPDX-License-Identifier: Apache-2.0
//! The plan of a lazy pull: which files are fetched, in which groups and in
//! which order, and which layers wait for each group.  Contents are dense
//! numbers (`0..present.len()`), layers are numbers, and what the stores
//! hold is one snapshot, `present`: the shell that reads the tables and
//! asks the stores is `velarx-core`.
//!
//! A content is fetched once, into the first layer that has it.  What the
//! startup profile names goes first, in its order; the rest follows layer by
//! layer, in the order of the table.  A group is cut by the limits (a file
//! that alone is over the bytes is a group of its own).
//!
//! The code is plain loops over slices and vectors with indices, and sums
//! that saturate, so that Aeneas can translate it (tools/verify).

pub type Content = u32;

/// A regular file with content in the table of a layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct File {
    pub content: Content,
    pub size: u64,
}

/// What a group is cut at (with 0 files, each file is a group of its own).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub files: u32,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// The layer it is fetched into.
    pub layer: u32,
    pub files: Vec<Content>,
    /// The sum of the sizes of the files (it saturates).
    pub bytes: u64,
    /// The layers that lack a file of the group, in ascending order.
    pub needed_by: Vec<u32>,
}

/// The group has room for a file of `size`.
fn has_room(group: &Group, size: u64, limits: Limits) -> bool {
    group.files.len() < limits.files as usize && group.bytes.saturating_add(size) <= limits.bytes
}

/// The file joins the last group if that is one of `layer` made after the
/// first `from` and has room, else it starts a group; the index of the
/// group it is in.
fn add(groups: &mut Vec<Group>, from: usize, layer: u32, file: File, limits: Limits) -> usize {
    let n = groups.len();
    if n > from && groups[n - 1].layer == layer && has_room(&groups[n - 1], file.size, limits) {
        groups[n - 1].files.push(file.content);
        groups[n - 1].bytes = groups[n - 1].bytes.saturating_add(file.size);
        n - 1
    } else {
        groups.push(Group {
            layer,
            files: vec![file.content],
            bytes: file.size,
            needed_by: Vec::new(),
        });
        n
    }
}

/// The groups to fetch for `layers` (the files of each, in the order of its
/// table) of the contents `present` lacks; the `profile` is the contents a
/// container looked up at its start, in the order it did.  What the profile
/// names that no layer has, that is present, or that it names twice, is
/// ignored.
pub fn plan(
    layers: &[Vec<File>],
    present: &[bool],
    profile: &[Content],
    limits: Limits,
) -> Vec<Group> {
    // where each content is fetched: the first layer that has it, with the
    // size its table gives there
    let mut home: Vec<Option<(u32, u64)>> = Vec::new();
    // the group each content is planned in
    let mut slot: Vec<Option<usize>> = Vec::new();
    let mut c = 0;
    while c < present.len() {
        home.push(None);
        slot.push(None);
        c += 1;
    }
    let mut l: u32 = 0;
    while (l as usize) < layers.len() {
        let mut f = 0;
        while f < layers[l as usize].len() {
            let file = layers[l as usize][f];
            if home[file.content as usize].is_none() {
                home[file.content as usize] = Some((l, file.size));
            }
            f += 1;
        }
        l += 1;
    }
    let mut groups: Vec<Group> = Vec::new();
    let mut p = 0;
    while p < profile.len() {
        let content = profile[p];
        if let Some((layer, size)) = home[content as usize] {
            if !present[content as usize] && slot[content as usize].is_none() {
                let file = File { content, size };
                slot[content as usize] = Some(add(&mut groups, 0, layer, file, limits));
            }
        }
        p += 1;
    }
    // (the rest starts groups of its own)
    let from = groups.len();
    let mut l: u32 = 0;
    while (l as usize) < layers.len() {
        let mut f = 0;
        while f < layers[l as usize].len() {
            let file = layers[l as usize][f];
            if !present[file.content as usize] && slot[file.content as usize].is_none() {
                slot[file.content as usize] = Some(add(&mut groups, from, l, file, limits));
            }
            f += 1;
        }
        l += 1;
    }
    // the layers wait for the files they lack: their own, and those another
    // layer fetches for them
    let mut l: u32 = 0;
    while (l as usize) < layers.len() {
        let mut f = 0;
        while f < layers[l as usize].len() {
            if let Some(g) = slot[layers[l as usize][f].content as usize] {
                let waits = &mut groups[g].needed_by;
                let n = waits.len();
                if n == 0 || waits[n - 1] != l {
                    waits.push(l);
                }
            }
            f += 1;
        }
        l += 1;
    }
    groups
}

#[cfg(test)]
mod rules;

#[cfg(test)]
mod walk;

#[cfg(test)]
mod tests {
    use super::*;

    const WIDE: Limits = Limits {
        files: u32::MAX,
        bytes: u64::MAX,
    };

    fn file(content: Content, size: u64) -> File {
        File { content, size }
    }

    /// Each layer a list of the contents it has, all of size 1.
    fn tables(layers: &[&[Content]]) -> Vec<Vec<File>> {
        layers
            .iter()
            .map(|l| l.iter().map(|&c| file(c, 1)).collect())
            .collect()
    }

    fn files(groups: &[Group]) -> Vec<(u32, Vec<Content>)> {
        groups.iter().map(|g| (g.layer, g.files.clone())).collect()
    }

    #[test]
    fn nothing_is_planned_for_no_layers_or_for_what_is_present() {
        assert!(plan(&[], &[], &[], WIDE).is_empty());
        let layers = tables(&[&[0, 1]]);
        assert!(plan(&layers, &[true, true], &[1], WIDE).is_empty());
    }

    /// The profile comes first in its order and together by layer; what it
    /// names wrongly is ignored.
    #[test]
    fn the_startup_profile_is_planned_first_in_its_order() {
        // contents: 0 "one", 1 "two", 2 "three", 3 "four", 4 "five", 5 nowhere
        let layers = tables(&[&[0, 1, 2], &[3, 4]]);
        let present = [false, false, true, false, false, false];
        let groups = plan(&layers, &present, &[3, 0, 1, 5, 0, 2], WIDE);
        assert_eq!(
            files(&groups),
            vec![(1, vec![3]), (0, vec![0, 1]), (1, vec![4])]
        );
        // what is present is not planned, with or without a profile
        let all = plan(&layers, &[true; 6], &[4], WIDE);
        assert!(all.is_empty());
    }

    #[test]
    fn a_group_of_the_profile_is_bounded_in_files() {
        let many: Vec<Content> = (0..70).collect();
        let layers = tables(&[&many]);
        let limits = Limits {
            files: 64,
            bytes: u64::MAX,
        };
        let groups = plan(&layers, &[false; 70], &many, limits);
        let sizes: Vec<usize> = groups.iter().map(|g| g.files.len()).collect();
        assert_eq!(sizes, [64, 6]);
    }

    /// A group of the rest is bounded too, and never holds what the profile
    /// planned; the rest of a layer does not join the group of the profile.
    #[test]
    fn the_rest_follows_the_profile_in_groups_of_its_own() {
        let layers = tables(&[&[0, 1, 2, 3]]);
        let limits = Limits {
            files: 2,
            bytes: u64::MAX,
        };
        let groups = plan(&layers, &[false; 4], &[2], limits);
        assert_eq!(
            files(&groups),
            vec![(0, vec![2]), (0, vec![0, 1]), (0, vec![3])]
        );
    }

    /// A content two layers have is planned once, in the first.
    #[test]
    fn a_content_is_planned_once_for_all_the_layers() {
        let layers = tables(&[&[0], &[0, 1]]);
        let groups = plan(&layers, &[false; 2], &[], WIDE);
        assert_eq!(files(&groups), vec![(0, vec![0]), (1, vec![1])]);
        assert_eq!(groups[0].needed_by, [0, 1]);
        assert_eq!(groups[1].needed_by, [1]);
        // the same with the profile
        let groups = plan(&layers, &[false; 2], &[0, 1], WIDE);
        assert_eq!(files(&groups), vec![(0, vec![0]), (1, vec![1])]);
    }

    /// A content a layer has twice is planned once, and the layer waits once.
    #[test]
    fn a_content_with_several_names_is_planned_once() {
        let layers = tables(&[&[0, 1, 0]]);
        let groups = plan(&layers, &[false; 2], &[], WIDE);
        assert_eq!(files(&groups), vec![(0, vec![0, 1])]);
        assert_eq!(groups[0].needed_by, [0]);
    }

    /// A layer waits for the groups of the contents it lacks, whichever
    /// layer fetches them, and not for the ones it has.
    #[test]
    fn a_layer_waits_for_the_files_it_lacks() {
        let layers = tables(&[&[0, 1], &[1, 2], &[2, 3]]);
        let groups = plan(&layers, &[true, false, false, false], &[], WIDE);
        assert_eq!(
            files(&groups),
            vec![(0, vec![1]), (1, vec![2]), (2, vec![3])]
        );
        assert_eq!(groups[0].needed_by, [0, 1]);
        assert_eq!(groups[1].needed_by, [1, 2]);
        assert_eq!(groups[2].needed_by, [2]);
    }

    /// A group is cut at the bytes; a file over them is a group of its own;
    /// 0 files is 1.
    #[test]
    fn the_limits_cut_a_group_and_a_big_file_is_alone() {
        let layer = vec![file(0, 3), file(1, 3), file(2, 10), file(3, 1), file(4, 1)];
        let limits = Limits { files: 8, bytes: 6 };
        let groups = plan(std::slice::from_ref(&layer), &[false; 5], &[], limits);
        assert_eq!(
            files(&groups),
            vec![(0, vec![0, 1]), (0, vec![2]), (0, vec![3, 4])]
        );
        assert_eq!(
            groups.iter().map(|g| g.bytes).collect::<Vec<_>>(),
            [6, 10, 2]
        );
        let none = Limits { files: 0, bytes: 6 };
        let groups = plan(&[layer], &[false; 5], &[], none);
        assert_eq!(groups.len(), 5);
    }

    /// The sizes of a hostile table add up without wrapping.
    #[test]
    fn the_bytes_of_a_group_saturate() {
        let layer = vec![file(0, u64::MAX), file(1, u64::MAX)];
        let groups = plan(&[layer], &[false; 2], &[], WIDE);
        assert_eq!(files(&groups), vec![(0, vec![0, 1])]);
        assert_eq!(groups[0].bytes, u64::MAX);
    }
}
