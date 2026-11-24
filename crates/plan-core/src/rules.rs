// SPDX-License-Identifier: Apache-2.0
//! The rules of a plan, checked on its answer: what is planned, into which
//! layer, who waits, how a group is cut and in which order the groups come.
//! They are stated by what the tables say, not by how `plan` loops, so that
//! a plan that is wrong in another way than the one it was written for
//! still fails one.

use super::*;

/// The contents of the layers in the order of the tables, each once, with
/// the layer that has it first and the size its table gives there.
fn first_of_each(layers: &[Vec<File>]) -> Vec<(Content, u32, u64)> {
    let mut seen: Vec<(Content, u32, u64)> = Vec::new();
    for (l, layer) in layers.iter().enumerate() {
        for f in layer {
            if !seen.iter().any(|s| s.0 == f.content) {
                seen.push((f.content, l as u32, f.size));
            }
        }
    }
    seen
}

/// The next file does not fit in the group.
fn full(group: &Group, size: u64, limits: Limits) -> bool {
    group.files.len() >= limits.files as usize || group.bytes.saturating_add(size) > limits.bytes
}

/// Checks the groups `plan` answers for the arguments; a rule that fails
/// panics with its words, and the arguments.
pub fn check(
    layers: &[Vec<File>],
    present: &[bool],
    profile: &[Content],
    limits: Limits,
    groups: &[Group],
) {
    let what =
        || format!("{layers:?} present {present:?} profile {profile:?} {limits:?}: {groups:?}");
    let have = first_of_each(layers);
    let lacking: Vec<_> = have
        .iter()
        .filter(|(c, _, _)| !present[*c as usize])
        .collect();
    let size_in = |c: Content, layer: u32| {
        layers[layer as usize]
            .iter()
            .find(|f| f.content == c)
            .map(|f| f.size)
    };

    let planned: Vec<Content> = groups.iter().flat_map(|g| g.files.clone()).collect();
    // P1: every content a layer lacks is in exactly one group, and nothing
    // else is
    for (c, _, _) in &lacking {
        let n = planned.iter().filter(|p| *p == c).count();
        assert_eq!(
            n,
            1,
            "a lacking content is in exactly one group: {c} {}",
            what()
        );
    }
    for c in &planned {
        assert!(
            have.iter().any(|h| h.0 == *c) && !present[*c as usize],
            "a content that is present or in no layer is not planned: {c} {}",
            what()
        );
    }

    // P5: the profile first, in its order, each content once, then the rest
    // in the order of the layers and of their tables
    let mut expected: Vec<Content> = Vec::new();
    for c in profile {
        let known = have.iter().any(|h| h.0 == *c);
        if known && !present[*c as usize] && !expected.contains(c) {
            expected.push(*c);
        }
    }
    let first = expected.len();
    for f in layers.iter().flatten() {
        if !present[f.content as usize] && !expected.contains(&f.content) {
            expected.push(f.content);
        }
    }
    assert_eq!(
        planned,
        expected,
        "the profile is planned first in its order, then the tables in order: {}",
        what()
    );
    // (the groups of the profile end where the profile ends)
    let (mut count, mut boundary) = (0, 0);
    while count < first {
        count += groups[boundary].files.len();
        boundary += 1;
    }
    assert_eq!(
        count,
        first,
        "the rest does not join a group of the profile: {}",
        what()
    );

    for (g, group) in groups.iter().enumerate() {
        assert!(!group.files.is_empty(), "a group is not empty: {}", what());
        // P3: the group is fetched into the first layer that has each file
        let mut sum = 0u64;
        for c in &group.files {
            let (_, home, size) = have.iter().find(|h| h.0 == *c).unwrap();
            assert_eq!(
                *home,
                group.layer,
                "a file is planned into the first layer that has it: {c} {}",
                what()
            );
            sum = sum.saturating_add(*size);
        }
        // P2: the layers that lack a file of the group wait for it
        let waiting: Vec<u32> = (0..layers.len() as u32)
            .filter(|l| {
                layers[*l as usize]
                    .iter()
                    .any(|f| group.files.contains(&f.content))
            })
            .collect();
        assert_eq!(
            group.needed_by,
            waiting,
            "a group is waited for by the layers that lack its files, in order: {}",
            what()
        );
        // P4: the limits, and a group is cut when the next file does not fit,
        // not before
        assert_eq!(
            group.bytes,
            sum,
            "the bytes of a group are the sum of its files: {}",
            what()
        );
        assert!(
            group.files.len() == 1
                || (group.files.len() <= limits.files as usize && group.bytes <= limits.bytes),
            "a group of several files is within the limits: {}",
            what()
        );
        if g > 0 && g != boundary && groups[g - 1].layer == group.layer {
            let next = size_in(group.files[0], group.layer).unwrap();
            assert!(
                full(&groups[g - 1], next, limits),
                "a group is cut only when the next file does not fit: {}",
                what()
            );
        }
    }
}
