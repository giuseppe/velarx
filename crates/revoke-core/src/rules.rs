// SPDX-License-Identifier: Apache-2.0
//! The rules of the adoption of lists (see the head of the crate), checked on
//! the answer of `adopt` for given held lists and parts.  They are stated by
//! a reference, not by how `adopt` computes: what is held after is, for each
//! issuer, the highest of the number held and the numbers of its verified
//! parts.
//!
//! The revoked peers are modelled by the lists they come from: a list
//! (issuer, number) revokes the peers `peers(issuer, number)`, a set of
//! its own (here a bit of its own), and the peers revoked are the union of
//! the sets of the lists held, one for each issuer: a newer list replaces the
//! set of the older.

use super::*;

/// The issuers of the world (the last one has no authority at the shell: its
/// parts are never verified there, here they may be, to check that the core
/// does not decide that).
pub const ISSUERS: u64 = 3;

fn number_of(held: &[Held], issuer: u64) -> Option<u64> {
    held.iter().find(|h| h.issuer == issuer).map(|h| h.number)
}

/// What is held after the adoption of `adopted`.
fn apply(held: &[Held], parts: &[Part], adopted: &[usize]) -> Vec<Held> {
    let mut after = held.to_vec();
    for &i in adopted {
        let list = Held {
            issuer: parts[i].issuer,
            number: parts[i].number,
        };
        match after.iter_mut().find(|h| h.issuer == list.issuer) {
            Some(h) => *h = list,
            None => after.push(list),
        }
    }
    after
}

/// The peers a list revokes, in a world where each list has its own.
fn peers(h: &Held) -> u64 {
    1 << (h.issuer * 4 + h.number.min(3))
}

/// The peers revoked by what is held: the union of the sets of its lists.
pub fn revoked(held: &[Held]) -> u64 {
    held.iter().fold(0, |all, h| all | peers(h))
}

/// The reference: the number held of each issuer after, from the number held
/// and the verified parts only.
fn expected(held: &[Held], parts: &[Part], issuer: u64) -> Option<u64> {
    parts
        .iter()
        .filter(|p| p.verified && p.issuer == issuer)
        .map(|p| p.number)
        .chain(number_of(held, issuer))
        .max()
}

fn same(a: &[Held], b: &[Held]) -> bool {
    (0..ISSUERS).all(|i| number_of(a, i) == number_of(b, i))
}

/// `held` is a state (an issuer once), and the rules hold for every order of
/// `parts` (all of them when `orders`).
pub fn check(held: &[Held], parts: &[Part], orders: bool) {
    let adopted = adopt(held, parts);
    let note = format!("held {held:?}, parts {parts:?}, adopted {adopted:?}");
    // the answer is places, in order, at most once an issuer
    assert!(adopted.windows(2).all(|w| w[0] < w[1]), "{note}");
    assert!(adopted.iter().all(|&i| i < parts.len()), "{note}");
    for (n, &i) in adopted.iter().enumerate() {
        assert!(
            adopted[..n]
                .iter()
                .all(|&j| parts[j].issuer != parts[i].issuer),
            "{note}"
        );
        // 2, 3: verified, and newer than what is held
        assert!(parts[i].verified, "{note}");
        assert!(
            number_of(held, parts[i].issuer).is_none_or(|h| parts[i].number > h),
            "{note}"
        );
    }
    let after = apply(held, parts, &adopted);
    for issuer in 0..ISSUERS {
        // 3: never decreases; 4: the highest of the verified
        assert!(
            number_of(&after, issuer) >= number_of(held, issuer),
            "{note}"
        );
        assert_eq!(
            number_of(&after, issuer),
            expected(held, parts, issuer),
            "{note}"
        );
        // an issuer is held once
        assert!(
            after.iter().filter(|h| h.issuer == issuer).count() <= 1,
            "{note}"
        );
    }
    // the union of the lists held, one for each issuer
    let mut union = 0;
    for issuer in 0..ISSUERS {
        if let Some(number) = expected(held, parts, issuer) {
            union |= peers(&Held { issuer, number });
        }
    }
    assert_eq!(revoked(&after), union, "{note}");
    // `newer` is what `adopt` asks of each part
    for p in parts {
        assert_eq!(
            newer(held, p.issuer, p.number),
            number_of(held, p.issuer).is_none_or(|h| p.number > h),
            "{note}"
        );
    }
    // 2: the parts that are not verified are not there
    let (kept, places): (Vec<Part>, Vec<usize>) = parts
        .iter()
        .enumerate()
        .filter(|(_, p)| p.verified)
        .map(|(i, p)| (*p, i))
        .unzip();
    let without: Vec<usize> = adopt(held, &kept).iter().map(|&i| places[i]).collect();
    assert_eq!(adopted, without, "{note}");
    // 5: again, nothing; any order, the same lists
    assert!(adopt(&after, parts).is_empty(), "{note}");
    if orders {
        let mut order: Vec<usize> = (0..parts.len()).collect();
        permute(&mut order, 0, &mut |order| {
            let moved: Vec<Part> = order.iter().map(|&i| parts[i]).collect();
            let got = apply(held, &moved, &adopt(held, &moved));
            assert!(same(&got, &after), "{note}, order {order:?}");
            assert_eq!(revoked(&got), revoked(&after), "{note}, order {order:?}");
        });
    }
}

fn permute(order: &mut Vec<usize>, from: usize, each: &mut dyn FnMut(&[usize])) {
    if from == order.len() {
        each(order);
        return;
    }
    for i in from..order.len() {
        order.swap(from, i);
        permute(order, from + 1, each);
        order.swap(from, i);
    }
}

/// The hostile text of the report: a genuine list N+1 and a part that claims
/// the highest number of the issuer without a signature that holds.
#[test]
fn junk_with_the_highest_number_hides_nothing() {
    let held = [Held {
        issuer: 0,
        number: 1,
    }];
    let genuine = Part {
        issuer: 0,
        number: 2,
        verified: true,
    };
    let junk = Part {
        issuer: 0,
        number: u64::MAX,
        verified: false,
    };
    for parts in [[junk, genuine], [genuine, junk]] {
        check(&held, &parts, true);
        let adopted = adopt(&held, &parts);
        assert_eq!(adopted.len(), 1);
        assert_eq!(parts[adopted[0]], genuine);
    }
}

#[test]
fn equal_and_older_numbers_change_nothing() {
    let held = [Held {
        issuer: 0,
        number: 2,
    }];
    for number in [0, 1, 2] {
        let parts = [Part {
            issuer: 0,
            number,
            verified: true,
        }];
        assert!(adopt(&held, &parts).is_empty());
    }
    assert_eq!(
        adopt(
            &[],
            &[Part {
                issuer: 0,
                number: 0,
                verified: true
            }]
        ),
        [0]
    );
}

/// A newer list replaces the set of the older: a peer the older revoked and
/// the newer does not is no more revoked.  It is what the code does (the
/// authority signs lists that hold every peer revoked so far); that it must
/// not be able to un-revoke is a decision of the design, not of this crate.
#[test]
fn a_newer_list_replaces_the_set() {
    let held = [Held {
        issuer: 0,
        number: 1,
    }];
    let parts = [Part {
        issuer: 0,
        number: 2,
        verified: true,
    }];
    let after = apply(&held, &parts, &adopt(&held, &parts));
    assert_eq!(revoked(&held), 1 << 1);
    assert_eq!(revoked(&after), 1 << 2);
}
