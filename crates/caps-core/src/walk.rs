// SPDX-License-Identifier: Apache-2.0
//! The requests of a small world, every one of them, and the rules checked
//! on each answer (see `rules`): four capabilities, every bounding set of
//! the engine, every default set, every `--cap-add` and `--cap-drop` set
//! and ambient set, `all` for either, privileged or not, root or not.

use super::rules::check;
use super::*;

/// The capabilities of the world: bits 0 to `BITS - 1`.
const BITS: u32 = 4;

/// The requests checked.
fn walk() -> usize {
    let masks = 0..1u64 << BITS;
    let mut checked = 0;
    for bounding in masks.clone() {
        for defaults in masks.clone() {
            for add in masks.clone() {
                for drop in masks.clone() {
                    for ambient in masks.clone() {
                        for flags in 0..16u32 {
                            let r = Request {
                                bounding,
                                defaults,
                                privileged: flags & 1 != 0,
                                root: flags & 2 != 0,
                                add,
                                add_all: flags & 4 != 0,
                                drop,
                                drop_all: flags & 8 != 0,
                                ambient,
                            };
                            check(&r, sets(&r));
                            checked += 1;
                        }
                    }
                }
            }
        }
    }
    checked
}

#[test]
fn every_request_of_the_small_world() {
    assert_eq!(walk(), 16usize.pow(5) * 16);
}
