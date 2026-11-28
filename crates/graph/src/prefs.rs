// SPDX-License-Identifier: Apache-2.0
//! A short list of distinct values in the order of preference, as plain
//! `Copy` data: what a driver says of the ways it supports something (the
//! user namespace mapping, the enforcement of fs-verity), which are a few
//! variants of an enum.

/// The most values a [`Prefs`] holds: the enums it lists have at most four
/// variants.
pub const MAX: usize = 4;

/// Up to [`MAX`] distinct values, the preferred first.  The list is owned
/// data, `Copy` and comparable, so that a driver states it in a `const`,
/// with nothing to keep alive.  The values are packed at the front (`None` only after the last),
/// so two lists are equal when they list the same values in the same order.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Prefs<T: Copy> {
    items: [Option<T>; MAX],
}

/// As the list it is: `[DriverMount, Translate]`.
impl<T: Copy + std::fmt::Debug> std::fmt::Debug for Prefs<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<T: Copy> Default for Prefs<T> {
    fn default() -> Self {
        Self::NONE
    }
}

impl<T: Copy> Prefs<T> {
    /// The empty list.
    pub const NONE: Self = Self { items: [None; MAX] };

    /// The list of `values`, in this order.  For a `const`: more than
    /// [`MAX`] values is a compile error there.  The values must differ (a
    /// repeat is not a second preference); [`Prefs::from_iter`]
    /// (`FromIterator`) drops them.
    pub const fn new(values: &[T]) -> Self {
        assert!(values.len() <= MAX, "too many values in a Prefs");
        let mut items = [None; MAX];
        let mut i = 0;
        while i < values.len() {
            items[i] = Some(values[i]);
            i += 1;
        }
        Self { items }
    }

    /// The values, the preferred first.
    pub fn iter(&self) -> impl Iterator<Item = T> + '_ {
        self.items.iter().map_while(|v| *v)
    }

    /// The preferred value, if there is one.
    pub fn first(&self) -> Option<T> {
        self.items[0]
    }

    pub fn is_empty(&self) -> bool {
        self.items[0].is_none()
    }

    pub fn len(&self) -> usize {
        self.iter().count()
    }
}

impl<T: Copy + PartialEq> Prefs<T> {
    pub fn contains(&self, value: T) -> bool {
        self.iter().any(|v| v == value)
    }
}

/// The values in order, each once: a value seen before is dropped, so that
/// a list cannot overflow with repeats.  The enums
/// a `Prefs` lists have at most [`MAX`] variants, so distinct values never
/// exceed it; if one ever had more, the values past the fourth would be
/// dropped (the least preferred), never an error or a panic.
impl<T: Copy + PartialEq> FromIterator<T> for Prefs<T> {
    fn from_iter<I: IntoIterator<Item = T>>(values: I) -> Self {
        let mut out = Self::NONE;
        let mut n = 0;
        for v in values {
            if n < MAX && !out.contains(v) {
                out.items[n] = Some(v);
                n += 1;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_list_keeps_its_order_and_drops_repeats() {
        let p: Prefs<u8> = [3, 1, 3, 2, 1].into_iter().collect();
        assert_eq!(p.iter().collect::<Vec<_>>(), [3, 1, 2]);
        assert_eq!(p.first(), Some(3));
        assert!(p.contains(2) && !p.contains(9));
        assert_eq!(p.len(), 3);
        assert_eq!(p, Prefs::new(&[3, 1, 2]));
        assert_ne!(p, Prefs::new(&[1, 3, 2]));
    }

    #[test]
    fn the_empty_list_is_the_default() {
        let p = Prefs::<u8>::default();
        assert!(p.is_empty());
        assert_eq!(p.first(), None);
        assert_eq!(p, Prefs::new(&[]));
    }

    #[test]
    fn a_list_is_copy_and_holds_four() {
        let p = Prefs::new(&[1u8, 2, 3, 4]);
        let q = p;
        assert_eq!(p, q);
        assert_eq!(q.len(), 4);
        // (more than four distinct values cannot come through `collect`)
        let r: Prefs<u8> = (0..9).collect();
        assert_eq!(r.len(), 4);
        assert_eq!(r, Prefs::new(&[0, 1, 2, 3]));
    }

    #[test]
    fn a_list_prints_as_its_values() {
        assert_eq!(format!("{:?}", Prefs::new(&[3u8, 1])), "[3, 1]");
        assert_eq!(format!("{:?}", Prefs::<u8>::NONE), "[]");
    }
}
