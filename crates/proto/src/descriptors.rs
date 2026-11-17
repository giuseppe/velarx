// SPDX-License-Identifier: Apache-2.0
//! The descriptors of a message, taken by position.
//!
//! The rule of every interface: a descriptor is a field of type `int` (or
//! `?int` when it may be absent), named after what it is, whose value is
//! its position among the descriptors of its message.  Nothing is counted
//! and nothing is implied by order.

use std::os::fd::OwnedFd;

/// The descriptors of a message, each taken once by the position a field
/// names.
pub struct Descriptors(Vec<Option<OwnedFd>>);

impl Descriptors {
    pub fn new(fds: Vec<OwnedFd>) -> Self {
        Self(fds.into_iter().map(Some).collect())
    }

    /// The descriptor `what` names at position `at`.  The error says what is
    /// wrong, for the caller to make its own error of it.
    pub fn take(&mut self, what: &str, at: u32) -> Result<OwnedFd, String> {
        let count = self.0.len();
        self.0
            .get_mut(at as usize)
            .ok_or_else(|| format!("{what} is descriptor {at}, and the message has {count}"))?
            .take()
            .ok_or_else(|| format!("{what} is descriptor {at}, which another field named"))
    }

    /// [`Descriptors::take`] of a field that may be absent.
    pub fn take_opt(&mut self, what: &str, at: Option<u32>) -> Result<Option<OwnedFd>, String> {
        at.map(|at| self.take(what, at)).transpose()
    }

    /// The descriptors no field named, in order: what a call that carries a
    /// list of them (the files of an artifact) takes after the named ones.
    pub fn rest(self) -> Vec<OwnedFd> {
        self.0.into_iter().flatten().collect()
    }

    /// Every descriptor of the message was named by a field: a message with
    /// one nobody names is refused.
    pub fn finish(self) -> Result<(), String> {
        if self.0.iter().any(Option::is_some) {
            return Err("a descriptor that no field names".into());
        }
        Ok(())
    }

    /// How many the message carries.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fd() -> OwnedFd {
        std::fs::File::open("/dev/null").unwrap().into()
    }

    #[test]
    fn a_descriptor_is_taken_by_its_position_once() {
        let mut fds = Descriptors::new(vec![fd(), fd()]);
        assert!(fds.take("a", 1).is_ok());
        assert!(fds.take("b", 1).unwrap_err().contains("another field"));
        assert!(fds.take("c", 2).unwrap_err().contains("has 2"));
        assert!(fds.take_opt("d", None).unwrap().is_none());
        assert!(fds.finish().is_err());
    }

    #[test]
    fn a_message_whose_descriptors_are_all_named_is_complete() {
        let mut fds = Descriptors::new(vec![fd()]);
        fds.take("a", 0).unwrap();
        assert!(fds.finish().is_ok());
    }
}
