// SPDX-License-Identifier: Apache-2.0
//! The streams of an exec session or an attach, between the engine and a
//! frontend (the copy loop and Docker's framing are the frontend's: the
//! engine never carries the bytes of a session).
//!
//! `ExecStart` and `ContainerAttach` are called with `more`.  The first
//! reply (`accepted`) says the session is taken and how it looks (a
//! terminal or not, the detach keys, the pipe of the log so far when the
//! attach asked for it), and names it; a container that waits for its
//! client to attach has no streams yet.  The next (`streams`) carries the
//! descriptors the monitor made for the process: its input, its outputs.
//! The last (`ended`) says how the session ended and what the engine says as
//! errors of the process (the runtime's, or the monitor's).  The client
//! types the detach keys: `SessionDetach` (the session goes on); its input
//! ends and was all written: `SessionCloseStdin`; both are calls on a
//! connection of their own, answered once the monitor was told.  The
//! frontend closes the connection of the session when its client is gone:
//! as with podman, a command of an exec and a container go on without it.

/// The keys that end an attach session.
pub fn parse_detach_keys(spec: &str) -> Result<Vec<u8>, String> {
    let mut keys = Vec::new();
    if spec.is_empty() {
        return Ok(keys);
    }
    for tok in spec.split(',') {
        let b = tok.as_bytes();
        let key = if let Some(c) = tok.strip_prefix("ctrl-") {
            match c.as_bytes() {
                [c @ b'a'..=b'z'] => c - b'a' + 1,
                [b'@'] => 0,
                [c @ b'['..=b'_'] => c - b'[' + 27,
                _ => return Err(format!("invalid detach key `{tok}`")),
            }
        } else if b.len() == 1 {
            b[0]
        } else {
            return Err(format!("invalid detach key `{tok}`"));
        };
        keys.push(key);
        if keys.len() > 16 {
            return Err(format!("too many detach keys in `{spec}`"));
        }
    }
    Ok(keys)
}

/// Finds the detach sequence in the input of a terminal.
pub struct DetachMatcher {
    keys: Vec<u8>,
    held: Vec<u8>,
}

impl DetachMatcher {
    pub fn new(keys: Vec<u8>) -> Self {
        Self {
            keys,
            held: Vec::new(),
        }
    }

    /// The bytes to forward, and whether the sequence was typed.  Keys held
    /// back because they may start the sequence are forwarded once they
    /// turn out not to.
    pub fn feed(&mut self, input: &[u8]) -> (Vec<u8>, bool) {
        let mut out = Vec::with_capacity(input.len());
        if self.keys.is_empty() {
            out.extend_from_slice(input);
            return (out, false);
        }
        for &b in input {
            // the held keys and this byte: the longest end of them that
            // starts the sequence stays held, what is before it is input
            self.held.push(b);
            while !self.keys.starts_with(&self.held) {
                out.push(self.held.remove(0));
            }
            if self.held.len() == self.keys.len() {
                self.held.clear();
                return (out, true);
            }
        }
        (out, false)
    }
}

#[cfg(feature = "session")]
mod session;
#[cfg(feature = "session")]
pub use session::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detach_keys_parse() {
        assert_eq!(
            parse_detach_keys("ctrl-p,ctrl-q").unwrap(),
            vec![0x10, 0x11]
        );
        assert_eq!(parse_detach_keys("ctrl-@,x").unwrap(), vec![0, b'x']);
        assert_eq!(parse_detach_keys("ctrl-[").unwrap(), vec![27]);
        assert_eq!(parse_detach_keys("").unwrap(), Vec::<u8>::new());
        assert!(parse_detach_keys("ctrl-1").is_err());
        assert!(parse_detach_keys("ab").is_err());
        assert!(parse_detach_keys(&vec!["a"; 17].join(",")).is_err());
    }

    #[test]
    fn the_sequence_detaches_and_partial_matches_are_forwarded() {
        let mut m = DetachMatcher::new(vec![0x10, 0x11]);
        assert_eq!(m.feed(b"ab"), (b"ab".to_vec(), false));
        assert_eq!(m.feed(&[0x10]), (vec![], false));
        assert_eq!(m.feed(b"x"), (vec![0x10, b'x'], false));
        assert_eq!(m.feed(&[0x10, 0x10, 0x11]), (vec![0x10], true));
        // The sequence split across reads.
        let mut m = DetachMatcher::new(vec![0x10, 0x11]);
        assert_eq!(m.feed(&[b'a', 0x10]), (b"a".to_vec(), false));
        assert_eq!(m.feed(&[0x11, b'z']), (vec![], true));
        // A sequence that starts with a repeated key.
        let mut m = DetachMatcher::new(vec![0x10, 0x10, 0x11]);
        assert_eq!(m.feed(&[0x10, 0x10, 0x10, 0x11]), (vec![0x10], true));
        // No keys: everything passes.
        let mut m = DetachMatcher::new(vec![]);
        assert_eq!(m.feed(&[0x10, 0x11]), (vec![0x10, 0x11], false));
    }
}
