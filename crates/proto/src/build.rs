// SPDX-License-Identifier: Apache-2.0
//! What crosses with a build: the document that says what to build is
//! [`crate::buildspec::BuildSpec`]; `ImageBuild` carries it as JSON in a
//! pipe, next to the pipe the build context streams through.

/// The most bytes of a build spec.
pub const MAX_BUILD_SPEC: usize = 1 << 20;

/// The context crosses its pipe in frames: a 4-byte big-endian length,
/// then that many bytes (at most this many); an empty frame ends it.  A
/// pipe that ends without the empty frame is an upload the client did not
/// finish (a tar cut between two entries is a valid tar of fewer files:
/// the end of the pipe alone could not tell).
pub const MAX_CONTEXT_FRAME: usize = 1 << 20;

/// The most bytes of a frame of a download.
pub const MAX_FRAME: usize = 1 << 20;

/// The name of the section of a multipart body that is the main context
/// (the sections: a frame with the name, the frames of the content, the
/// empty frame; the empty frame in the place of a name ends them).
pub const SECTION_MAIN: &str = "main";
/// The start of the name of a section that is a named context.
pub const SECTION_CONTEXT: &str = "context:";
/// A frame of this length in the place of a frame gives the upload up: the
/// length of the reason (at most [`MAX_ABORT_REASON`]) and the reason follow.
pub const FRAME_ABORT: u32 = u32::MAX;
pub const MAX_ABORT_REASON: usize = 4096;

/// No byte of the context for this long: the upload stalled, the engine
/// gives it up (an upload as such has no time limit).
pub const CONTEXT_STALL: std::time::Duration = std::time::Duration::from_secs(600);
