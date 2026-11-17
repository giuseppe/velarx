//! Cryptographic hash digest wrappers.
//!
//! Provides [`Digest`] and [`FixedOutputReset`] traits with concrete
//! implementations for SHA-256, SHA-384, and SHA-512.
//!
//! Vendored by velarx: backed by the RustCrypto `sha2` crate instead of the
//! system OpenSSL library, so that the processes that only read layer
//! images (the monitor, the image server) link no TLS library.

use sha2::digest::Digest as _;
use std::fmt;

/// The output type of a [`Digest`] algorithm.
pub type Output<D> = <D as Digest>::Output;

/// Trait for cryptographic hash digest algorithms.
pub trait Digest: fmt::Debug {
    /// Fixed-size byte array produced by this algorithm.
    type Output: AsRef<[u8]> + AsMut<[u8]> + Clone + fmt::Debug + PartialEq + Eq;

    /// Create a new hasher instance.
    fn new() -> Self;

    /// Feed data into the hasher.
    fn update(&mut self, data: impl AsRef<[u8]>);

    /// Consume the hasher and return the digest.
    fn finalize(self) -> Self::Output;

    /// Compute the digest of `data` in one step.
    fn digest(data: impl AsRef<[u8]>) -> Self::Output
    where
        Self: Sized,
    {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

/// A [`Digest`] that can return its output and start over.
pub trait FixedOutputReset: Digest {
    /// Return the digest and reset the hasher to its initial state.
    fn finalize_reset(&mut self) -> Self::Output;
}

macro_rules! impl_digest {
    ($name:ident, $inner:ty, $size:literal) => {
        /// A hasher of this algorithm.
        #[derive(Clone)]
        pub struct $name($inner);

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl Digest for $name {
            type Output = [u8; $size];

            fn new() -> Self {
                Self(<$inner>::new())
            }

            fn update(&mut self, data: impl AsRef<[u8]>) {
                self.0.update(data.as_ref());
            }

            fn finalize(self) -> [u8; $size] {
                let mut out = [0u8; $size];
                out.copy_from_slice(&self.0.finalize());
                out
            }
        }

        impl FixedOutputReset for $name {
            fn finalize_reset(&mut self) -> [u8; $size] {
                let mut out = [0u8; $size];
                out.copy_from_slice(&self.0.finalize_reset());
                out
            }
        }
    };
}

impl_digest!(Sha256, sha2::Sha256, 32);
impl_digest!(Sha384, sha2::Sha384, 48);
impl_digest!(Sha512, sha2::Sha512, 64);
