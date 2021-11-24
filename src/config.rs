// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::crypto::digest::Digest;

/// TODO: Don't Hardcode these sizes
///
/// It would be great if we could make these associated constants in `Config`
/// but unfortunately, we need these for array sizes, and associated constants
/// don't play well with that use case or const generics.
///
/// We can use associated constants with const generics with
/// `#![feature(const_evaluatable_checked)]` but that requires nightly.
/// See <https://github.com/rust-lang/rust/issues/76560>
/// The number of stored certificate chains used in the system. There can
/// be up to 8 slots.
///
/// While a responder can have more slots than this in use, the requester
/// will only store information and utilize the first NUM_SLOTS.
pub const NUM_SLOTS: usize = 1;

/// The maximum size of a certificate chain supported in the system. The
/// absolute maximum size supported by the spec is 65536 bytes.
pub const MAX_CERT_CHAIN_SIZE: usize = 1536;

/// This must be larger than MAX_CERT_CHAIN_SIZE
pub const TRANSCRIPT_SIZE: usize = 2048;

/// The maximum size of a hash in bytes.
pub const MAX_DIGEST_SIZE: usize = 64;

/// The maximum size of a signature in bytes
pub const MAX_SIGNATURE_SIZE: usize = 128;

/// ChallengeAuth responses allow opaque data.
/// This is probably not necessary for most users/transports.
pub const MAX_OPAQUE_DATA_SIZE: usize = 0;

/// The maximum depth of a certificate chain
pub const MAX_CERT_CHAIN_DEPTH: usize = 6;

/// A trait used to define algorithm implementations
///
/// Important: This trait will be going away as it is insufficient to capture
/// all crypto implementations, specifically those that require lifetime
/// parameters. This limitation is due to the lack of Generic Associated Type
/// (GAT) stabilization.
pub trait Config {
    /// The configured Digest implementation
    type Digest: Digest;
}
