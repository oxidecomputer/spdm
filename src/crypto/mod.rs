// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The crypto module provides the traits that the rest of the SPDM code relies
//! on to implement the cryptographic parts of the protocol.

pub mod digest;
mod nonce;
pub mod pki;
pub mod signing;
mod slot;

#[cfg(not(feature = "crypto"))]
mod no_crypto_defaults;
#[cfg(not(feature = "crypto"))]
pub use no_crypto_defaults::{FakeSigner, ProvidedDigests};

#[cfg(feature = "crypto-ring")]
pub mod ring;
#[cfg(feature = "crypto-ring")]
pub use self::ring::digest::ProvidedDigests;

pub use digest::{Digests, SupportedDigestAlgorithms};
pub use nonce::Nonce;
pub use signing::Signer;
pub use slot::FilledSlot;
