// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use core::convert::AsRef;

// Opaque error type
#[derive(Debug)]
pub struct Error {}

// Providers implement this trait to represent a digital signature.
pub trait Signature: AsRef<[u8]> {}

/// Providers implement this trait to generate digital signatures.
pub trait Signer {
    type Signature: Signature;

    fn sign(&self, msg: &[u8]) -> Result<Self::Signature, Error>;
}
