// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A provider implements cryptographic mechanisms required by the SPDM protocol.
//! Each mechanism supports some number of different algorithms.
//!
//! An example of a mechanism is a *digest*, which may support SHA_256 and SHA_512
//! algorithms. A provider of a digest mechanism would be something like `ring`
//! or `RustCrypto`.

use super::digest::Digest;
use super::pki::EndEntityCert;
use super::signing::{Signature, Signer};

pub trait CryptoProvider {
    type Digest: Digest;
    type Pki: PkiProvider;
    type Signature: SignatureProvider;
}

pub trait PkiProvider {
    type EndEntityCert: EndEntityCert;
}

// TODO: Maybe add `Verifier`. Do we want to only allow verification via pki?
pub trait SignatureProvider {
    type Signature: Signature;
    type Signer: Signer;
}
