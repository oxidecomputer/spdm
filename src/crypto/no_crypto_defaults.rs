// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! This module provides unimplemented, dummy instances of types and functions
//! for use of this library without the "crypto" feature enabled.
//!
//! This mechanism allows the higher level code to be compiled without littering
//! conditional compilation directives across the requester and responder.
//!
//! Mechanisms higher up the stack are used to ensure that these default
//! implementations are never actually called. If any of these functions or
//! methods panics then we have a bug up the stack where states are being
//! transitioned to where the capabilities are not enabled.

use core::convert::TryFrom;
use core::marker::PhantomData;

use crate::msgs::{
    algorithms::{BaseAsymAlgo, BaseHashAlgo},
    common::DigestBuf,
};

use super::{
    pki::{self, EndEntityCert},
    signing::{self, Signature, Signer},
    Digests,
};

pub struct ProvidedDigests;

// We have to actually provide at least one algorithm for use in the
// ALGORITHMS message exchange. However, if no real crypto provider is given,
// the code that uses this algorithm will not be compiled.
impl ProvidedDigests {
    pub fn supported_algorithms() -> BaseHashAlgo {
        BaseHashAlgo::SHA_256
    }
}

// We implement this manually here since we want panics if this is ever called.
impl Digests for ProvidedDigests {
    fn update(&mut self, _: impl AsRef<[u8]>) {
        unimplemented!();
    }
    fn finalize(self) -> DigestBuf {
        unimplemented!();
    }
    fn digest(_: BaseHashAlgo, _: impl AsRef<[u8]>) -> DigestBuf {
        unimplemented!();
    }
}

impl TryFrom<BaseHashAlgo> for ProvidedDigests {
    type Error = ();
    fn try_from(_: BaseHashAlgo) -> Result<Self, Self::Error> {
        unimplemented!();
    }
}

pub fn new_end_entity_cert<'a>(
    _: &'a [u8],
) -> Result<impl EndEntityCert<'a>, pki::Error> {
    Ok(FakeEndEntityCert { phantom: PhantomData })
}

pub struct FakeEndEntityCert<'a> {
    phantom: PhantomData<&'a [u8]>,
}

impl<'a> EndEntityCert<'a> for FakeEndEntityCert<'a> {
    fn verify_signature(&self, _: BaseAsymAlgo, _: &[u8], _: &[u8]) -> bool {
        unimplemented!();
    }

    fn verify_chain_of_trust(
        &self,
        _: BaseAsymAlgo,
        _: &[&[u8]],
        _: &[u8],
        _: u64,
    ) -> Result<(), pki::Error> {
        unimplemented!();
    }
}

pub struct FakeSigner;

pub struct FakeSignature;

impl Signature for FakeSignature {}
impl AsRef<[u8]> for FakeSignature {
    fn as_ref(&self) -> &[u8] {
        unimplemented!()
    }
}

impl Signer for FakeSigner {
    type Signature = FakeSignature;
    fn sign(&self, _msg: &[u8]) -> Result<Self::Signature, signing::Error> {
        unimplemented!();
    }
}
