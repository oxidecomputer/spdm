// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::crypto::{pki, Digests};
use crate::msgs::algorithms::BaseAsymAlgo;
use crate::msgs::capabilities::ReqFlags;
use crate::msgs::encoding::{ReadError, Reader};

use core::mem;
use tinyvec::SliceVec;

// This is the size in bytes of the largest buffer required for a signature
// using the base asymmetric signing algorithms in the SPDM 1.2 spec,
// not-including RSA.
//
// See Table 15, Byte offset: 8, Field: BaseAsymAlgo in the SPDM 1.2 spec
pub const MAX_SIGNATURE_SIZE: usize = 132;

// This is the size in bytes of the largest buffer required for a digest
// See Table 15, Byte offset: 12, Field: BaseHashAlgo in the SPDM 1.2 spec
pub const MAX_DIGEST_SIZE: usize = 64;

// A slot contains a certificate chain. It can be either full or empty.
pub enum MutableSlot<'a> {
    Full(FilledSlot<'a>),
    Empty(EmptySlot<'a>),

    // A value used to allow mutation of an enum in place.
    // An application should never see this value.
    // See option 3: https://users.rust-lang.org/t/mutate-enum-in-place/18785/2
    Temporary,
}

impl<'a> MutableSlot<'a> {
    pub fn is_full(&self) -> bool {
        if let MutableSlot::Full(_) = self {
            true
        } else {
            false
        }
    }

    pub fn is_empty(&self) -> bool {
        !self.is_full()
    }

    pub fn id(&self) -> u8 {
        match self {
            MutableSlot::Full(f) => f.id(),
            MutableSlot::Empty(e) => e.id(),
            _ => panic!("Cannot be called in temporary state!"),
        }
    }

    pub fn capacity(&self) -> usize {
        match self {
            MutableSlot::Full(f) => f.buf.len(),
            MutableSlot::Empty(e) => e.buf.len(),
            _ => panic!("Cannot be called in a temporary state!"),
        }
    }

    // Fill in the empty slot and turn it into a filled slot.
    // Panic if the `self` is not empty.
    //
    // Invariant: Ensure that we never return from this method with the slot set
    // to "Temporary".
    pub(crate) fn fill<'b>(
        &mut self,
        len: usize,
        r: &mut Reader<'b>,
    ) -> Result<(), ReadError> {
        match mem::replace(self, MutableSlot::Temporary) {
            MutableSlot::Empty(empty_slot) => {
                if let Err(e) = r.get_slice(len, empty_slot.buf) {
                    // Must restore the empty slot as self.
                    *self = MutableSlot::Empty(empty_slot);
                    Err(e)
                } else {
                    *self = MutableSlot::Full(FilledSlot {
                        id: self.id,
                        algo: self.algo,
                        len,
                        buf: self.buf,
                    });
                    Ok(())
                }
            }
            _ => panic!("Cannot fill a slot that is not empty!"),
        }
    }
}

// A slot that does not yet contain a certificate chain
//
// All requesters are configured with a set of empty slots.
//
// If `CERT_CAP` is enabled, then the slots will be filled when the
// `CERTIFICATE` messages are received. Upon filling the slot will automatically
// be converted to a FilledSlot.
pub struct EmptySlot<'a> {
    id: u8,
    algo: BaseAsymAlgo,
    buf: &'a mut [u8],
}

impl<'a> EmptySlot<'a> {
    fn new(id: u8, algo: BaseAsymAlgo, buf: &'a mut [u8]) -> EmptySlot<'a> {
        EmptySlot { id, algo, buf }
    }

    pub fn id(&self) -> u8 {
        self.id
    }

    pub fn algo(&self) -> BaseAsymAlgo {
        self.algo
    }

    // Copy `len` bytes from a Reader into a slot
    pub(crate) fn fill<'b>(
        self,
        len: usize,
        r: &mut Reader<'b>,
    ) -> Result<FilledSlot<'a>, ReadError> {
        r.get_slice(len, self.buf)?;
        Ok(FilledSlot { id: self.id, algo: self.algo, len, buf: self.buf })
    }
}

// A slot that holds a certificate chain
pub struct FilledSlot<'a> {
    id: u8,
    algo: BaseAsymAlgo,
    len: usize,
    buf: &'a mut [u8],
}

impl<'a> FilledSlot<'a> {
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    pub fn id(&self) -> u8 {
        self.id
    }

    pub fn algo(&self) -> BaseAsymAlgo {
        self.algo
    }

    pub(crate) fn clear(self) -> EmptySlot<'a> {
        // Don't bother zeroing the data. It can't be read from EmptySlot<'a>
        // and it's public information anyway.
        EmptySlot { id: self.id, algo: self.algo, buf: self.buf }
    }
}

// A slot filled with a local cert, and not one that needs to be retrieved from
// a responder.
pub struct ImmutableSlot<'a> {
    id: u8,
    algo: BaseAsymAlgo,
    buf: &'a [u8],
}

impl<'a> ImmutableSlot<'a> {
    pub fn new(id: u8, algo: BaseAsymAlgo, buf: &'a [u8]) -> ImmutableSlot<'a> {
        ImmutableSlot { id, algo, buf }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn id(&self) -> u8 {
        self.id
    }

    pub fn algo(&self) -> BaseAsymAlgo {
        self.algo
    }
}

#[derive(Debug, PartialEq)]
pub enum RequesterConfigError {
    /// One or more capabilities requires a `Validator`
    ValidatorRequired(ReqFlags),

    /// One or more capabilities requires a `Digests`
    DigestsRequired(ReqFlags),

    /// The given capabilies are not yet supported by this library
    CapabiltiesNotSupported(ReqFlags),

    /// At least one responder cert slot is needed to support the given
    /// capabilities.
    ResponderCertRequired(ReqFlags),

    /// At least one provisioned cert slot is required to support the given
    /// capabilities
    MyCertRequired(ReqFlags),

    /// Currently we don't support provisioning of remote certs, so we always
    /// require `CERT_CAP` if `CHAL_CAP` is given.
    ///
    /// This restriction may be removed in the future.
    ChalCapRequiresCertCap,

    /// Slots must have exactly one bit set for `algo`
    SlotsMustHaveExactlyOneAlgoSelected,
}

// TODO: Use a new method, make some/most fields private
//
// To not require user to turbofish D/V
// impl RequesterConfig<'a, (), V> {
//     pub fn with_null_digests(...) -> Self { ...}
//     }
#[derive(Debug, Clone)]
pub struct RequesterConfig<'a, D, V> {
    digests: Option<D>,
    validator: Option<V>,

    /// This is only needed for mutual authentication, which we don't currently
    /// support. It's fine to leave it blank for now.
    my_certs: &'a [ImmutableSlot<'a>],

    /// This is data received from the remote side of the connection and will
    /// be deserialized into the provided buffer.
    responder_certs: &'a mut [MutableSlot<'a>],

    // Some mess
    my_opaque_data: SliceVec<'a, u8>,

    /// This is data received from the remote side of the connection and will
    /// be deserialized into the provided buffer.
    responder_opaque_data: SliceVec<'a, u8>,

    capabilities: ReqFlags,
}

impl<'a, D, V> RequesterConfig<'a, D, V>
where
    D: Digests,
    V: for<'b> pki::Validator<'b>,
{
    pub fn new(
        digests: Option<D>,
        validator: Option<V>,
        my_certs: &'a MutableSlot<'a>,
        responder_certs: &'a [MutableSlot<'a>],
        my_opaque_data: SliceVec<'a, u8>,
        responder_opaque_data: SliceVec<'a, u8>,
        capabilities: ReqFlags,
    ) -> Result<RequesterConfig<'a, D, V>, RequesterConfigError> {
        let config = RequesterConfig {
            digests,
            validator,
            my_certs,
            responder_certs,
            my_opaque_data,
            responder_opaque_data,
            capabilities,
        };

        config.validate()
    }

    pub(crate) fn responder_certs(&self) -> &'a [MutableSlot<'a>] {
        self.responder_certs
    }

    pub fn my_opaque_data(&mut self) -> &mut SliceVec<'a, u8> {
        &mut self.my_opaque_data
    }

    // TODO: Be sure to update this as more capabilities are added
    fn validate(self) -> Result<Self, RequesterConfigError> {
        if self.capabilities.contains(ReqFlags::CHAL_CAP)
            && !self.capabilities.contains(ReqFlags::CERT_CAP)
        {
            return Err(RequesterConfigError::ChalCapRequiresCertCap);
        }

        let requiring_caps = ReqFlags::CERT_CAP | ReqFlags::CHAL_CAP;

        // Set intersection
        let err_caps = requiring_caps & self.capabilities;
        if !err_caps.is_empty() {
            if !self.validator {
                return Err(RequesterConfigError::ValidatorRequired(err_caps));
            }

            if !self.digests {
                return Err(RequesterConfigError::ValidatorRequired(err_caps));
            }

            if self.responder_certs.is_empty() {
                return Err(RequesterConfigError::ResponderCertRequired);
            }
        };

        let supported_caps = ReqFlags::CHAL_CAP | ReqFlags::CERT_CAP;

        // set difference
        let err_caps = self.capabilities - supported_caps;
        if !err_caps.is_empty() {
            return Err(RequesterConfigError::CapabiltiesNotSupported);
        }

        // TODO: Ensure that all requester and responder certs use algorithms
        // supported by the  Validator

        // Ensure that exactly one bit of BaseAsymAlgo is set for each algorithm in
        // `my_certs` and `responder_certs`.
        for slot in &self.my_certs {
            if slot.algo().bits().count_ones() != 1 {
                return Err(
                    RequesterConfigError::SlotsMustHaveExactlyOneAlgoSelected,
                );
            }
        }

        for slot in &self.responder_certs {
            match slot {
                MutableSlot::Full(s) => {
                    if s.algo().bits.count_ones() != 1 {
                        return Err(
                    RequesterConfigError::SlotsMustHaveExactlyOneAlgoSelected);
                    }
                }
                MutableSlot::Empty(s) => {
                    if s.algo().bits.count_ones() != 1 {
                        return Err(
                    RequesterConfigError::SlotsMustHaveExactlyOneAlgoSelected,
                );
                    }
                }
            }
        }

        Ok(self)
    }
}
