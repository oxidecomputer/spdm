// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::crypto::{pki, Digests};
use crate::msgs::algorithms::BaseAsymAlgo;
use crate::msgs::capabilities::ReqFlags;
use crate::msgs::encoding::{ReadError, Reader};

use core::mem;
use tinyvec::SliceVec;

/// This is the size in bytes of the largest buffer required for a signature
/// using the base asymmetric signing algorithms in the SPDM 1.2 spec,
/// not-including RSA.
///
/// See Table 15, Byte offset: 8, Field: BaseAsymAlgo in the SPDM 1.2 spec
pub const MAX_SIGNATURE_SIZE: usize = 132;

/// This is the size in bytes of the largest buffer required for a digest
/// See Table 15, Byte offset: 12, Field: BaseHashAlgo in the SPDM 1.2 spec
pub const MAX_DIGEST_SIZE: usize = 64;

pub enum SlotState {
    /// There is a full cert chain in the slot
    Full,
    /// There is no cert chain in the slot
    Empty,
    /// The cert chain has been partially retrieved in a CERTIFICATE msg
    /// This isn't yet in use.
    Partial,
}

/// Slots contain certificate chains or are placeholders for certificate
/// chains. There are 8 slot ids ranging from 0 to 7. Each slot's algorithm is
/// known a-priori whether it is for a requester or responder.
pub struct Slot<'a> {
    state: SlotState,
    id: u8,
    algo: BaseAsymAlgo,
    buf: SliceVec<'a, u8>,
}

impl<'a> Slot<'a> {
    fn new(
        state: SlotState,
        id: u8,
        algo: BaseAsymAlgo,
        buf: SliceVec<'a, u8>,
    ) -> Slot<'a> {
        Slot { state, id, algo, buf }
    }
    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn id(&self) -> u8 {
        self.id
    }

    pub fn algo(&self) -> BaseAsymAlgo {
        self.algo
    }

    pub fn fill<'b>(
        &mut self,
        reader: &mut Reader<'b>,
        len: usize,
    ) -> Result<(), ReadError> {
        // We don't currently allow partial fills
        assert!(self.state == SlotState::Empty);
        self.buf.set_len(len);
        if let Err(e) = reader.get_slice(len, self.buf.as_mut_slice()) {
            // Maintain invariant that len = 0 when state = SliceState::Empty
            self.buf.set_len(0);
            return Err(e);
        }
        self.state = SlotState::Full;
        Ok(())
    }

    pub(crate) fn clear(&mut self) {
        self.buf.clear();
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
    my_certs: &'a [Slot<'a>],

    /// This is data received from the remote side of the connection and will
    /// be deserialized into the provided buffer.
    responder_certs: &'a mut [Slot<'a>],

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
        my_certs: &'a Slot<'a>,
        responder_certs: &'a [Slot<'a>],
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

    pub(crate) fn responder_certs(&self) -> &'a [Slot<'a>] {
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
            if slot.algo().bits.count_ones() != 1 {
                return Err(
                    RequesterConfigError::SlotsMustHaveExactlyOneAlgoSelected,
                );
            }
        }

        Ok(self)
    }
}
