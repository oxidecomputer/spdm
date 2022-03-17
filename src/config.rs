// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::crypto::{pki, Digests};
use crate::msgs::algorithms::BaseAsymAlgo;
use crate::msgs::capabilities::ReqFlags;
use crate::msgs::encoding::{ReadError, Reader};

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

/// The number of possible slots in the SPDM
pub const NUM_SLOTS: usize = 8;

/// TODO: Eventually we will get rid of the need for this by maintaining a rolling
/// hash.
pub const TRANSCRIPT_SIZE: usize = 512;

/// The state of a slot holding a certificate chain.
///
/// A local slot is always full. A slot that is retrieved from requester or
/// responder may not yet be full.
#[derive(Debug, PartialEq)]
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
#[derive(Debug, PartialEq)]
pub struct Slot<'a> {
    pub state: SlotState,
    pub id: u8,
    pub algo: BaseAsymAlgo,
    pub buf: SliceVec<'a, u8>,
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

    pub fn capacity(&self) -> usize {
        self.buf.capacity()
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

    /// The provided algorithm is not supported.
    AlgorithmNotSupported(BaseAsymAlgo),

    /// Each slot must use a unique algorithm
    /// This is necessary so the implementation can choose which slot to use
    /// based on the selected algorithm.
    ///
    /// It's anticipated that different requesters can chose different slots
    /// depending upon the given responder, so this should not be problematic.
    AlgorithmUsedInMoreThanOneSlot(BaseAsymAlgo),

    /// Requester and Responder certs do not use the same algorithms
    CertificateAlgorithmMismatch {
        requester_algos: BaseAsymAlgo,
        responder_algos: BaseAsymAlgo,
    },
}

// TODO: Use a new method, make some/most fields private
//
// To not require user to turbofish D/V
// impl RequesterConfig<'a, (), V> {
//     pub fn with_null_digests(...) -> Self { ...}
//     }
#[derive(Debug, PartialEq)]
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

    /// These get derived from my_certs and responder_certs
    asym_algos_supported: BaseAsymAlgo,
}

impl<'a, D, V> RequesterConfig<'a, D, V>
where
    D: Digests,
    V: for<'b> pki::Validator<'b>,
{
    pub fn new(
        digests: Option<D>,
        validator: Option<V>,
        my_certs: &'a [Slot<'a>],
        responder_certs: &'a mut [Slot<'a>],
        my_opaque_data: SliceVec<'a, u8>,
        responder_opaque_data: SliceVec<'a, u8>,
        capabilities: ReqFlags,
    ) -> Result<RequesterConfig<'a, D, V>, RequesterConfigError> {
        let asym_algos_supported =
            Self::derive_asym_algos(my_certs, responder_certs)?;

        let config = RequesterConfig {
            digests,
            validator,
            my_certs,
            responder_certs,
            my_opaque_data,
            responder_opaque_data,
            capabilities,
            asym_algos_supported,
        };

        config.validate()
    }

    pub(crate) fn responder_certs(&mut self) -> &mut [Slot<'a>] {
        self.responder_certs
    }

    pub fn my_opaque_data(&mut self) -> &mut SliceVec<'a, u8> {
        &mut self.my_opaque_data
    }

    pub fn capabilities(&self) -> ReqFlags {
        self.capabilities
    }

    pub fn digests(&self) -> &Option<D> {
        &self.digests
    }

    pub fn asym_algos_supported(&self) -> BaseAsymAlgo {
        self.asym_algos_supported
    }

    pub fn validator(&self) -> &Option<V> {
        &self.validator
    }

    // Ensure that the requester and responder certs match algorithms and then
    // report the supported algorithms.
    fn derive_asym_algos(
        requester_certs: &'a [Slot<'a>],
        responder_certs: &'a [Slot<'a>],
    ) -> Result<BaseAsymAlgo, RequesterConfigError> {
        let req_algos = requester_certs.iter().fold(
            BaseAsymAlgo::default(),
            |acc, slot| {
                acc |= slot.algo();
                acc
            },
        );
        let rsp_algos = responder_certs.iter().fold(
            BaseAsymAlgo::default(),
            |acc, slot| {
                acc |= slot.algo();
                acc
            },
        );

        if req_algos != rsp_algos {
            Err(RequesterConfigError::CertificateAlgorithmMismatch {
                requester_algos: req_algos,
                responder_algos: rsp_algos,
            })
        } else {
            Ok(req_algos)
        }
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
            if self.validator.is_none() {
                return Err(RequesterConfigError::ValidatorRequired(err_caps));
            }

            if self.digests.is_none() {
                return Err(RequesterConfigError::ValidatorRequired(err_caps));
            }

            if self.responder_certs.is_empty() {
                return Err(RequesterConfigError::ResponderCertRequired(
                    err_caps,
                ));
            }
        };

        let supported_caps = ReqFlags::CHAL_CAP | ReqFlags::CERT_CAP;

        // set difference
        let err_caps = self.capabilities - supported_caps;
        if !err_caps.is_empty() {
            return Err(RequesterConfigError::CapabiltiesNotSupported(
                err_caps,
            ));
        }

        // TODO: Ensure that all requester and responder certs use algorithms
        // supported by the  Validator

        Self::validate_slots(&self.my_certs)?;
        Self::validate_slots(&self.responder_certs)?;

        Ok(self)
    }

    // Ensure that exactly one bit of BaseAsymAlgo is set for each algorithm in
    // `my_certs` and `responder_certs`.
    //
    // Also ensure that no more than one slot has the same algorithm.
    fn validate_slots(slots: &[Slot<'a>]) -> Result<(), RequesterConfigError> {
        // We don't support RSA, and need to add Ed25519 once we upgrade the
        // algorithms message to 1.2.
        let mut counts = heapless::LinearMap::<BaseAsymAlgo, usize, 3>::new();
        counts.insert(BaseAsymAlgo::ECDSA_ECC_NIST_P256, 0).unwrap();
        counts.insert(BaseAsymAlgo::ECDSA_ECC_NIST_P384, 0).unwrap();
        counts.insert(BaseAsymAlgo::ECDSA_ECC_NIST_P521, 0).unwrap();

        for slot in slots {
            if slot.algo().bits().count_ones() != 1 {
                return Err(
                    RequesterConfigError::SlotsMustHaveExactlyOneAlgoSelected,
                );
            }
            match counts.get_mut(&slot.algo()) {
                Some(count) => {
                    *count += 1;
                    if *count > 1 {
                        return Err(
                        RequesterConfigError::AlgorithmUsedInMoreThanOneSlot(slot.algo)
                        );
                    }
                }
                None => {
                    return Err(RequesterConfigError::AlgorithmNotSupported(
                        slot.algo,
                    ));
                }
            }
        }

        Ok(())
    }
}
