// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::config::{validate_slots, SlotConfigError};
use crate::crypto::{pki, Digests};
use crate::msgs::algorithms::BaseAsymAlgo;
use crate::msgs::capabilities::ReqFlags;
use crate::Slot;

use tinyvec::SliceVec;

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

    /// Requester and Responder certs do not use the same algorithms
    CertificateAlgorithmMismatch {
        requester_algos: BaseAsymAlgo,
        responder_algos: BaseAsymAlgo,
    },

    Slot(SlotConfigError),
}

impl From<SlotConfigError> for RequesterConfigError {
    fn from(e: SlotConfigError) -> Self {
        RequesterConfigError::Slot(e)
    }
}

// TODO: Use a new method, make some/most fields private
//
// To not require user to turbofish D/V
// impl RequesterConfig<'a, (), V> {
//     pub fn with_null_digests(...) -> Self { ...}
//     }
#[derive(Debug, PartialEq)]
pub struct RequesterConfig<'a, D, V> {
    pub(crate) digests: Option<D>,
    pub(crate) validator: Option<V>,

    /// This is only needed for mutual authentication, which we don't currently
    /// support. It's fine to leave it blank for now.
    my_certs: &'a [Slot<'a>],

    /// This is data received from the remote side of the connection and will
    /// be deserialized into the provided buffer.
    pub(crate) responder_certs: &'a mut [Slot<'a>],

    // Some messages accept opaque data fields from the requester
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
        requester_certs: &[Slot<'a>],
        responder_certs: &[Slot<'a>],
    ) -> Result<BaseAsymAlgo, RequesterConfigError> {
        let req_algos = requester_certs.iter().fold(
            BaseAsymAlgo::default(),
            |mut acc, slot| {
                acc |= slot.algo();
                acc
            },
        );
        let rsp_algos = responder_certs.iter().fold(
            BaseAsymAlgo::default(),
            |mut acc, slot| {
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
                return Err(RequesterConfigError::DigestsRequired(err_caps));
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

        validate_slots(&self.my_certs)?;
        validate_slots(&self.responder_certs)?;

        Ok(self)
    }
}
