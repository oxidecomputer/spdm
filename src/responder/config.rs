// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::config::{validate_slots, SlotConfigError};
use crate::crypto::{Digests, Signer};
use crate::msgs::algorithms::BaseAsymAlgo;
use crate::msgs::capabilities::RspFlags;
use crate::Slot;

use tinyvec::SliceVec;

#[derive(Debug, PartialEq)]
pub enum ResponderConfigError {
    /// One or more capabilities requires a `Signer`
    SignerRequired(RspFlags),

    /// One or more capabilities requires a `Digests`
    DigestsRequired(RspFlags),

    /// The given capabilies are not yet supported by this library
    CapabiltiesNotSupported(RspFlags),

    // At least one provisioned cert is required to support the given
    // capabilities
    ResponderCertRequired(RspFlags),

    Slot(SlotConfigError),
}

impl From<SlotConfigError> for ResponderConfigError {
    fn from(e: SlotConfigError) -> Self {
        ResponderConfigError::Slot(e)
    }
}
/// Configuration for a Responder
///
// Once we support mutual auth we will provide cert slots for the requester and
/// a validator for those certs.
#[derive(Debug, PartialEq)]
pub struct ResponderConfig<'a, D, S> {
    digests: Option<D>,
    signer: Option<S>,

    /// This is only needed for mutual authentication, which we don't currently
    /// support. It's fine to leave it blank for now.
    my_certs: &'a [Slot<'a>],

    /// Some messages accept opaque data fields from the requester
    my_opaque_data: SliceVec<'a, u8>,

    /// This is data received from the remote side of the connection and will
    /// be deserialized into the provided buffer.
    requester_opaque_data: SliceVec<'a, u8>,

    capabilities: RspFlags,

    /// These get derived from my_certs and responder_certs
    asym_algos_supported: BaseAsymAlgo,
}

impl<'a, D, S> ResponderConfig<'a, D, S>
where
    D: Digests,
    S: Signer,
{
    pub fn new(
        digests: Option<D>,
        signer: Option<S>,
        my_certs: &'a [Slot<'a>],
        my_opaque_data: SliceVec<'a, u8>,
        requester_opaque_data: SliceVec<'a, u8>,
        capabilities: RspFlags,
    ) -> Result<ResponderConfig<'a, D, S>, ResponderConfigError> {
        let asym_algos_supported = Self::derive_asym_algos(my_certs);

        let config = ResponderConfig {
            digests,
            signer,
            my_certs,
            my_opaque_data,
            requester_opaque_data,
            capabilities,
            asym_algos_supported,
        };

        config.validate()
    }

    pub fn my_opaque_data(&mut self) -> &mut SliceVec<'a, u8> {
        &mut self.my_opaque_data
    }

    pub fn capabilities(&self) -> RspFlags {
        self.capabilities
    }

    pub fn digests(&self) -> &Option<D> {
        &self.digests
    }

    pub fn signer(&self) -> &Option<S> {
        &self.signer
    }

    pub fn asym_algos_supported(&self) -> BaseAsymAlgo {
        self.asym_algos_supported
    }

    // Return the superset of asymmetric signing algorithms provided in the
    // responder certs.
    fn derive_asym_algos(responder_certs: &'a [Slot<'a>]) -> BaseAsymAlgo {
        responder_certs.iter().fold(BaseAsymAlgo::default(), |acc, slot| {
            acc |= slot.algo();
            acc
        })
    }

    fn validate(self) -> Result<Self, ResponderConfigError> {
        let requiring_caps = RspFlags::CHAL_CAP;

        // Set intersection
        let err_caps = requiring_caps & self.capabilities;
        if !err_caps.is_empty() {
            if self.signer.is_none() {
                return Err(ResponderConfigError::SignerRequired(err_caps));
            }

            if self.digests.is_none() {
                return Err(ResponderConfigError::DigestsRequired(err_caps));
            }

            if self.my_certs.is_empty() {
                return Err(ResponderConfigError::ResponderCertRequired(
                    err_caps,
                ));
            }
        };

        let supported_caps = RspFlags::CHAL_CAP | RspFlags::CERT_CAP;

        // set difference
        let err_caps = self.capabilities - supported_caps;
        if !err_caps.is_empty() {
            return Err(ResponderConfigError::CapabiltiesNotSupported(
                err_caps,
            ));
        }

        // TODO: Ensure that all requester and responder certs use algorithms
        // supported by the  Validator

        validate_slots(&self.my_certs)?;

        Ok(self)
    }
}
