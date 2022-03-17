// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use core::convert::From;
use core::fmt::Debug;

use super::{expect, id_auth, RequesterError};
use crate::config::Slot;
use crate::crypto::{
    pki::{self, EndEntityCert, Validator},
    Digests, Nonce,
};
use crate::msgs::{
    capabilities::{ReqFlags, RspFlags},
    challenge::ParseChallengeAuthError,
    Algorithms, CertificateChain, Challenge, ChallengeAuth,
    MeasurementHashType, Msg, VersionEntry, HEADER_SIZE,
};

use crate::Transcript;

// A provisioned certificate does not need to be retrieved
const PROVISIONED_MASK: u8 = 0x0F;

#[derive(Debug, PartialEq)]
pub enum ChallengeAuthError {
    /// The responder did not indicate the slot which was requested
    IncorrectSlot,

    /// The slot mask does not contain the slot filled in by the responder
    SlotNotInMask,

    /// The digest in the response does not match the cert chain at the
    /// requester
    DigestMismatch,

    /// The signature of the ChallengeAuth message is invalid
    InvalidSignature,

    /// Parsing failed for the ChallengeAuth message
    ParseChallengeAuth(ParseChallengeAuthError),

    /// Cert chain validation failed
    Pki(pki::Error),
}

impl From<ParseChallengeAuthError> for ChallengeAuthError {
    fn from(e: ParseChallengeAuthError) -> Self {
        ChallengeAuthError::ParseChallengeAuth(e)
    }
}

impl From<pki::Error> for ChallengeAuthError {
    fn from(e: pki::Error) -> Self {
        ChallengeAuthError::Pki(e)
    }
}

/// Perform challenge-response authentication using the certificate chain
/// received from the responder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub version: VersionEntry,
    pub requester_ct_exponent: u8,
    pub requester_cap: ReqFlags,
    pub responder_ct_exponent: u8,
    pub responder_cap: RspFlags,
    pub algorithms: Algorithms,
    pub slot_id: u8,
    pub nonce: Option<Nonce>,
}

impl From<id_auth::State> for State {
    fn from(s: id_auth::State) -> Self {
        State {
            version: s.version,
            requester_ct_exponent: s.requester_ct_exponent,
            requester_cap: s.requester_cap,
            responder_ct_exponent: s.responder_ct_exponent,
            responder_cap: s.responder_cap,
            algorithms: s.algorithms,
            slot_id: s.slot_id.unwrap(),
            nonce: None,
        }
    }
}

impl State {
    /// Write a CHALLENGE msg to the buffer, and append it to the transcript.
    pub fn write_msg<'a>(
        &mut self,
        buf: &'a mut [u8],
        transcript: &mut Transcript,
    ) -> Result<&'a [u8], RequesterError> {
        // We plan to have the user retrieve measurements in a secure channel
        // Is there also a need to retrieve them during challenge-response?
        let measurement_hash_type = MeasurementHashType::None;
        let challenge = Challenge::new(self.slot_id, measurement_hash_type);
        self.nonce = Some(challenge.nonce.clone());
        let size = challenge.write(buf).map_err(|e| RequesterError::from(e))?;
        transcript.extend(&buf[..size])?;
        Ok(&buf[..size])
    }

    /// Process a received responder message.
    ///
    /// Only CHALLENGE_AUTH msgs are acceptable here.
    pub fn handle_msg<'a, D, V>(
        &self,
        buf: &[u8],
        transcript: &mut Transcript,
        _: &D,
        validator: &V,
        responder_certs: &'a mut [Slot<'a>],
    ) -> Result<(), RequesterError>
    where
        D: Digests,
        V: for<'b> Validator<'b>,
    {
        expect::<ChallengeAuth>(buf)?;
        let hash_algo = self.algorithms.base_hash_algo_selected;
        let signing_algo = self.algorithms.base_asym_algo_selected;
        let digest_size = hash_algo.get_digest_size();
        let signature_size =
            self.algorithms.base_asym_algo_selected.get_signature_size();

        let rsp = ChallengeAuth::parse_body(
            &buf[HEADER_SIZE..],
            digest_size,
            signature_size,
        )?;

        if rsp.slot != self.slot_id {
            return Err(ChallengeAuthError::IncorrectSlot.into());
        }

        // A cert is not provisioned and it's not included in the slot mask
        if (rsp.slot != PROVISIONED_MASK)
            && ((rsp.slot_mask & (1 << rsp.slot)) == 0)
        {
            return Err(ChallengeAuthError::SlotNotInMask.into());
        }

        let slot = responder_certs
            .iter()
            .find(|slot| slot.id == self.slot_id)
            .unwrap();

        // TODO: Handle pre-provisioned certs
        let digest = D::digest(hash_algo, slot.as_slice());

        if rsp.cert_chain_hash.as_ref() != digest.as_ref() {
            return Err(ChallengeAuthError::DigestMismatch.into());
        }

        // TODO: Do something with returned measurements
        // TODO: Do something with opaque data

        // Generate M2 as in the SPDM spec by extending the transcript with the
        // ChallengeAuth response without the signature.
        let sig_start = buf.len() - usize::from(signature_size);
        transcript.extend(&buf[..sig_start])?;
        let m2_hash = D::digest(hash_algo, transcript.get());

        let cert_chain = CertificateChain::parse(slot.as_slice(), digest_size)?;

        // Validate the certificate chain using the trust authorities loaded
        // into `validator`.
        let end_entity_cert = validator.validate(signing_algo, cert_chain)?;

        // Verify the signature using the end entity cert parsed, used, and
        // returned by the validator.
        end_entity_cert.verify_signature(
            signing_algo,
            m2_hash.as_ref(),
            rsp.signature.as_ref(),
        )?;

        Ok(())
    }
}
