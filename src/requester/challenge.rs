// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use core::convert::From;

use super::{expect, id_auth, RequesterError};
use crate::config::MAX_CERT_CHAIN_SIZE;
use crate::crypto::{
    digest::{Digest, DigestImpl},
    pki::{new_end_entity_cert, EndEntityCert},
};
use crate::msgs::capabilities::{ReqFlags, RspFlags};
use crate::msgs::{
    Algorithms, CertificateChain, Challenge, ChallengeAuth,
    MeasurementHashType, Msg, VersionEntry, HEADER_SIZE,
};

use crate::Transcript;

// This is purposefully hardcoded as device certs mostly will not expire and we
// need *some* valid time. Furthermore, during early boot we will not have
// access to a trusted source of time.
//
// An alternative would be to disable the time checck in a patched version of
//  WebPKI.
//
// This may not work for all consumers of this library.
// Tracked in https://github.com/oxidecomputer/spdm/issues/31
//
// December 1, 2021 00:00:00 GMT
const UNIX_TIME: u64 = 1638316800;

#[derive(Debug, PartialEq, Eq)]
pub enum Transition {
    Placeholder,
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
    pub cert_slot: u8,
    pub cert_chain: [u8; MAX_CERT_CHAIN_SIZE],
    pub cert_chain_size: u16,
    pub nonce: [u8; 32],
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
            cert_slot: s.cert_chain.as_ref().unwrap().slot,
            cert_chain: s.cert_chain.as_ref().unwrap().cert_chain,
            cert_chain_size: s.cert_chain.unwrap().portion_length,
            nonce: [0u8; 32],
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
        let challenge = Challenge::new(self.cert_slot, measurement_hash_type);
        self.nonce = challenge.nonce;
        let size = challenge.write(buf).map_err(|e| RequesterError::from(e))?;
        transcript.extend(&buf[..size])?;
        Ok(&buf[..size])
    }

    /// Process a received responder message.
    ///
    /// Only CHALLENGE_AUTH msgs are acceptable here.
    pub fn handle_msg(
        self,
        buf: &[u8],
        transcript: &mut Transcript,
        root_cert: &[u8],
    ) -> Result<Transition, RequesterError> {
        expect::<ChallengeAuth>(buf)?;
        let hash_algo = self.algorithms.base_hash_algo_selected;

        let digest_size = hash_algo.get_digest_size();
        let signature_size =
            self.algorithms.base_asym_algo_selected.get_signature_size();
        let rsp = ChallengeAuth::parse_body(
            &buf[HEADER_SIZE..],
            digest_size,
            signature_size,
        )?;
        if rsp.slot != self.cert_slot {
            return Err(RequesterError::BadChallengeAuth);
        }
        // Provisioned certs don't need retrieval
        if (rsp.slot != 0x0F) && (rsp.slot_mask != (1 << rsp.slot)) {
            return Err(RequesterError::BadChallengeAuth);
        }

        // TODO: Handle pre-provisioned certs
        let digest = DigestImpl::hash(
            hash_algo,
            &self.cert_chain[..self.cert_chain_size as usize],
        );

        if rsp.cert_chain_hash() != digest.as_ref() {
            return Err(RequesterError::BadChallengeAuth);
        }

        // TODO: Do something with returned measurements
        // TODO: Do something with opaque data

        // Generate M2 as in the SPDM spec by extending the transcript with the
        // ChallengeAuth response without the signature.
        let sig_start = buf.len() - signature_size;
        transcript.extend(&buf[..sig_start])?;
        let m2_hash = DigestImpl::hash(hash_algo, transcript.get());

        self.verify_cert_chain_and_signature(
            digest_size,
            m2_hash.as_ref(),
            rsp.signature(),
            root_cert,
            UNIX_TIME,
        )
    }

    fn verify_cert_chain_and_signature(
        &self,
        digest_size: u8,
        m2_hash: &[u8],
        signature: &[u8],
        root_cert: &[u8],
        seconds_since_unix_epoch: u64,
    ) -> Result<Transition, RequesterError> {
        let cert_chain_buf = &self.cert_chain[..self.cert_chain_size as usize];
        let cert_chain = CertificateChain::parse(cert_chain_buf, digest_size)?;

        let end_entity_cert = new_end_entity_cert(cert_chain.leaf_cert)?;

        end_entity_cert.verify_chain_of_trust(
            self.algorithms.base_asym_algo_selected,
            cert_chain.intermediate_certs(),
            root_cert,
            seconds_since_unix_epoch,
        )?;

        if !end_entity_cert.verify_signature(
            self.algorithms.base_asym_algo_selected,
            m2_hash,
            signature,
        ) {
            return Err(RequesterError::BadChallengeAuth);
        }

        Ok(Transition::Placeholder)
    }
}
