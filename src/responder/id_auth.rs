// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::{algorithms, challenge, expect, AllStates, ResponderError};

use crate::config::{MAX_CERT_CHAIN_SIZE, NUM_SLOTS};
use crate::crypto::digest::{Digest, DigestImpl};
use crate::msgs::{
    capabilities::{ReqFlags, RspFlags},
    common::DigestBuf,
    encoding::Writer,
    Algorithms, Certificate, CertificateChain, Digests, GetCertificate,
    GetDigests, Msg, ReadError, ReadErrorKind, HEADER_SIZE,
};
use crate::{reset_on_get_version, Transcript};

/// Create a slot mask where a `1` represents a present cert chain, and a `0`
/// indicates absence.
pub fn create_slot_mask<'a, T: 'a>(slots: &[Option<T>; NUM_SLOTS]) -> u8 {
    let mut bits = 0u8;
    for i in 0..NUM_SLOTS {
        if slots[i].is_some() {
            bits |= 1 << i;
        }
    }
    return bits;
}

/// The state where digests and certificates are sent to a requester in order to
/// identify a responder.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub requester_ct_exponent: u8,
    pub requester_cap: ReqFlags,
    pub responder_ct_exponent: u8,
    pub responder_cap: RspFlags,
    pub algorithms: Algorithms,
}

impl From<algorithms::State> for State {
    fn from(s: algorithms::State) -> Self {
        State {
            requester_ct_exponent: s.requester_ct_exponent,
            requester_cap: s.requester_cap,
            responder_ct_exponent: s.responder_ct_exponent,
            responder_cap: s.responder_cap,
            algorithms: s.algorithms.unwrap(),
        }
    }
}

impl State {
    /// Handle a message from a requester.
    ///
    /// Only GET_VERSION, GET_DIGESTS, and GET_CERTIFICATE messsages are
    /// allowed.
    pub fn handle_msg<'a>(
        self,
        cert_chains: &[Option<CertificateChain<'a>>; NUM_SLOTS],
        req: &[u8],
        rsp: &mut [u8],
        transcript: &mut Transcript,
    ) -> Result<(usize, AllStates), ResponderError> {
        reset_on_get_version!(req, rsp, transcript);

        if GetDigests::parse_header(req)? {
            return self.handle_get_digests(cert_chains, req, rsp, transcript);
        }

        // TODO: Handle more than one CERTIFICATE message. How do we decide when
        // to transfer to the next state then?
        expect::<GetCertificate>(req)?;
        self.handle_get_certificate(cert_chains, req, rsp, transcript)
    }

    fn handle_get_certificate<'a>(
        self,
        cert_chains: &[Option<CertificateChain<'a>>; NUM_SLOTS],
        req: &[u8],
        rsp: &mut [u8],
        transcript: &mut Transcript,
    ) -> Result<(usize, AllStates), ResponderError> {
        let get_cert = GetCertificate::parse_body(&req[HEADER_SIZE..])?;
        if get_cert.slot as usize >= NUM_SLOTS {
            return Err(ReadError::new(
                GetCertificate::NAME,
                ReadErrorKind::ImplementationLimitReached,
            )
            .into());
        }

        // TODO: Handle cert chains larger than response buffer (i.e. send
        // responses in multiple messages)
        let mut cert_chain = [0u8; MAX_CERT_CHAIN_SIZE];
        let mut portion_length: u16 = 0;
        if let Some(chain) = &cert_chains[get_cert.slot as usize] {
            let mut w = Writer::new("CERTIFICATE_CHAIN", &mut cert_chain);
            portion_length = chain.write(&mut w)? as u16;
        }

        let cert = Certificate {
            slot: get_cert.slot,
            portion_length,
            remainder_length: 0,
            cert_chain,
        };

        let size = cert.write(rsp)?;
        transcript.extend(req)?;
        transcript.extend(&rsp[..size])?;

        Ok((size, challenge::State::from(self).into()))
    }

    fn handle_get_digests<'a>(
        self,
        cert_chains: &[Option<CertificateChain<'a>>; NUM_SLOTS],
        req: &[u8],
        rsp: &mut [u8],
        transcript: &mut Transcript,
    ) -> Result<(usize, AllStates), ResponderError> {
        let slot_mask = create_slot_mask(cert_chains);
        let digests = self.hash_cert_chains(cert_chains)?;

        let digests = Digests { slot_mask, digests };
        let size = digests.write(rsp)?;

        transcript.extend(req)?;
        transcript.extend(&rsp[..size])?;

        Ok((size, self.into()))
    }

    fn hash_cert_chains<'a>(
        &self,
        cert_chains: &[Option<CertificateChain<'a>>; NUM_SLOTS],
    ) -> Result<[DigestBuf; NUM_SLOTS], ResponderError> {
        let digest_size =
            self.algorithms.base_hash_algo_selected.get_digest_size();
        let mut digests = [DigestBuf::new(digest_size); NUM_SLOTS];
        let mut buf = [0u8; MAX_CERT_CHAIN_SIZE];
        for i in 0..NUM_SLOTS {
            if let Some(cert_chain) = &cert_chains[i] {
                let mut w = Writer::new("CERTIFICATE_CHAIN", &mut buf);
                let size = cert_chain.write(&mut w)?;
                let digest = DigestImpl::hash(
                    self.algorithms.base_hash_algo_selected,
                    &buf[..size],
                );
                digests[i].as_mut().copy_from_slice(digest.as_ref());
            }
        }
        Ok(digests)
    }
}
