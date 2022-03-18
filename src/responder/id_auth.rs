// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use core::convert::TryFrom;

use super::{algorithms, challenge, expect, AllStates, ResponderError};
use crate::crypto::{Digests as DigestsTrait, Signer};
use crate::msgs::{
    capabilities::{ReqFlags, RspFlags},
    common::DigestBuf,
    encoding::Writer,
    Algorithms, Certificate, Digests, GetCertificate, GetDigests, Msg,
    HEADER_SIZE,
};
use crate::Slot;
use crate::{reset_on_get_version, Transcript};

/// Create a slot mask where a `1` represents a present cert chain, and a `0`
/// indicates absence.
pub fn create_slot_mask<'a, S>(slots: &[(S, Slot<'a>)]) -> u8 {
    let mut bits = 0u8;
    for &(_, slot) in slots {
        bits |= 1 << slot.id;
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
    pub fn handle_msg<'a, S: Signer>(
        self,
        req: &[u8],
        rsp: &mut [u8],
        transcript: &mut Transcript,
        my_certs: &'a [(S, Slot<'a>)],
    ) -> Result<(usize, AllStates), ResponderError> {
        reset_on_get_version!(req, rsp, transcript);

        if GetDigests::parse_header(req)? {
            return self.handle_get_digests(req, rsp, transcript, my_certs);
        }

        // TODO: Handle more than one CERTIFICATE message. How do we decide when
        // to transfer to the next state then?
        expect::<GetCertificate>(req)?;
        self.handle_get_certificate(req, rsp, transcript, my_certs)
    }

    fn handle_get_certificate<'a, S>(
        self,
        req: &[u8],
        rsp: &mut [u8],
        transcript: &mut Transcript,
        my_certs: &'a [(S, Slot<'a>)],
    ) -> Result<(usize, AllStates), ResponderError> {
        let get_cert = GetCertificate::parse_body(&req[HEADER_SIZE..])?;
        let slot = my_certs.iter().find(|(_, slot)| get_cert.slot == slot.id);
        if slot.is_none() {
            return Err(ResponderError::InvalidSlot);
        }
        let (_, slot) = slot.unwrap();

        // TODO: Handle cert chains larger than response buffer (i.e. send
        // responses in multiple messages)
        let cert = Certificate {
            slot_id: slot.id,
            portion_length: u16::try_from(slot.len()).unwrap(),
            remainder_length: 0,
            cert_chain: slot,
        };

        let size = cert.write(rsp)?;
        transcript.extend(req)?;
        transcript.extend(&rsp[..size])?;

        Ok((size, challenge::State::from(self).into()))
    }

    fn handle_get_digests<'a, S>(
        self,
        req: &[u8],
        rsp: &mut [u8],
        transcript: &mut Transcript,
        my_certs: &'a [(S, Slot<'a>)],
    ) -> Result<(usize, AllStates), ResponderError> {
        let slot_mask = create_slot_mask(my_certs);
        let digests = self.hash_cert_chains(my_certs)?;

        let digests = Digests { slot_mask, digests };
        let size = digests.write(rsp)?;

        transcript.extend(req)?;
        transcript.extend(&rsp[..size])?;

        Ok((size, self.into()))
    }

    fn hash_cert_chains<'a, S>(
        &self,
        my_certs: &'a [(S, Slot<'a>)],
    ) -> Result<[Option<DigestBuf>; config::NUM_SLOTS], ResponderError> {
        // Avoid requiring DigestBuf to implement Copy
        const VAL: Option<DigestBuf> = None;
        let mut digests = [VAL; config::NUM_SLOTS];
        let mut buf = [0u8; MAX_CERT_CHAIN_SIZE];
        for i in 0..NUM_SLOTS {
            if let Some(cert_chain) = &cert_chains[i] {
                let mut w = Writer::new(&mut buf);
                let size = cert_chain.write(&mut w)?;
                let digest = ProvidedDigests::digest(
                    self.algorithms.base_hash_algo_selected,
                    &buf[..size],
                );
                digests[i] =
                    Some(DigestBuf::try_from(digest.as_ref()).unwrap());
            }
        }
        Ok(digests)
    }
}
