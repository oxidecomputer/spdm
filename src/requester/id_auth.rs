// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use core::convert::TryFrom;

use super::{algorithms, expect, RequesterError};
use crate::msgs::capabilities::{ReqFlags, RspFlags};
use crate::msgs::{
    Algorithms, Certificate, Digests, GetCertificate, GetDigests, Msg,
    VersionEntry, HEADER_SIZE,
};
use crate::Transcript;
use crate::{Slot, SlotState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Id<'a> {
    PubKey(&'a [u8]),
    CertChain(&'a [u8]),
}

/// After the negotiation state, the requester has to identify the responder.
///
/// This state encapsulates the sending of GET_DIGESTS and GET_CERTIFICATE
/// requests and their correspdonging repsonses.
///
/// TODO: This code currently allows skipping both GET_DIGESTS and
/// GET_CERTIFICATE, but certificate caching is currently not done, and so you
/// cannot skip just GET_CERTIFICATE.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub version: VersionEntry,
    pub requester_ct_exponent: u8,
    pub requester_cap: ReqFlags,
    pub responder_ct_exponent: u8,
    pub responder_cap: RspFlags,
    pub algorithms: Algorithms,
    pub slot_id: Option<u8>,
    pub digests: Option<Digests>,
}

impl From<algorithms::State> for State {
    fn from(s: algorithms::State) -> Self {
        State {
            version: s.version,
            requester_ct_exponent: s.requester_ct_exponent,
            requester_cap: s.requester_cap,
            responder_ct_exponent: s.responder_ct_exponent,
            responder_cap: s.responder_cap,
            algorithms: s.algorithms.unwrap(),
            slot_id: None,
            digests: None,
        }
    }
}

impl State {
    /// Write a GET_DIGESTS msg to the buffer and record it in the transcript.
    ///
    /// TODO: We can probably shrink the transcript to the size of a hash at
    /// this point, since we know the hashing algorithm and can just maintain an
    /// incremental hash. For now, we just continue appending the raw data.
    pub fn write_get_digests_msg<'a>(
        &mut self,
        buf: &'a mut [u8],
        transcript: &mut Transcript,
    ) -> Result<&'a [u8], RequesterError> {
        let size = GetDigests {}.write(buf)?;
        transcript.extend(&buf[..size])?;
        Ok(&buf[..size])
    }

    /// Handle a DIGESTS msg.
    ///
    /// TODO: For now this takes &mut self since we don't support certificate caching
    /// yet. In the future this will likely take self and return a Transition, or this
    /// state will be split into 2 separate states.
    pub fn handle_digests(
        &mut self,
        buf: &[u8],
        transcript: &mut Transcript,
    ) -> Result<(), RequesterError> {
        expect::<Digests>(buf)?;
        let digest_size =
            self.algorithms.base_hash_algo_selected.get_digest_size();
        let digests = Digests::parse_body(digest_size, &buf[HEADER_SIZE..])?;
        self.digests = Some(digests);
        transcript.extend(buf)?;
        Ok(())
    }

    /// Write a GET_CERTIFICATE msg to the buffer and record it in the
    /// transcript.
    pub fn write_get_certificate_msg<'a, 'b>(
        &mut self,
        buf: &'a mut [u8],
        transcript: &mut Transcript,
        responder_certs: &mut [Slot<'b>],
    ) -> Result<&'a [u8], RequesterError> {
        // A requester must a-priori know what slots are filled by a
        // responder and what algotithms they use. There must not be
        // more than one slot with the same algorithm. The slot that
        // matches the negotiated algorithm should be retrieved.
        //
        // Here we find an empty responder slot for the
        // negotiated algorithm and send a request for it.
        let slot = responder_certs
            .iter()
            .filter(|slot| {
                slot.state == SlotState::Empty
                    && slot.algo == self.algorithms.base_asym_algo_selected
            })
            .next();

        if slot.is_none() {
            return Err(RequesterError::ResponderSlotNotEmpty);
        }

        let slot = slot.unwrap();

        // TODO: Allow retrieiving cert chains from offsets. We assume for now
        // buffers are large enough to retrieve them in one round trip.
        //
        let msg = GetCertificate {
            slot: slot.id(),
            offset: 0,
            length: u16::try_from(slot.capacity()).unwrap(),
        };
        let size = msg.write(buf)?;
        transcript.extend(&buf[..size])?;
        self.slot_id = Some(slot.id());
        Ok(&buf[..size])
    }

    // Handle a CERTFICATE msg.
    pub fn handle_certificate<'a>(
        &mut self,
        buf: &[u8],
        transcript: &mut Transcript,
        responder_certs: &'a mut [Slot<'a>],
    ) -> Result<Certificate<'a>, RequesterError> {
        expect::<Certificate>(buf)?;

        // We assume that a GET_CERTIFICATE message has already been sent, and
        // so a slot has been selected.
        let slot = responder_certs
            .iter_mut()
            .find(|slot| slot.id() == self.slot_id.unwrap())
            .unwrap();

        let digest_size =
            self.algorithms.base_hash_algo_selected.get_digest_size();

        // Read the cert chain into the proper slot
        let cert =
            Certificate::parse_body(&buf[HEADER_SIZE..], digest_size, slot)?;
        transcript.extend(buf)?;
        Ok(cert)
    }
}
