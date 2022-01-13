// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use core::convert::From;

use super::{algorithms, challenge, expect, RequesterError};
use crate::config::{MAX_CERT_CHAIN_SIZE, NUM_SLOTS};
use crate::msgs::capabilities::{ReqFlags, RspFlags};
use crate::msgs::{
    Algorithms, Certificate, Digests, GetCertificate, GetDigests, Msg,
    VersionEntry, HEADER_SIZE,
};
use crate::Transcript;

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

    // GET_DIGESTS and GET_CERTIFICATE messages will not be issued if the public
    // key of the responder was provisioned in a trusted environment or if
    // CAP_PSK is enabled.
    pub digests: Option<Digests>,
    pub cert_chain: Option<Certificate<MAX_CERT_CHAIN_SIZE>>,
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
            digests: None,
            cert_chain: None,
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
    pub fn write_get_certificate_msg<'a>(
        &mut self,
        slot: u8,
        buf: &'a mut [u8],
        transcript: &mut Transcript,
    ) -> Result<&'a [u8], RequesterError> {
        // TODO: Validate rather than assert in requester.rs ?
        assert!((slot as usize) < NUM_SLOTS);
        // TODO: Allow retrieiving cert chains from offsets. We assume for now
        // buffers are large enough to retrieve them in one round trip.
        let msg = GetCertificate {
            slot,
            offset: 0,
            length: MAX_CERT_CHAIN_SIZE as u16,
        };
        let size = msg.write(buf)?;
        transcript.extend(&buf[..size])?;
        Ok(&buf[..size])
    }

    // Handle a CERTFICATE msg.
    pub fn handle_certificate(
        mut self,
        buf: &[u8],
        transcript: &mut Transcript,
    ) -> Result<challenge::State, RequesterError> {
        expect::<Certificate<MAX_CERT_CHAIN_SIZE>>(buf)?;
        let cert = Certificate::parse_body(&buf[HEADER_SIZE..])?;
        self.cert_chain = Some(cert);
        transcript.extend(buf)?;
        Ok(self.into())
    }
}
