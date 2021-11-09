use core::convert::From;

use super::{algorithms, expect, RequesterError};
use crate::config::{MAX_CERT_CHAIN_SIZE, NUM_SLOTS};
use crate::msgs::algorithms::*;
use crate::msgs::capabilities::{ReqFlags, RspFlags};
use crate::msgs::{
    Algorithms, Certificate, Digests, GetCertificate, GetDigests, Msg,
    VersionEntry, HEADER_SIZE,
};
use crate::Transcript;

pub enum Transition {
    Placeholder,
}

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
    // key of the responder was provisioned in a trusted environment.
    pub digests: Option<Digests<NUM_SLOTS>>,
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
    /// Skip to the next state without sending GET_DIGEST and GET_CERTIFICATE
    /// requests.
    ///
    /// Indentity authentication is optional. We allow the user to skip this
    /// state entirely if they desire. This is useful if, as described in the spec, the
    /// public key of the responder was provisioned to the requester in a trusted
    /// environment.
    pub fn skip(self) -> Transition {

        // TODO: Return a real state
        Transition::Placeholder
    }

    /// Write a GET_DIGESTS msg to the buffer and record it in the transcript.
    ///
    /// TODO: We can probably shrink the transcript to the size of a hash at
    /// this point, since we know the hashing algorithm and can just maintain an
    /// incremental hash. For now, we just continue appending the raw data.
    pub fn write_get_digests_msg(
        &mut self,
        buf: &mut [u8],
        transcript: &mut Transcript,
    ) -> Result<usize, RequesterError> {
        let size = GetDigests {}.write(buf)?;
        transcript.extend(&buf[..size])?;
        Ok(size)
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
        expect::<Digests<NUM_SLOTS>>(buf)?;
        let digest_size = self.get_digest_size();
        let digests = Digests::parse_body(digest_size, &buf[HEADER_SIZE..])?;
        self.digests = Some(digests);
        transcript.extend(buf)?;
        Ok(())
    }

    /// Write a GET_CERTIFICATE msg to the buffer and record it in the
    /// transcript.
    pub fn write_get_certificate_msg(
        &mut self,
        slot: u8,
        buf: &mut [u8],
        transcript: &mut Transcript,
    ) -> Result<usize, RequesterError> {
        assert!(MAX_CERT_CHAIN_SIZE < 65536);
        assert!((slot as usize) < NUM_SLOTS);
        // TODO: Allow retrieiving cert chains from offsets. We assume for now
        // buffers are large enough to retrieve them in one round trip.
        let msg = GetCertificate {
            slot, offset: 0, length: MAX_CERT_CHAIN_SIZE as u16
        };
        let size = msg.write(buf)?;
        transcript.extend(&buf[..size])?;
        Ok(size)
    }

    // Handle a CERTFICATE msg.
    pub fn handle_certificate(
        mut self,
        buf: &[u8],
        transcript: &mut Transcript,
    ) -> Result<Transition, RequesterError> {
        expect::<Certificate<MAX_CERT_CHAIN_SIZE>>(buf)?;
        let cert = Certificate::parse_body(&buf[HEADER_SIZE..])?;
        self.cert_chain = Some(cert);
        transcript.extend(buf)?;
        Ok(Transition::Placeholder)
    }

    fn get_digest_size(&self) -> u8 {
        use BaseHashAlgo as H;
        match self.algorithms.base_hash_algo_selected {
            H::SHA_256 | H::SHA3_256 => 32,
            H::SHA_384 | H::SHA3_384 => 48,
            H::SHA_512 | H::SHA3_512 => 64,
            _ => unreachable!(),
        }
    }
}