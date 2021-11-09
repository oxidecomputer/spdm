use super::{algorithms, capabilities, ResponderError};

use crate::config::{Config, MAX_CERT_CHAIN_SIZE, NUM_SLOTS};
use crate::crypto::digest::Digest;
use crate::msgs::algorithms::*;
use crate::msgs::capabilities::{ReqFlags, RspFlags};
use crate::msgs::digest::DigestBuf;
use crate::msgs::{
    Algorithms, Certificate, Digests, GetCertificate, GetDigests, Msg,
    ReadError, ReadErrorKind, HEADER_SIZE,
};
use crate::{reset_on_get_version, Transcript};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    Capabilities(capabilities::State),
    IdAuth(State),
    Placeholder,
}

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
    pub fn handle_msg<C: Config>(
        self,
        cert_chains: &[Option<&[u8]>; NUM_SLOTS],
        req: &[u8],
        rsp: &mut [u8],
        transcript: &mut Transcript,
    ) -> Result<(usize, Transition), ResponderError> {
        reset_on_get_version!(req, rsp, transcript);

        if GetDigests::parse_header(req)? {
            return self.handle_get_digests::<C>(
                cert_chains,
                req,
                rsp,
                transcript,
            );
        }

        if GetCertificate::parse_header(req)? {
            return self.handle_get_certificate(
                cert_chains,
                req,
                rsp,
                transcript,
            );
        }

        // TODO: Handle message that causes transition to next state.
        unimplemented!()
    }

    fn handle_get_certificate(
        self,
        cert_chains: &[Option<&[u8]>; NUM_SLOTS],
        req: &[u8],
        rsp: &mut [u8],
        transcript: &mut Transcript,
    ) -> Result<(usize, Transition), ResponderError> {
        let get_cert = GetCertificate::parse_body(&req[HEADER_SIZE..])?;
        if get_cert.slot as usize >= NUM_SLOTS {
            return Err(ReadError::new(
                GetCertificate::NAME,
                ReadErrorKind::ImplementationLimitReached,
            ).into());
        }
        let mut cert_chain = [0u8; MAX_CERT_CHAIN_SIZE];
        let mut portion_length: u16 = 0;
        if let Some(chain) = cert_chains[get_cert.slot as usize] {
            portion_length = chain.len() as u16;
            // TODO: Handle cert chains larger than response buffer (i.e. send
            // responses in multiple messages)
            cert_chain[..chain.len()].copy_from_slice(chain);
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

        Ok((size, Transition::IdAuth(self)))
    }

    fn handle_get_digests<C: Config>(
        self,
        cert_chains: &[Option<&[u8]>; NUM_SLOTS],
        req: &[u8],
        rsp: &mut [u8],
        transcript: &mut Transcript,
    ) -> Result<(usize, Transition), ResponderError> {
        let slot_mask = Self::create_slot_mask(cert_chains);
        let digests = self.hash_cert_chains::<C>(cert_chains);
        let digest_size = self.get_digest_size();
        let digests = Digests { digest_size, slot_mask, digests };
        let size = digests.write(rsp)?;

        transcript.extend(req)?;
        transcript.extend(&rsp[..size])?;

        Ok((size, Transition::IdAuth(self)))
    }

    fn hash_cert_chains<C: Config>(
        &self,
        cert_chains: &[Option<&[u8]>; NUM_SLOTS],
    ) -> [DigestBuf; NUM_SLOTS] {
        let mut digests = [DigestBuf::default(); NUM_SLOTS];
        for i in 0..NUM_SLOTS {
            if let Some(buf) = cert_chains[i] {
                let digest = C::Digest::hash(
                    self.algorithms.base_hash_algo_selected,
                    buf,
                );
                let len = digest.as_ref().len();
                digests[i].as_mut(len).copy_from_slice(digest.as_ref());
            }
        }
        digests
    }

    fn create_slot_mask(cert_chains: &[Option<&[u8]>; NUM_SLOTS]) -> u8 {
        let mut bits = 0u8;
        for i in 0..NUM_SLOTS {
            if cert_chains[i].is_some() {
                bits |= 1 << i;
            }
        }
        return bits;
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
