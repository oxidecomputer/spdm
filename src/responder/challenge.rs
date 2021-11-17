use core::convert::From;

use super::{capabilities, expect, id_auth, ResponderError};

use crate::config::{
    Config, MAX_CERT_CHAIN_SIZE, MAX_DIGEST_SIZE, MAX_SIGNATURE_SIZE, NUM_SLOTS,
};
use crate::crypto::{digest::Digest, signing::Signer};
use crate::msgs::capabilities::{ReqFlags, RspFlags};
use crate::msgs::{
    challenge::nonce, encoding::Writer, Algorithms, CertificateChain,
    Challenge, ChallengeAuth, Msg, HEADER_SIZE,
};
use crate::{reset_on_get_version, Transcript};

#[derive(Debug, PartialEq, Eq)]
pub enum Transition {
    Capabilities(capabilities::State),
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

impl From<id_auth::State> for State {
    fn from(s: id_auth::State) -> Self {
        State {
            requester_ct_exponent: s.requester_ct_exponent,
            requester_cap: s.requester_cap,
            responder_ct_exponent: s.responder_ct_exponent,
            responder_cap: s.responder_cap,
            algorithms: s.algorithms,
        }
    }
}

impl State {
    pub fn handle_msg<'a, C: Config, S: Signer>(
        self,
        cert_chains: &[Option<CertificateChain<'a>>; NUM_SLOTS],
        signer: &S,
        req: &[u8],
        rsp: &mut [u8],
        transcript: &mut Transcript,
    ) -> Result<(usize, Transition), ResponderError> {
        reset_on_get_version!(req, rsp, transcript);
        expect::<Challenge>(req)?;
        let digest_size =
            self.algorithms.base_hash_algo_selected.get_digest_size();
        let signature_size =
            self.algorithms.base_asym_algo_selected.get_signature_size();

        let req_msg = Challenge::parse_body(&req[HEADER_SIZE..])?;

        let cert_chain_digest =
            if let Some(Some(chain)) = cert_chains.get(req_msg.slot as usize) {
                let mut buf = [0u8; MAX_CERT_CHAIN_SIZE];
                let mut w = Writer::new("CERTIFICATE_CHAIN", &mut buf);
                let size = chain.write(&mut w)?;
                C::Digest::hash(
                    self.algorithms.base_hash_algo_selected,
                    &buf[..size],
                )
            } else {
                return Err(ResponderError::InvalidSlot);
            };

        let use_mutual_auth =
            self.requester_cap.contains(ReqFlags::MUT_AUTH_CAP)
                && self.responder_cap.contains(RspFlags::MUT_AUTH_CAP);

        // TODO: Actually return measurement hashes if requested
        let measurement_summary_hash = [0u8; MAX_DIGEST_SIZE];

        transcript.extend(req)?;

        // Build the M1 transcript according to the SPDM spec.
        //
        // We need to extend the transcript with the serialized ChallengeAuth
        // message, but excluding the signature. We therefore use a placeholder
        // signature, serialize, extend the transcript, construct the real
        // signature, and overwrite the dummy signature in the serialized
        // message.
        let dummy_sig = [0u8; MAX_SIGNATURE_SIZE];

        let auth = ChallengeAuth::new(
            req_msg.slot,
            id_auth::create_slot_mask(cert_chains),
            use_mutual_auth,
            cert_chain_digest.as_ref(),
            nonce(),
            &measurement_summary_hash[..digest_size as usize],
            &[],
            &dummy_sig[..signature_size],
        );

        let size = auth.write(rsp)?;

        let sig_start = size - signature_size;
        transcript.extend(&rsp[..sig_start])?;

        let m1_hash = C::Digest::hash(
            self.algorithms.base_hash_algo_selected,
            transcript.get(),
        );

        let signature = signer
            .sign(m1_hash.as_ref())
            .map_err(|_| ResponderError::SigningFailed)?;

        // Attach the real signature to the CHALLENGE_AUTH message
        rsp[sig_start..size].copy_from_slice(signature.as_ref());

        Ok((size, Transition::Placeholder))
    }
}
