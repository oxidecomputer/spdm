// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use core::convert::From;

use super::{expect, id_auth, AllStates, ResponderError};

use crate::crypto::{Digests, Nonce, Signer};
use crate::msgs::{
    capabilities::{ReqFlags, RspFlags},
    common::{DigestBuf, SignatureBuf},
    Algorithms, Challenge, ChallengeAuth, Msg, OpaqueData, HEADER_SIZE,
};
use crate::{reset_on_get_version, Slot, Transcript};

/// Challenge requests are handled and responded to in this state
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
    /// Handle a message from a requester
    ///
    /// Only CHALLENGE and GET_VERSION msgs are allowed here.
    pub fn handle_msg<'a, S: Signer, D: Digests>(
        self,
        req: &[u8],
        rsp: &mut [u8],
        transcript: &mut Transcript,
        slots: &'a [(S, Slot<'a>)],
    ) -> Result<(usize, AllStates), ResponderError> {
        reset_on_get_version!(req, rsp, transcript);
        expect::<Challenge>(req)?;
        let digest_size =
            self.algorithms.base_hash_algo_selected.get_digest_size();
        let signature_size =
            self.algorithms.base_asym_algo_selected.get_signature_size();

        let req_msg = Challenge::parse_body(&req[HEADER_SIZE..])?;

        let (signer, slot) = slots
            .iter()
            .find(|(_, s)| s.id() == req_msg.slot)
            .ok_or(ResponderError::InvalidSlot)?;

        let cert_chain_digest =
            D::digest(self.algorithms.base_hash_algo_selected, slot.as_slice());

        let use_mutual_auth =
            self.requester_cap.contains(ReqFlags::MUT_AUTH_CAP)
                && self.responder_cap.contains(RspFlags::MUT_AUTH_CAP);

        // TODO: Actually return measurement hashes if requested
        let measurement_summary_hash = DigestBuf::new(digest_size);

        transcript.extend(req)?;

        // TODO: Update this for the 1.2 spec
        //
        // Build the M1 transcript according to the SPDM spec.
        //
        // We need to extend the transcript with the serialized ChallengeAuth
        // message, but excluding the signature. We therefore use a placeholder
        // signature, serialize, extend the transcript, construct the real
        // signature, and overwrite the dummy signature in the serialized
        // message.
        let dummy_sig = SignatureBuf::new(signature_size);

        let auth = ChallengeAuth::new(
            req_msg.slot,
            id_auth::create_slot_mask(slots),
            use_mutual_auth,
            cert_chain_digest.as_ref(),
            Nonce::new(),
            measurement_summary_hash.as_ref(),
            // TODO: Use the negotiated form from ALGORITHMS msg of 1.2 spec.
            OpaqueData::default(),
            dummy_sig.as_ref(),
        );

        let size = auth.write(rsp)?;

        let sig_start = size - usize::from(signature_size);
        transcript.extend(&rsp[..sig_start])?;

        let m1_hash = D::digest(
            self.algorithms.base_hash_algo_selected,
            transcript.get(),
        );

        let signature = signer
            .sign(m1_hash.as_ref())
            .map_err(|_| ResponderError::SigningFailed)?;

        // Attach the real signature to the CHALLENGE_AUTH message
        rsp[sig_start..size].copy_from_slice(signature.as_ref());

        Ok((size, self.into()))
    }
}
