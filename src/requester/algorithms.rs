//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//

use core::convert::From;

use super::{capabilities, expect, id_auth, RequesterError};
use crate::msgs::algorithms::{AlgorithmRequest, AlgorithmResponse};
use crate::msgs::capabilities::{ReqFlags, RspFlags};
use crate::msgs::{
    Algorithms, Msg, NegotiateAlgorithms, VersionEntry, HEADER_SIZE,
};
use crate::Transcript;

/// After capabilities negotiation, comes algorithm negotiation
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub version: VersionEntry,
    pub requester_ct_exponent: u8,
    pub requester_cap: ReqFlags,
    pub responder_ct_exponent: u8,
    pub responder_cap: RspFlags,
    pub negotiate_algorithms: Option<NegotiateAlgorithms>,
    pub algorithms: Option<Algorithms>,
}

impl From<capabilities::State> for State {
    fn from(s: capabilities::State) -> Self {
        State {
            version: s.version,
            requester_ct_exponent: s.requester_ct_exponent.unwrap(),
            requester_cap: s.requester_cap.unwrap(),
            responder_ct_exponent: s.responder_ct_exponent.unwrap(),
            responder_cap: s.responder_cap.unwrap(),
            negotiate_algorithms: None,
            algorithms: None,
        }
    }
}

impl State {
    /// Serialize a NEGOTIATE_ALGORITHMS request and append it to the
    /// transcript
    pub fn write_msg(
        &mut self,
        msg: NegotiateAlgorithms,
        buf: &mut [u8],
        transcript: &mut Transcript,
    ) -> Result<usize, RequesterError> {
        let size = msg.write(buf)?;
        self.negotiate_algorithms = Some(msg);
        transcript.extend(&buf[..size])?;
        Ok(size)
    }

    /// Only `Algorithms` messsages are acceptable here.
    pub fn handle_msg<const NUM_SLOTS: usize, const CERT_CHAIN_SIZE: usize>(
        mut self,
        buf: &[u8],
        transcript: &mut Transcript,
    ) -> Result<id_auth::State, RequesterError> {
        expect::<Algorithms>(buf)?;
        let algorithms = Algorithms::parse_body(&buf[HEADER_SIZE..])?;
        self.ensure_valid_algorithms_selected(&algorithms)?;
        self.algorithms = Some(algorithms);
        transcript.extend(buf)?;
        Ok(self.into())
    }

    // Make sure that any algorithms chosen by the responder correspond to
    // algorithms set in the requester `NegotiateAlgorithms` request.
    fn ensure_valid_algorithms_selected(
        &self,
        algorithms: &Algorithms,
    ) -> Result<(), RequesterError> {
        {
            let requested = self.negotiate_algorithms.as_ref().unwrap();
            let err = Err(RequesterError::SelectedAlgorithmNotRequested);

            if requested.measurement_spec
                != algorithms.measurement_spec_selected
            {
                return err;
            }

            if requested.base_asym_algo.bits()
                & algorithms.base_asym_algo_selected.bits()
                == 0
            {
                return err;
            }

            if requested.base_hash_algo.bits()
                & algorithms.base_hash_algo_selected.bits()
                == 0
            {
                return err;
            }

            if requested.base_hash_algo.bits()
                & algorithms.measurement_hash_algo_selected.bits()
                == 0
            {
                return err;
            }
        }

        for i in 0..algorithms.num_algorithm_responses as usize {
            self.ensure_algorithm_response_is_valid(
                &algorithms.algorithm_responses[i],
            )?;
        }

        Ok(())
    }

    fn ensure_algorithm_response_is_valid(
        &self,
        response: &AlgorithmResponse,
    ) -> Result<(), RequesterError> {
        let requested = self.negotiate_algorithms.as_ref().unwrap();
        let err = Err(RequesterError::SelectedAlgorithmNotRequested);

        match response {
            AlgorithmResponse::Dhe(rsp) => {
                for i in 0..requested.num_algorithm_requests as usize {
                    if let AlgorithmRequest::Dhe(req) =
                        requested.algorithm_requests[i]
                    {
                        if req.supported.bits() & rsp.supported.bits() == 0 {
                            return err;
                        }
                    }
                }
            }
            AlgorithmResponse::Aead(rsp) => {
                for i in 0..requested.num_algorithm_requests as usize {
                    if let AlgorithmRequest::Aead(req) =
                        requested.algorithm_requests[i]
                    {
                        if req.supported.bits() & rsp.supported.bits() == 0 {
                            return err;
                        }
                    }
                }
            }
            AlgorithmResponse::ReqBaseAsym(rsp) => {
                for i in 0..requested.num_algorithm_requests as usize {
                    if let AlgorithmRequest::ReqBaseAsym(req) =
                        requested.algorithm_requests[i]
                    {
                        if req.supported.bits() & rsp.supported.bits() == 0 {
                            return err;
                        }
                    }
                }
            }
            AlgorithmResponse::KeySchedule(rsp) => {
                for i in 0..requested.num_algorithm_requests as usize {
                    if let AlgorithmRequest::KeySchedule(req) =
                        requested.algorithm_requests[i]
                    {
                        if req.supported.bits() & rsp.supported.bits() == 0 {
                            return err;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgs::algorithms::tests;
    use crate::msgs::algorithms::*;

    fn state_and_algorithms() -> (State, Algorithms) {
        let mut requests =
            [AlgorithmRequest::default(); MAX_ALGORITHM_REQUESTS];
        tests::algo_requests(&mut requests);
        let msg = tests::negotiate_algo(requests);

        let state = State {
            version: VersionEntry::default(),
            requester_ct_exponent: 0,
            requester_cap: ReqFlags::default(),
            responder_ct_exponent: 0,
            responder_cap: RspFlags::default(),
            negotiate_algorithms: Some(msg),
            algorithms: None,
        };

        let mut responses =
            [AlgorithmResponse::default(); MAX_ALGORITHM_REQUESTS];
        tests::algo_responses(&mut responses);

        (state, tests::algo(responses))
    }

    #[test]
    fn valid_algorithms_selected() {
        let (state, algorithms) = state_and_algorithms();
        assert!(state.ensure_valid_algorithms_selected(&algorithms).is_ok());
    }

    #[test]
    fn catch_mismatched_bits() {
        let (state, mut algorithms) = state_and_algorithms();

        // This hash algo was not part of the `NegotiateAlgorithms` request.
        algorithms.base_hash_algo_selected = BaseHashAlgo::SHA_256;

        assert!(state.ensure_valid_algorithms_selected(&algorithms).is_err());
    }

    #[test]
    fn catch_bad_algorithm_response() {
        let (state, mut algorithms) = state_and_algorithms();

        // This DHE algo was not part of the  `NegotiateAlgorithms` request.
        if let AlgorithmResponse::Dhe(algo) =
            &mut algorithms.algorithm_responses[0]
        {
            algo.supported = DheFixedAlgorithms::FFDHE_2048;
        } else {
            panic!();
        }

        assert!(state.ensure_valid_algorithms_selected(&algorithms).is_err());
    }
}
