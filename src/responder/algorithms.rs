use super::{capabilities, expect, id_auth, ResponderError};
use crate::msgs::algorithms::*;
use crate::msgs::capabilities::{ReqFlags, RspFlags};
use crate::msgs::{Msg, HEADER_SIZE};
use crate::{Transcript, reset_on_get_version};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    Capabilities(capabilities::State),
    IdAuth(id_auth::State),
}

// Algorithms are selected after capability negotiation.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub requester_ct_exponent: u8,
    pub requester_cap: ReqFlags,
    pub responder_ct_exponent: u8,
    pub responder_cap: RspFlags,
    pub algorithms: Option<Algorithms>,
}

impl From<capabilities::State> for State {
    fn from(s: capabilities::State) -> Self {
        State {
            requester_ct_exponent: s.requester_ct_exponent.unwrap(),
            requester_cap: s.requester_cap.unwrap(),
            responder_ct_exponent: s.responder_ct_exponent.unwrap(),
            responder_cap: s.responder_cap.unwrap(),
            algorithms: None,
        }
    }
}

impl State {
    /// GetVersion and NegotiateAlgorithms messages are valid here.
    pub fn handle_msg(
        mut self,
        req: &[u8],
        rsp: &mut [u8],
        transcript: &mut Transcript,
    ) -> Result<(usize, Transition), ResponderError> {
        reset_on_get_version!(req, rsp, transcript);
        expect::<NegotiateAlgorithms>(req)?;

        let req_msg = NegotiateAlgorithms::parse_body(&req[HEADER_SIZE..])?;
        transcript.extend(req)?;

        let algorithms = self.choose_algorithms(req_msg);
        let size = algorithms.write(rsp)?;
        transcript.extend(&rsp[..size])?;
        self.algorithms = Some(algorithms);

        Ok((size, Transition::IdAuth(self.into())))
    }

    // We use the simplest mechanism possible here and just choose the first set
    // bit for each algorithm.
    //
    // TODO: Allow the user to choose which algorithms it can utilize, or
    // encapsulate that in a type/trait ?
    //
    // TODO: Allow the user to pass priorities? It really seems like the
    // requester should be the one prioritizing though! Unfortunately, SPDM
    // doesn't appear to have a mechanism for that.
    fn choose_algorithms(&self, req: NegotiateAlgorithms) -> Algorithms {
        let mut rsp = Algorithms::default();

        rsp.measurement_spec_selected = req.measurement_spec;

        let first_bit_set = req.base_hash_algo.bits().trailing_zeros();
        rsp.measurement_hash_algo_selected =
            BaseHashAlgo::from_bits(1 << first_bit_set).unwrap();
        rsp.base_hash_algo_selected = rsp.measurement_hash_algo_selected;

        let first_bit_set = req.base_asym_algo.bits().trailing_zeros();
        rsp.base_asym_algo_selected =
            BaseAsymAlgo::from_bits(1 << first_bit_set).unwrap();

        rsp.num_algorithm_responses = req.num_algorithm_requests;

        for i in 0..rsp.num_algorithm_responses as usize {
            match &req.algorithm_requests[i] {
                AlgorithmRequest::Dhe(algo) => {
                    let first_bit_set = algo.supported.bits().trailing_zeros();
                    let supported =
                        DheFixedAlgorithms::from_bits(1 << first_bit_set)
                            .unwrap();
                    let algo = DheAlgorithm { supported };
                    rsp.algorithm_responses[i] = AlgorithmResponse::Dhe(algo);
                }
                AlgorithmRequest::Aead(algo) => {
                    let first_bit_set = algo.supported.bits().trailing_zeros();
                    let supported =
                        AeadFixedAlgorithms::from_bits(1 << first_bit_set)
                            .unwrap();
                    let algo = AeadAlgorithm { supported };
                    rsp.algorithm_responses[i] = AlgorithmResponse::Aead(algo);
                }
                AlgorithmRequest::ReqBaseAsym(algo) => {
                    let first_bit_set = algo.supported.bits().trailing_zeros();
                    let supported = ReqBaseAsymFixedAlgorithms::from_bits(
                        1 << first_bit_set,
                    )
                    .unwrap();
                    let algo = ReqBaseAsymAlgorithm { supported };
                    rsp.algorithm_responses[i] =
                        AlgorithmResponse::ReqBaseAsym(algo);
                }
                AlgorithmRequest::KeySchedule(algo) => {
                    let first_bit_set = algo.supported.bits().trailing_zeros();
                    let supported = KeyScheduleFixedAlgorithms::from_bits(
                        1 << first_bit_set,
                    )
                    .unwrap();
                    let algo = KeyScheduleAlgorithm { supported };
                    rsp.algorithm_responses[i] =
                        AlgorithmResponse::KeySchedule(algo);
                }
            }
        }

        rsp
    }
}
