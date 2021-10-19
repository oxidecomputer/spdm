use spdm::config::{Config, MAX_CERT_CHAIN_SIZE, NUM_SLOTS};
use spdm::crypto::digest::{Digest, RingDigest};
use spdm::msgs::algorithms::*;
use spdm::msgs::capabilities::{
    Capabilities, GetCapabilities, ReqFlags, RspFlags,
};
use spdm::msgs::digest::Digests;
use spdm::msgs::GetVersion;
use spdm::msgs::Msg;
use spdm::requester;
use spdm::responder;
use spdm::{msgs, Transcript};

pub struct TestConfig {}

impl Config for TestConfig {
    type Digest = RingDigest;
}

const BUF_SIZE: usize = 2048;

// Mutable data used by the requester and responder
pub struct Data {
    req_buf: [u8; BUF_SIZE],
    rsp_buf: [u8; BUF_SIZE],
    req_transcript: Transcript,
    rsp_transcript: Transcript,
}

impl Data {
    pub fn new() -> Data {
        Data {
            req_buf: [0u8; BUF_SIZE],
            rsp_buf: [0u8; BUF_SIZE],
            req_transcript: Transcript::new(),
            rsp_transcript: Transcript::new(),
        }
    }
}

fn mock_cert_chains() -> [Vec<u8>; NUM_SLOTS] {
    let mut cert_chains = [Vec::new(); NUM_SLOTS];
    for i in 0..NUM_SLOTS {
        if i % 2 == 0 {
            cert_chains[i] = vec![i as u8; MAX_CERT_CHAIN_SIZE / (i + 1)];
        }
    }
    cert_chains
}

// A successful version negotiation brings both requester and responder to
// capabilities negotiation states.
fn negotiate_versions(
    data: &mut Data,
) -> (requester::capabilities::State, responder::capabilities::State) {
    // Start the requester and responder state machines in VersionState.
    let req_state = requester::start();
    let rsp_state = responder::start();

    // Create a version request and write it into the request buffer
    let req_size = req_state
        .write_get_version(&mut data.req_buf, &mut data.req_transcript)
        .unwrap();

    // The message is appended to the transcript
    assert_eq!(&data.req_buf[..req_size], data.req_transcript.get());

    // In a real system the messge would be sent over a transport.
    // Directly call the responder message handler here instead as if the
    // message was delivered. Message slices must be exact sized when calling
    // `handle_msg` methods.
    let (rsp_size, rsp_state) = rsp_state
        .handle_msg(
            &data.req_buf[..req_size],
            &mut data.rsp_buf,
            &mut data.rsp_transcript,
        )
        .unwrap();

    // The responder transitions to `capabilities::State`
    assert_eq!(responder::capabilities::State::new(), rsp_state);

    // The request and response are appended to the transcript
    assert_eq!(data.req_buf[..req_size], data.rsp_transcript.get()[..req_size]);
    assert_eq!(data.rsp_buf[..rsp_size], data.rsp_transcript.get()[req_size..]);
    assert_eq!(req_size + rsp_size, data.rsp_transcript.len());

    // Take the response and deliver it to the requester
    let req_state = req_state
        .handle_msg(&data.rsp_buf[..rsp_size], &mut data.req_transcript)
        .unwrap();

    // We know the version
    let version =
        msgs::VersionEntry { major: 1, minor: 1, update: 0, alpha: 0 };

    // The requester transitions to `capabilities::State`
    assert_eq!(requester::capabilities::State::new(version), req_state);

    // The requester transcript matches the responder transcript
    assert_eq!(data.req_transcript.get(), data.rsp_transcript.get());

    (req_state, rsp_state)
}

// A successful capabilities negotiation brings both requester and responder to
// algorithm negotiation states.
fn negotiate_capabilities(
    mut req_state: requester::capabilities::State,
    rsp_state: responder::capabilities::State,
    data: &mut Data,
) -> (requester::algorithms::State, responder::algorithms::State) {
    // The requester defines its capabilities in the GetCapabilities msg.
    let req = GetCapabilities {
        ct_exponent: 12,
        flags: ReqFlags::CERT_CAP
            | ReqFlags::CHAL_CAP
            | ReqFlags::ENCRYPT_CAP
            | ReqFlags::MAC_CAP
            | ReqFlags::MUT_AUTH_CAP
            | ReqFlags::KEY_EX_CAP
            | ReqFlags::ENCAP_CAP
            | ReqFlags::HBEAT_CAP
            | ReqFlags::KEY_UPD_CAP,
    };

    // Serialize the GetCapabilities  message to send to the responder and
    // update the transcript.
    let req_size = req_state
        .write_msg(&req, &mut data.req_buf, &mut data.req_transcript)
        .unwrap();

    // The Responder defines its capabilities the `Capabilities` msg
    let rsp = Capabilities {
        ct_exponent: 14,
        flags: RspFlags::CERT_CAP
            | RspFlags::CHAL_CAP
            | RspFlags::ENCRYPT_CAP
            | RspFlags::MAC_CAP
            | RspFlags::MUT_AUTH_CAP
            | RspFlags::KEY_EX_CAP
            | RspFlags::ENCAP_CAP
            | RspFlags::HBEAT_CAP
            | RspFlags::KEY_UPD_CAP,
    };

    // Let the responder handle the message.
    let (rsp_size, transition) = rsp_state
        .handle_msg(
            rsp,
            &data.req_buf[..req_size],
            &mut data.rsp_buf,
            &mut data.rsp_transcript,
        )
        .unwrap();

    // The responder transitions to `algorithms::State`
    let rsp_state =
        if let responder::capabilities::Transition::Algorithms(rsp_state) =
            transition
        {
            rsp_state
        } else {
            panic!()
        };

    // Deliver the response to the requester
    let req_state = req_state
        .handle_msg(&data.rsp_buf[..rsp_size], &mut data.req_transcript)
        .unwrap();

    // The requester transitions to `algorithms::State`

    assert!(matches!(req_state, requester::algorithms::State { .. }));

    assert_eq!(data.req_transcript, data.rsp_transcript);

    (req_state, rsp_state)
}

// A successful capabilities negotiation brings both requester and responder to
// algorithm negotiation states.
fn negotiate_algorithms(
    mut req_state: requester::algorithms::State,
    rsp_state: responder::algorithms::State,
    data: &mut Data,
) -> (requester::id_auth::State, responder::id_auth::State) {
    // The requester describes its options for algorithms
    let req = NegotiateAlgorithms {
        measurement_spec: MeasurementSpec::DMTF,
        base_asym_algo: BaseAsymAlgo::ECDSA_ECC_NIST_P384,
        base_hash_algo: BaseHashAlgo::SHA_256 | BaseHashAlgo::SHA3_256,
        num_algorithm_requests: 4,
        algorithm_requests: [
            AlgorithmRequest::Dhe(DheAlgorithm {
                supported: DheFixedAlgorithms::FFDHE_3072
                    | DheFixedAlgorithms::SECP_384_R1,
            }),
            AlgorithmRequest::Aead(AeadAlgorithm {
                supported: AeadFixedAlgorithms::AES_256_GCM
                    | AeadFixedAlgorithms::CHACHA20_POLY1305,
            }),
            AlgorithmRequest::ReqBaseAsym(ReqBaseAsymAlgorithm {
                supported: ReqBaseAsymFixedAlgorithms::ECDSA_ECC_NIST_P384
                    | ReqBaseAsymFixedAlgorithms::ECDSA_ECC_NIST_P256,
            }),
            AlgorithmRequest::KeySchedule(KeyScheduleAlgorithm {
                supported: KeyScheduleFixedAlgorithms::SPDM,
            }),
        ],
    };

    // Serialize the request
    let req_size = req_state
        .write_msg(req, &mut data.req_buf, &mut data.req_transcript)
        .unwrap();

    // Deliver the request to the responder
    let (rsp_size, transition) = rsp_state
        .handle_msg(
            &data.req_buf[..req_size],
            &mut data.rsp_buf,
            &mut data.rsp_transcript,
        )
        .unwrap();

    // The responder transitions to `requester_id_auth::State`
    let rsp_state =
        if let responder::algorithms::Transition::IdAuth(state) = transition {
            state
        } else {
            unreachable!();
        };

    // Deliver the response to the requester.
    let req_state = req_state
        .handle_msg::<NUM_SLOTS, MAX_CERT_CHAIN_SIZE>(
            &data.rsp_buf[..rsp_size],
            &mut data.req_transcript,
        )
        .unwrap();

    assert!(matches!(req_state, requester::id_auth::State { .. }));

    assert_eq!(data.req_transcript, data.rsp_transcript);

    // One of the selected algorithms was chosen for each setting.
    // We prioritize the low order bit (for no good reason).
    assert_eq!(
        req_state.algorithms.measurement_spec_selected,
        MeasurementSpec::DMTF
    );
    assert_eq!(
        req_state.algorithms.base_asym_algo_selected,
        BaseAsymAlgo::ECDSA_ECC_NIST_P384
    );
    assert_eq!(
        req_state.algorithms.base_hash_algo_selected,
        BaseHashAlgo::SHA_256
    );
    assert_eq!(
        req_state.algorithms.measurement_hash_algo_selected,
        req_state.algorithms.base_hash_algo_selected
    );
    assert!(matches!(
        req_state.algorithms.algorithm_responses[0],
        AlgorithmResponse::Dhe(DheAlgorithm {
            supported: DheFixedAlgorithms::FFDHE_3072
        })
    ));
    assert!(matches!(
        req_state.algorithms.algorithm_responses[1],
        AlgorithmResponse::Aead(AeadAlgorithm {
            supported: AeadFixedAlgorithms::AES_256_GCM
        })
    ));
    assert!(matches!(
        req_state.algorithms.algorithm_responses[2],
        AlgorithmResponse::ReqBaseAsym(ReqBaseAsymAlgorithm {
            supported: ReqBaseAsymFixedAlgorithms::ECDSA_ECC_NIST_P256
        })
    ));
    assert!(matches!(
        req_state.algorithms.algorithm_responses[3],
        AlgorithmResponse::KeySchedule(KeyScheduleAlgorithm {
            supported: KeyScheduleFixedAlgorithms::SPDM
        })
    ));

    (req_state, rsp_state)
}

fn identify_responder(
    mut req_state: requester::id_auth::State,
    rsp_state: responder::id_auth::State,
    data: &mut Data,
) {
    // We expect the responder application to have a set of certs.
    let stored_certs = mock_cert_chains();
    let mut cert_chains: [Option<&[u8]>; NUM_SLOTS] = [None; NUM_SLOTS];
    for (i, v) in stored_certs.iter().enumerate() {
        if v.len() != 0 {
            cert_chains[i] = Some(&v[..]);
        }
    }

    // Generate the GET_DIGESTS request at the requester
    let req_size = req_state
        .write_get_digests_msg(&mut data.req_buf, &mut data.req_transcript)
        .unwrap();

    // Handle the GET_DIGESTS request at the responder
    let (rsp_size, transition) = rsp_state
        .handle_msg::<TestConfig>(
            &cert_chains,
            &data.req_buf[..req_size],
            &mut data.rsp_buf,
            &mut data.rsp_transcript,
        )
        .unwrap();

    // Unpack the current state from the state transition
    let rsp_state =
        if let responder::id_auth::Transition::IdAuth(rsp_state) = transition {
            rsp_state
        } else {
            unreachable!();
        };

    // Handle the DIGESTS response at the requester
    req_state
        .handle_digests(&data.rsp_buf[..rsp_size], &mut data.req_transcript)
        .unwrap();

    assert_eq!(data.req_transcript.get(), data.rsp_transcript.get());

    // The responder creates and sends a digest for each cert chain that exists
    assert_digests_match_cert_chains(
        req_state.algorithms.base_hash_algo_selected,
        &cert_chains,
        &req_state.digests.as_ref().unwrap(),
    );

    // Get the first cert chain (slot 0 always exists)
    let slot = 0;
    let req_size = req_state
        .write_get_certificate_msg(
            slot,
            &mut data.req_buf,
            &mut data.req_transcript,
        )
        .unwrap();

    // Handle the GET_CERTIFICATE request at the responder
    let (rsp_size, _rsp_state) = rsp_state
        .handle_msg::<TestConfig>(
            &cert_chains,
            &data.req_buf[..req_size],
            &mut data.rsp_buf,
            &mut data.rsp_transcript,
        )
        .unwrap();

    // Handle the CERTIFICATE response at the requester
    req_state
        .handle_certificate(&data.rsp_buf[..rsp_size], &mut data.req_transcript)
        .unwrap();

    assert_eq!(data.req_transcript.get(), data.rsp_transcript.get());
}

// Verify that there is a proper digest for each cert chain
fn assert_digests_match_cert_chains(
    hash_algo: BaseHashAlgo,
    cert_chains: &[Option<&[u8]>; NUM_SLOTS],
    digests: &Digests<NUM_SLOTS>,
) {
    for (i, (chain, digest)) in
        cert_chains.iter().zip(digests.digests).enumerate()
    {
        // Is there a digest for the given slot
        if (1 << i as u8) & digests.slot_mask != 0 {
            let expected =
                <TestConfig as Config>::Digest::hash(hash_algo, chain.unwrap());
            let len = expected.as_ref().len();
            assert_eq!(digest.as_slice(len), expected.as_ref());
        } else {
            assert!(chain.is_none());
        }
    }
}

#[test]
fn successful_negotiation() {
    let mut data = Data::new();

    let (req_state, rsp_state) = negotiate_versions(&mut data);
    let (req_state, rsp_state) =
        negotiate_capabilities(req_state, rsp_state, &mut data);
    let (req_state, rsp_state) =
        negotiate_algorithms(req_state, rsp_state, &mut data);
    identify_responder(req_state, rsp_state, &mut data);
}

// A Responder will go back to `capabilities::State` if a requester sends a
// GetVersion message in the middle of negotiation.
//
// The responder actually goes back to the `version::State` internally and
// processes the message to transfer to the `capabilities::State`
#[test]
fn reset_to_capabilities_state_from_capabilities_state() {
    let state = responder::capabilities::State::new();
    let cap = Capabilities::default();

    // Create necessary buffers
    let mut req_buf = [0u8; 512];
    let mut rsp_buf = [0u8; 512];
    let mut rsp_transcript = Transcript::new();

    // Serialize a GetVersion msg
    let size = GetVersion {}.write(&mut req_buf).unwrap();

    let (_, transition) = state
        .handle_msg(cap, &req_buf[..size], &mut rsp_buf, &mut rsp_transcript)
        .unwrap();

    assert!(matches!(
        transition,
        responder::capabilities::Transition::Capabilities(_)
    ));
}

// A Responder will go back to `capabilities::State` if a requester sends a
// GetVersion message in the middle of negotiation.
//
// The responder actually goes back to the `version::State` internally and
// processes the message to transfer to the `capabilities::State`
#[test]
fn reset_to_capabilities_state_from_algorithms_state() {
    let state = responder::algorithms::State::default();

    // Create necessary buffers
    let mut req_buf = [0u8; 512];
    let mut rsp_buf = [0u8; 512];
    let mut rsp_transcript = Transcript::new();

    // Serialize a GetVersion msg
    let size = GetVersion {}.write(&mut req_buf).unwrap();

    let (_, transition) = state
        .handle_msg(&req_buf[..size], &mut rsp_buf, &mut rsp_transcript)
        .unwrap();

    assert!(matches!(
        transition,
        responder::algorithms::Transition::Capabilities(_)
    ));
}
