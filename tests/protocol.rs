use spdm::msgs::algorithms::*;
use spdm::msgs::capabilities::{
    Capabilities, GetCapabilities, ReqFlags, RspFlags,
};
use spdm::requester;
use spdm::responder;
use spdm::{msgs, Transcript};

#[test]
fn successful_negotiation() {
    // Start the requester and responder state machines in VersionState.
    let req_state = requester::start();
    let rsp_state = responder::start();

    // Create necessary buffers
    let mut req_buf = [0u8; 512];
    let mut rsp_buf = [0u8; 512];
    let mut req_transcript = Transcript::new();
    let mut rsp_transcript = Transcript::new();

    /*
     * VERSION NEGOTIATION
     */

    // Create a version request and write it into the request buffer
    let req_size =
        req_state.write_get_version(&mut req_buf, &mut req_transcript).unwrap();

    // The message is appended to the transcript
    assert_eq!(&req_buf[..req_size], req_transcript.get());

    // In a real system the messge would be sent over a transport.
    // Directly call the responder message handler here instead as if the
    // message was delivered. Message slices must be exact sized when calling
    // `handle_msg` methods.
    let (rsp_size, rsp_state) = rsp_state
        .handle_msg(&req_buf[..req_size], &mut rsp_buf, &mut rsp_transcript)
        .unwrap();

    // The responder transitions to `capabilities::State`
    assert_eq!(responder::capabilities::State::new(), rsp_state);

    // The request and response are appended to the transcript
    assert_eq!(req_buf[..req_size], rsp_transcript.get()[..req_size]);
    assert_eq!(rsp_buf[..rsp_size], rsp_transcript.get()[req_size..]);
    assert_eq!(req_size + rsp_size, rsp_transcript.len());

    // Take the response and deliver it to the requester
    let mut req_state = req_state
        .handle_msg(&rsp_buf[..rsp_size], &mut req_transcript)
        .unwrap();

    // We know the version
    let version =
        msgs::VersionEntry { major: 1, minor: 1, update: 0, alpha: 0 };

    // Thre requester transitions to `capabilities::State`
    assert_eq!(requester::capabilities::State::new(version), req_state);

    // The requester transcript matches the responder transcript
    assert_eq!(req_transcript.get(), rsp_transcript.get());

    /*
     * CAPABILITIES NEGOTIATION
     */

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
    let req_size =
        req_state.write_msg(&req, &mut req_buf, &mut req_transcript).unwrap();

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
            &req_buf[..req_size],
            &mut rsp_buf,
            &mut rsp_transcript,
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
    let mut req_state = req_state
        .handle_msg(&rsp_buf[..rsp_size], &mut req_transcript)
        .unwrap();

    assert!(matches!(req_state, requester::algorithms::State { .. }));

    assert_eq!(req_transcript, rsp_transcript);

    /*
     * ALGORITHMS NEGOTIATION
     */

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
    let req_size =
        req_state.write_msg(req, &mut req_buf, &mut req_transcript).unwrap();

    // Deliver the request to the responder
    let (rsp_size, transition) = rsp_state
        .handle_msg(&req_buf[..req_size], &mut rsp_buf, &mut rsp_transcript)
        .unwrap();

    // The responder transitions to `requester_id_auth::State`
    assert!(matches!(transition, responder::algorithms::Transition::IdAuth(_)));

    // Deliver the response to the requester.
    let req_state = req_state
        .handle_msg(&rsp_buf[..rsp_size], &mut req_transcript)
        .unwrap();

    assert!(matches!(req_state, requester::responder_id_auth::State { .. }));

    assert_eq!(req_transcript, rsp_transcript);

    // One of the selected algorithms was chosen for each setting.
    // We prioritize the low order bit (for no good reason).
    assert_eq!(req_state.algorithms.measurement_spec_selected,
MeasurementSpec::DMTF);
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
        AlgorithmResponse::ReqBaseAsym(ReqBaseAsymAlgorithm{
            supported: ReqBaseAsymFixedAlgorithms::ECDSA_ECC_NIST_P256
        })
    ));
    assert!(matches!(
        req_state.algorithms.algorithm_responses[3],
        AlgorithmResponse::KeySchedule(KeyScheduleAlgorithm{
            supported: KeyScheduleFixedAlgorithms::SPDM
        })
    ));
}
