// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use spdm::config::{MAX_CERT_CHAIN_SIZE, NUM_SLOTS};
use spdm::crypto::{
    digest::{Digest, DigestImpl},
    signing::{new_signer, RingSigner},
    FilledSlot, Signer,
};
use spdm::msgs::algorithms::*;
use spdm::msgs::{
    digest::Digests, encoding::Writer, CertificateChain, GetVersion, Msg,
};
use spdm::requester::{self, RequesterInit};
use spdm::responder::{self, AllStates, Responder};
use spdm::Transcript;

use test_utils::certs::*;

const BUF_SIZE: usize = 2048;

// Mutable data used by the requester and responder
pub struct Data {
    req_buf: [u8; BUF_SIZE],
    rsp_buf: [u8; BUF_SIZE],
}

impl Data {
    pub fn new() -> Data {
        Data { req_buf: [0u8; BUF_SIZE], rsp_buf: [0u8; BUF_SIZE] }
    }
}

struct Certs {
    pub root_der: Vec<u8>,
    pub intermediate_der: Vec<u8>,
    pub leaf_der: Vec<u8>,
    pub leaf_private_der: Vec<u8>,
    pub root_hash: DigestImpl,
}

impl Certs {
    pub fn new() -> Certs {
        let root_params = cert_params_ecdsa_p256_sha256(true, "Root");
        let intermediate_params =
            cert_params_ecdsa_p256_sha256(true, "Intermediate");
        let leaf_params = cert_params_ecdsa_p256_sha256(false, "Leaf");
        let root = rcgen::Certificate::from_params(root_params).unwrap();
        let intermediate =
            rcgen::Certificate::from_params(intermediate_params).unwrap();
        let leaf = rcgen::Certificate::from_params(leaf_params).unwrap();
        let root_der = root.serialize_der().unwrap();
        let root_hash = DigestImpl::hash(BaseHashAlgo::SHA_256, &root_der);

        Certs {
            root_der,
            intermediate_der: intermediate
                .serialize_der_with_signer(&root)
                .unwrap(),
            leaf_der: leaf.serialize_der_with_signer(&intermediate).unwrap(),
            leaf_private_der: leaf.serialize_private_key_der(),
            root_hash,
        }
    }

    pub fn cert_chain<'a>(&'a self) -> CertificateChain<'a> {
        let mut chain =
            CertificateChain::new(self.root_hash.as_ref(), &self.leaf_der);
        chain.append_intermediate_cert(&self.intermediate_der).unwrap();
        chain
    }
}

fn create_certs_per_slot() -> Vec<Certs> {
    (0..NUM_SLOTS).map(|_| Certs::new()).collect()
}

/// Create a set of cert chains and signers, but only filling in some slots
///
/// In our test code, all cert chains use the same algorithms, but this is not
/// how they will likely be deployed in practice. From what I can tell, the most
/// likely usage is to support multiple endpoints with different algorithm
/// capabilities, such as during rolling upgrade of software or hardware.
fn create_slots<'a>(
    certs: &'a [Certs],
) -> [Option<FilledSlot<'a, RingSigner>>; NUM_SLOTS] {
    assert_eq!(certs.len(), NUM_SLOTS);
    let mut slots: [Option<FilledSlot<'a, RingSigner>>; NUM_SLOTS] =
        Default::default();
    for i in 0..NUM_SLOTS {
        if i % 2 == 0 {
            let private_key = &certs[i].leaf_private_der;
            slots[i] = Some(FilledSlot {
                signing_algorithm: BaseAsymAlgo::ECDSA_ECC_NIST_P256,
                hash_algorithm: BaseHashAlgo::SHA_256,
                cert_chain: certs[i].cert_chain(),
                signer: new_signer(
                    BaseAsymAlgo::ECDSA_ECC_NIST_P256,
                    private_key,
                )
                .unwrap(),
            });
        }
    }
    slots
}

// A successful version negotiation brings both requester and responder to
// capabilities negotiation states.
fn negotiate_versions<'a, S: Signer>(
    data: &mut Data,
    requester: &mut RequesterInit<'a, S>,
    responder: &mut Responder<'a, S>,
) {
    // Create a version request and write it into the request buffer
    let req_data = requester.next_request(&mut data.req_buf).unwrap();

    // The message is appended to the transcript
    assert_eq!(req_data, requester.transcript().get());

    // In a real system the messge would be sent over a transport.
    // Directly call the responder message handler here instead as if the
    // message was delivered. Message slices must be exact sized when calling
    // `handle_msg` methods.
    let (rsp_data, result) = responder.handle_msg(req_data, &mut data.rsp_buf);
    result.unwrap();

    // The responder transitions to `capabilities::State`
    assert_eq!("Capabilities", responder.state().name());

    // The request and response are appended to the transcript
    let req_size = req_data.len();
    let rsp_size = rsp_data.len();
    assert_eq!(req_data, &responder.transcript().get()[..req_size]);
    assert_eq!(rsp_data, &responder.transcript().get()[req_size..]);
    assert_eq!(req_size + rsp_size, responder.transcript().len());

    // Take the response and deliver it to the requester
    let initialization_complete =
        requester.handle_msg(&data.rsp_buf[..rsp_size]).unwrap();
    assert_eq!(false, initialization_complete);

    // The requester transitions to `capabilities::State`
    assert_eq!("Capabilities", requester.state().name());

    // The requester transcript matches the responder transcript
    assert_eq!(requester.transcript().get(), responder.transcript().get());
}

// A successful capabilities negotiation brings both requester and responder to
// algorithm negotiation states.
fn negotiate_capabilities<'a, S: Signer>(
    requester: &mut RequesterInit<'a, S>,
    responder: &mut Responder<'a, S>,
    data: &mut Data,
) {
    // Serialize the GetCapabilities  message to send to the responder and
    // update the transcript.
    let req_data = requester.next_request(&mut data.req_buf).unwrap();

    // Let the responder handle the message.
    let (rsp_data, result) = responder.handle_msg(req_data, &mut data.rsp_buf);
    result.unwrap();

    // The responder transitioned to `algorithms::State`
    assert_eq!("Algorithms", responder.state().name());

    // Deliver the response to the requester
    let initialization_complete = requester.handle_msg(rsp_data).unwrap();
    assert_eq!(false, initialization_complete);

    // The requester transitions to `algorithms::State`
    assert_eq!("Algorithms", requester.state().name());

    assert_eq!(requester.transcript(), responder.transcript());
}

// A successful capabilities negotiation brings both requester and responder to
// algorithm negotiation states.
fn negotiate_algorithms<'a, S: Signer>(
    requester: &mut RequesterInit<'a, S>,
    responder: &mut Responder<'a, S>,
    data: &mut Data,
) {
    // Serialize the request
    let req_data = requester.next_request(&mut data.req_buf).unwrap();

    // Deliver the request to the responder
    let (rsp_data, result) = responder.handle_msg(req_data, &mut data.rsp_buf);
    result.unwrap();

    // The responder transitioned to `requester_id_auth::State`
    assert_eq!("IdAuth", responder.state().name());

    // Deliver the response to the requester.
    let initialization_complete = requester.handle_msg(rsp_data).unwrap();
    assert_eq!(false, initialization_complete);

    assert_eq!("IdAuth", requester.state().name());

    assert_eq!(requester.transcript(), responder.transcript());

    if let requester::AllStates::IdAuth(ref req_state) = requester.state() {
        // One of the selected algorithms was chosen for each setting.
        // This should match config
        assert_eq!(
            req_state.algorithms.measurement_spec_selected,
            MeasurementSpec::DMTF
        );
        assert_eq!(
            req_state.algorithms.base_asym_algo_selected,
            BaseAsymAlgo::ECDSA_ECC_NIST_P256
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
    } else {
        assert!(false);
    }
}

fn identify_responder<'a, S: Signer>(
    requester: &mut RequesterInit<'a, S>,
    responder: &mut Responder<'a, S>,
    data: &mut Data,
) {
    // Generate the GET_DIGESTS request at the requester
    let req_data = requester.next_request(&mut data.req_buf).unwrap();

    // Handle the GET_DIGESTS request at the responder
    let (rsp_data, result) = responder.handle_msg(req_data, &mut data.rsp_buf);
    result.unwrap();

    // The responder is still in IdAuth state
    assert_eq!("IdAuth", responder.state().name());

    // Handle the DIGESTS response at the requester
    let initialization_complete = requester.handle_msg(rsp_data).unwrap();
    assert_eq!(false, initialization_complete);

    assert_eq!(requester.transcript().get(), responder.transcript().get());

    if let requester::AllStates::IdAuth(ref req_state) = requester.state() {
        // The responder creates and sends a digest for each cert chain that exists
        assert_digests_match_cert_chains(
            req_state.algorithms.base_hash_algo_selected,
            responder.slots(),
            &req_state.digests.as_ref().unwrap(),
        );
    } else {
        assert!(false);
    }

    // Get the first cert chain (slot 0 always exists)
    let req_data = requester.next_request(&mut data.req_buf).unwrap();

    // Handle the GET_CERTIFICATE request at the responder
    let (rsp_data, response) =
        responder.handle_msg(req_data, &mut data.rsp_buf);
    response.unwrap();

    // The responder transitioned to the the challenge state
    assert_eq!("Challenge", responder.state().name());

    // Handle the CERTIFICATE response at the requester
    let initialization_complete = requester.handle_msg(rsp_data).unwrap();
    assert_eq!(initialization_complete, false);

    assert_eq!(requester.transcript().get(), responder.transcript().get());

    assert_eq!("Challenge", requester.state().name());
}

fn challenge_auth<'a, S: Signer>(
    requester: &mut RequesterInit<'a, S>,
    responder: &mut Responder<'a, S>,
    data: &mut Data,
) {
    // Create the CHALLENGE request at the requester
    let req_data = requester.next_request(&mut data.req_buf).unwrap();

    // Handle the CHALLENGE request at the responder
    let (rsp_data, result) = responder.handle_msg(req_data, &mut data.rsp_buf);
    result.unwrap();

    // The rest of the states have not yet been implemented, so we don't transition
    // here.
    assert_eq!("Challenge", responder.state().name());

    // Deliver the response to the requester
    let initialization_complete = requester.handle_msg(rsp_data).unwrap();
    assert_eq!(true, initialization_complete);

    assert_eq!("NewSession", requester.state().name());
}

// Verify that there is a proper digest for each cert chain
fn assert_digests_match_cert_chains<'a, S: Signer>(
    hash_algo: BaseHashAlgo,
    slots: &[Option<FilledSlot<'a, S>>; NUM_SLOTS],
    digests: &Digests,
) {
    for (i, (slot, digest)) in slots.iter().zip(digests.digests).enumerate() {
        // Is there a digest for the given slot
        if (1 << i as u8) & digests.slot_mask != 0 {
            let mut buf = [0u8; MAX_CERT_CHAIN_SIZE];
            let mut w = Writer::new("CERTIFICATE_CHAIN", &mut buf);
            let size = slot.as_ref().unwrap().cert_chain.write(&mut w).unwrap();
            let expected = DigestImpl::hash(hash_algo, &buf[..size]);
            assert_eq!(digest.as_slice(), expected.as_ref());
        } else {
            assert!(slot.is_none());
        }
    }
}

// A test that follows the full flow of the currently implemented SPDM protocol,
// where each state is successfully entered and exited. No errors are returned.
#[test]
fn successful_e2e() {
    let mut data = Data::new();

    let certs = create_certs_per_slot();
    let slots = create_slots(&certs);
    let slots2 = create_slots(&certs);

    let mut responder = Responder::new(slots);

    // TODO: Should the root be the same for all slots?
    let mut requester = RequesterInit::new(&certs[0].root_der, slots2);

    negotiate_versions(&mut data, &mut requester, &mut responder);
    negotiate_capabilities(&mut requester, &mut responder, &mut data);
    negotiate_algorithms(&mut requester, &mut responder, &mut data);
    identify_responder(&mut requester, &mut responder, &mut data);
    challenge_auth(&mut requester, &mut responder, &mut data);
}

// A Responder will go back to `capabilities::State` if a requester sends a
// GetVersion message in the middle of negotiation.
//
// The responder actually goes back to the `version::State` internally and
// processes the message to transfer to the `capabilities::State`
#[test]
fn reset_to_capabilities_state_from_capabilities_state() {
    let state = responder::capabilities::State::new();

    // Create necessary buffers
    let mut req_buf = [0u8; 512];
    let mut rsp_buf = [0u8; 512];
    let mut rsp_transcript = Transcript::new();

    // Serialize a GetVersion msg
    let size = GetVersion {}.write(&mut req_buf).unwrap();

    let (_, transition) = state
        .handle_msg(&req_buf[..size], &mut rsp_buf, &mut rsp_transcript)
        .unwrap();

    assert!(matches!(transition, AllStates::Capabilities(_)));
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

    assert!(matches!(transition, AllStates::Capabilities(_)));
}
