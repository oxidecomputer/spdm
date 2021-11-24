// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use spdm::config::{Config, MAX_CERT_CHAIN_SIZE, NUM_SLOTS};
use spdm::crypto::{
    digest::{Digest, RingDigest},
    signing::{new_signer, RingSigner},
};
use spdm::msgs::algorithms::*;
use spdm::msgs::capabilities::{
    Capabilities, GetCapabilities, ReqFlags, RspFlags,
};
use spdm::msgs::{
    digest::Digests, encoding::Writer, CertificateChain, GetVersion, Msg,
};
use spdm::requester;
use spdm::responder;
use spdm::{msgs, Transcript};

use test_utils::certs::*;

use std::time::SystemTime;

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

// Return the number of seconds since Unix epoch when a cert is expected to
// expire.
fn expiry() -> u64 {
    SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        + 10000
}

struct Certs {
    pub root_der: Vec<u8>,
    pub intermediate_der: Vec<u8>,
    pub leaf_der: Vec<u8>,
    pub leaf_private_der: Vec<u8>,
    pub root_hash: <TestConfig as Config>::Digest,
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
        let root_hash = <TestConfig as Config>::Digest::hash(
            BaseHashAlgo::SHA_256,
            &root_der,
        );

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

/// Create a set of cert chains, but only filling in some slots
///
/// In our test code, all cert chains use the same algorithms, but this is not
/// how they will likely be deployed in practice. From what I can tell, the most
/// likely usage is to support multiple endpoints with different algorithm
/// capabilities, such as during rolling upgrade of software or hardware.
fn create_cert_chains<'a>(
    certs: &'a [Certs],
) -> [Option<CertificateChain<'a>>; NUM_SLOTS] {
    assert_eq!(certs.len(), NUM_SLOTS);
    let mut cert_chains = [None; NUM_SLOTS];
    for i in 0..NUM_SLOTS {
        if i % 2 == 0 {
            cert_chains[i] = Some(certs[i].cert_chain());
        } else {
            cert_chains[i] = None;
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
        base_asym_algo: BaseAsymAlgo::ECDSA_ECC_NIST_P256,
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

    (req_state, rsp_state)
}

fn identify_responder<'a>(
    mut req_state: requester::id_auth::State,
    rsp_state: responder::id_auth::State,
    data: &mut Data,
    cert_chains: &[Option<CertificateChain<'a>>; NUM_SLOTS],
) -> (requester::challenge::State, responder::challenge::State) {
    // Generate the GET_DIGESTS request at the requester
    let req_size = req_state
        .write_get_digests_msg(&mut data.req_buf, &mut data.req_transcript)
        .unwrap();

    // Handle the GET_DIGESTS request at the responder
    let (rsp_size, transition) = rsp_state
        .handle_msg::<TestConfig>(
            cert_chains,
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
        cert_chains,
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
    let (rsp_size, transition) = rsp_state
        .handle_msg::<TestConfig>(
            &cert_chains,
            &data.req_buf[..req_size],
            &mut data.rsp_buf,
            &mut data.rsp_transcript,
        )
        .unwrap();

    let rsp_state = if let responder::id_auth::Transition::Challenge(
        rsp_state,
    ) = transition
    {
        rsp_state
    } else {
        unreachable!();
    };

    // Handle the CERTIFICATE response at the requester
    let req_state = req_state
        .handle_certificate(&data.rsp_buf[..rsp_size], &mut data.req_transcript)
        .unwrap();

    assert_eq!(data.req_transcript.get(), data.rsp_transcript.get());

    (req_state, rsp_state)
}

fn challenge_auth<'a>(
    mut req_state: requester::challenge::State,
    rsp_state: responder::challenge::State,
    data: &mut Data,
    cert_chains: &[Option<CertificateChain<'a>>; NUM_SLOTS],
    certs: &[Certs],
) {
    // Create the CHALLENGE request at the requester
    let req_size = req_state
        .write_challenge_msg(
            msgs::MeasurementHashType::None,
            &mut data.req_buf,
            &mut data.req_transcript,
        )
        .unwrap();

    // Create the signer, since the private key is application specific. In a
    // system with an RoT or other hardware mechanism, the signer will be a call
    // into that mechanism, since the private key is not exposed outside the HW.
    //
    // TODO: This only works with a single cert/signer. We need to figure out a
    // way to support a signer per slot. This gets tricky if each slot has a separate
    // algorithm. It's possible, instead, that we create a signing interface to
    // use that takes a slot as a parameter.
    let private_key = &certs[0].leaf_private_der;
    let signer =
        new_signer(rsp_state.algorithms.base_asym_algo_selected, private_key)
            .unwrap();

    // Handle the CHALLENGE request at the responder
    let (rsp_size, transition) = rsp_state
        .handle_msg::<TestConfig, RingSigner>(
            cert_chains,
            &signer,
            &data.req_buf[..req_size],
            &mut data.rsp_buf,
            &mut data.rsp_transcript,
        )
        .unwrap();

    assert_eq!(transition, responder::challenge::Transition::Placeholder);

    // TODO: Handle more than one slot
    let root_cert = &certs[0].root_der;

    // Deliver the response to the requester
    let transition = req_state
        .handle_msg::<TestConfig>(
            &data.rsp_buf[..rsp_size],
            &mut data.req_transcript,
            root_cert,
            expiry(),
        )
        .unwrap();

    assert_eq!(transition, requester::challenge::Transition::Placeholder);
}

// Verify that there is a proper digest for each cert chain
fn assert_digests_match_cert_chains<'a>(
    hash_algo: BaseHashAlgo,
    cert_chains: &[Option<CertificateChain<'a>>; NUM_SLOTS],
    digests: &Digests<NUM_SLOTS>,
) {
    for (i, (chain, digest)) in
        cert_chains.iter().zip(digests.digests).enumerate()
    {
        // Is there a digest for the given slot
        if (1 << i as u8) & digests.slot_mask != 0 {
            let mut buf = [0u8; MAX_CERT_CHAIN_SIZE];
            let mut w = Writer::new("CERTIFICATE_CHAIN", &mut buf);
            let size = chain.as_ref().unwrap().write(&mut w).unwrap();
            let expected =
                <TestConfig as Config>::Digest::hash(hash_algo, &buf[..size]);
            let len = expected.as_ref().len();
            assert_eq!(digest.as_slice(len), expected.as_ref());
        } else {
            assert!(chain.is_none());
        }
    }
}

// A test that follows the full flow of the currently implemented SPDM protocol,
// where each state is successfully entered and exited. No errors are returned.
#[test]
fn successful_e2e() {
    let mut data = Data::new();

    let certs = create_certs_per_slot();
    let cert_chains = create_cert_chains(&certs);

    let (req_state, rsp_state) = negotiate_versions(&mut data);
    let (req_state, rsp_state) =
        negotiate_capabilities(req_state, rsp_state, &mut data);
    let (req_state, rsp_state) =
        negotiate_algorithms(req_state, rsp_state, &mut data);
    let (req_state, rsp_state) =
        identify_responder(req_state, rsp_state, &mut data, &cert_chains);

    challenge_auth(req_state, rsp_state, &mut data, &cert_chains, &certs);
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
