use spdm::requester;
use spdm::responder;
use spdm::{msgs, Transcript};

#[test]
fn successful_version_negotiation() {
    // Start the requester and responder state machines in VersionState.
    let req_state = requester::start();
    let rsp_state = responder::start();

    // Create necessary buffers
    let mut req_buf = [0u8; 512];
    let mut rsp_buf = [0u8; 512];
    let mut req_transcript = Transcript::new();
    let mut rsp_transcript = Transcript::new();

    // Create a version request and write it into the request buffer
    let req_size =
        req_state.write_get_version(&mut req_buf, &mut req_transcript).unwrap();

    // The message is appended to the transcript
    assert_eq!(&req_buf[..req_size], req_transcript.get());

    // In a real system the messge would be sent over a transport.
    // Directly call the responder message handler here instead as if the
    // message was delivered. Message slices must be exact sized when calling
    // `handle_msg` methods.
    let (rsp_size, transition) = rsp_state
        .handle_msg(&req_buf[..req_size], &mut rsp_buf, &mut rsp_transcript)
        .unwrap();

    // The responder transitions to CapabilitiesState
    assert_eq!(
        responder::VersionTransition::Capabilities(
            responder::CapabilitiesState::new()
        ),
        transition
    );

    // The request and response are appended to the transcript
    assert_eq!(req_buf[..req_size], rsp_transcript.get()[..req_size]);
    assert_eq!(rsp_buf[..rsp_size], rsp_transcript.get()[req_size..]);
    assert_eq!(req_size + rsp_size, rsp_transcript.len());

    // Take the response and deliver it to the requester
    let transition = req_state
        .handle_msg(&rsp_buf[..rsp_size], &mut req_transcript)
        .unwrap();

    // We know the version
    let version =
        msgs::VersionEntry { major: 1, minor: 1, update: 0, alpha: 0 };

    // Thre requester transitions to CapabilitiesState
    assert_eq!(
        requester::VersionTransition::Capabilities(
            requester::CapabilitiesState::new(version)
        ),
        transition
    );

    // The requester transcript matches the responder transcript
    assert_eq!(req_transcript.get(), rsp_transcript.get());
}
