use super::{algorithms, version, ResponderError};
use crate::msgs::capabilities::{GetCapabilities, Capabilities, ReqFlags, RspFlags};
use crate::msgs::{Msg, GetVersion, HEADER_SIZE};
use crate::Transcript;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition{
    Capabilities(State),
    Algorithms(algorithms::State),
}

/// After version negotiation, capabilities are negotiated.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub requester_ct_exponent: Option<u8>,
    pub requester_cap: Option<ReqFlags>,
    pub responder_ct_exponent: Option<u8>,
    pub responder_cap: Option<RspFlags>,
}

impl State {
    pub fn new() -> State {
        State::default()
    }

    // GetVersion and GetCapabilities messages are valid here.
    //
    // The caller passes in the set of supported capabilities
    pub fn handle_msg(
        self,
        supported: Capabilities,
        req: &[u8],
        rsp: &mut [u8],
        transcript: &mut Transcript,
    ) -> Result<(usize, Transition), ResponderError> {
        match GetVersion::parse_header(req) {
            Ok(true) => return self.handle_get_version(req, rsp, transcript),
            Err(e) => return Err(e.into()),
            _ => (),
        }

        match GetCapabilities::parse_header(req) {
            Ok(true) => self.handle_get_capabilities(supported, req, rsp, transcript),
            Ok(false) => Err(ResponderError::UnexpectedMsg {
                expected: GetCapabilities::name(),
                got: req[0],
            }),
            Err(e) => Err(e.into()),
        }
    }

    fn handle_get_version(
        self,
        req: &[u8],
        rsp: &mut [u8],
        transcript: &mut Transcript,
    ) -> Result<(usize, Transition), ResponderError> {
        // Go back to the beginning!
        let (size, cap_state) =
            version::State{}.handle_msg(req, rsp, transcript)?;
        Ok((size, Transition::Capabilities(cap_state)))
    }

    fn handle_get_capabilities(
        mut self,
        supported: Capabilities,
        req: &[u8],
        rsp: &mut [u8],
        transcript: &mut Transcript
    ) -> Result<(usize, Transition), ResponderError> {
        let get_cap = GetCapabilities::parse_body(&req[HEADER_SIZE..])?;
        self.requester_ct_exponent = Some(get_cap.ct_exponent);
        self.requester_cap = Some(get_cap.flags);
        transcript.extend(req)?;

       let size = supported.write(rsp)?;
       transcript.extend(&rsp[..size])?;
       self.responder_ct_exponent = Some(supported.ct_exponent);
       self.responder_cap = Some(supported.flags);

       Ok((size, Transition::Algorithms(self.into())))
    }
}
