use core::convert::From;

use super::{CapabilitiesState, RequesterError, ResponderIdAuthState};
use crate::msgs::{
    Algorithms, Msg, NegotiateAlgorithms, VersionEntry, HEADER_SIZE,
};
use crate::msgs::capabilities::{ReqFlags, RspFlags};
use crate::Transcript;

// After capabilities negotiation, comes algorithm negotiation
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmsState {
    pub version: VersionEntry,
    pub requester_ct_exponent: u8,
    pub requester_cap: ReqFlags,
    pub responder_ct_exponent: u8,
    pub responder_cap: RspFlags,
    pub algorithms: Option<Algorithms>,
}

impl From<CapabilitiesState> for AlgorithmsState {
    fn from(s: CapabilitiesState) -> Self {
        AlgorithmsState {
            version: s.version,
            requester_ct_exponent: s.requester_ct_exponent.unwrap(),
            requester_cap: s.requester_cap.unwrap(),
            responder_ct_exponent: s.responder_ct_exponent.unwrap(),
            responder_cap: s.responder_cap.unwrap(),
            algorithms: None,
        }
    }
}

impl AlgorithmsState {
    pub fn write_msg(
        &self,
        msg: &NegotiateAlgorithms,
        buf: &mut [u8],
        transcript: &mut Transcript,
    ) -> Result<usize, RequesterError> {
        let size = msg.write(buf)?;
        transcript.extend(&buf[..size])?;
        Ok(size)
    }

    /// Only `Algorithms` messsages are acceptable here.
    pub fn handle_msg(
        self,
        buf: &[u8],
        transcript: &mut Transcript,
    ) -> Result<ResponderIdAuthState, RequesterError> {
        match Algorithms::parse_header(buf) {
            Ok(true) => self.handle_algorithms(buf, transcript),
            Ok(false) => Err(RequesterError::UnexpectedMsg {
                expected: Algorithms::name(),
                got: buf[0],
            }),
            Err(e) => Err(e.into()),
        }
    }

    pub fn handle_algorithms(
        mut self,
        buf: &[u8],
        transcript: &mut Transcript,
    ) -> Result<ResponderIdAuthState, RequesterError> {
        let algorithms = Algorithms::parse_body(&buf[HEADER_SIZE..])?;
        self.algorithms = Some(algorithms);
        transcript.extend(buf)?;
        Ok(self.into())
    }
}
