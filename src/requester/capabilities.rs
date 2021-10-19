use super::{algorithms, expect, RequesterError};
use crate::msgs::capabilities::{ReqFlags, RspFlags};
use crate::msgs::{
    Capabilities, GetCapabilities, Msg, VersionEntry, HEADER_SIZE,
};
use crate::Transcript;

/// After version negotiation, capabilities are negotiated.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub version: VersionEntry,
    pub requester_ct_exponent: Option<u8>,
    pub requester_cap: Option<ReqFlags>,
    pub responder_ct_exponent: Option<u8>,
    pub responder_cap: Option<RspFlags>,
}

impl State {
    pub fn new(version: VersionEntry) -> State {
        State { version, ..Self::default() }
    }

    /// Write the `msg` into `buf` and record it in `transcript`.
    pub fn write_msg(
        &mut self,
        msg: &GetCapabilities,
        buf: &mut [u8],
        transcript: &mut Transcript,
    ) -> Result<usize, RequesterError> {
        let size = msg.write(buf)?;
        transcript.extend(&buf[..size])?;
        self.requester_ct_exponent = Some(msg.ct_exponent);
        self.requester_cap = Some(msg.flags);
        Ok(size)
    }

    /// Only `Capabilities` messages are acceptable here.
    pub fn handle_msg(
        mut self,
        buf: &[u8],
        transcript: &mut Transcript,
    ) -> Result<algorithms::State, RequesterError> {
        expect::<Capabilities>(buf)?;

        let capabilities = Capabilities::parse_body(&buf[HEADER_SIZE..])?;

        self.responder_ct_exponent = Some(capabilities.ct_exponent);
        self.responder_cap = Some(capabilities.flags);

        transcript.extend(buf)?;
        Ok(self.into())
    }
}
