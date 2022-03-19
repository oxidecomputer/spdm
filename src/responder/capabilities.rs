// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::{algorithms, expect, AllStates, ResponderError};
use crate::msgs::capabilities::{
    Capabilities, GetCapabilities, ReqFlags, RspFlags,
};
use crate::msgs::{Msg, HEADER_SIZE};
use crate::{reset_on_get_version, Transcript};

/// After version negotiation, capabilities are negotiated.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub requester_ct_exponent: Option<u8>,
    pub requester_cap: Option<ReqFlags>,
    pub responder_ct_exponent: Option<u8>,
    pub responder_cap: Option<RspFlags>,
}

impl State {
    /// Create a new capabilities::State
    pub fn new() -> State {
        State::default()
    }

    /// Handle a message from a requester
    ///
    /// Only GetVersion and GetCapabilities messages are valid here.
    ///
    /// The set of supported capabilities comes from configuration.
    pub fn handle_msg(
        mut self,
        req: &[u8],
        rsp: &mut [u8],
        transcript: &mut Transcript,
        flags: RspFlags,
    ) -> Result<(usize, AllStates), ResponderError> {
        reset_on_get_version!(req, rsp, transcript);
        expect::<GetCapabilities>(req)?;

        let get_cap = GetCapabilities::parse_body(&req[HEADER_SIZE..])?;
        self.requester_ct_exponent = Some(get_cap.ct_exponent);
        self.requester_cap = Some(get_cap.flags);
        transcript.extend(req)?;

        let caps = Capabilities {
            // TODO: Don't hardcode this
            ct_exponent: 12,
            flags,
        };

        let size = caps.write(rsp)?;
        transcript.extend(&rsp[..size])?;
        self.responder_ct_exponent = Some(caps.ct_exponent);
        self.responder_cap = Some(caps.flags);

        Ok((size, algorithms::State::from(self).into()))
    }
}
