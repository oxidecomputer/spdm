// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::{capabilities, AllStates, ResponderError};
use crate::msgs::{GetVersion, Msg, Version, HEADER_SIZE};
use crate::Transcript;

pub struct State {}

impl State {
    /// Handle the initial message from a SPDM requester: GET_VERSION
    pub fn handle_msg(
        self,
        req: &[u8],
        rsp: &mut [u8],
        transcript: &mut Transcript,
    ) -> Result<(usize, AllStates), ResponderError> {
        match GetVersion::parse_header(req) {
            Ok(true) => self.handle_get_version(req, rsp, transcript),
            Ok(false) => Err(ResponderError::UnexpectedMsg {
                expected: GetVersion::NAME,
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
    ) -> Result<(usize, AllStates), ResponderError> {
        let _ = GetVersion::parse_body(&req[HEADER_SIZE..])?;

        // A GetVersion msg always resets the state of the protocol
        transcript.clear();
        transcript.extend(req)?;

        let size = Version::default().write(rsp)?;
        transcript.extend(&rsp[..size])?;

        Ok((size, capabilities::State::new().into()))
    }
}
