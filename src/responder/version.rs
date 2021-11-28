// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::{capabilities, ResponderError};
use crate::msgs::{GetVersion, Msg, Version, HEADER_SIZE};
use crate::Transcript;

pub struct State {}

impl State {
    /// Handle the initial message from a SPDM requester: GET_VERSION
    pub fn handle_msg<'a>(
        self,
        req: &[u8],
        rsp: &'a mut [u8],
        transcript: &mut Transcript,
    ) -> Result<(&'a [u8], capabilities::State), ResponderError> {
        match GetVersion::parse_header(req) {
            Ok(true) => self.handle_get_version(req, rsp, transcript),
            Ok(false) => Err(ResponderError::UnexpectedMsg {
                expected: GetVersion::NAME,
                got: req[0],
            }),
            Err(e) => Err(e.into()),
        }
    }

    fn handle_get_version<'a>(
        self,
        req: &[u8],
        rsp: &'a mut [u8],
        transcript: &mut Transcript,
    ) -> Result<(&'a [u8], capabilities::State), ResponderError> {
        let _ = GetVersion::parse_body(&req[HEADER_SIZE..])?;

        // A GetVersion msg always resets the state of the protocol
        transcript.clear();
        transcript.extend(req)?;

        let size = Version::default().write(rsp)?;
        transcript.extend(&rsp[..size])?;

        Ok((&rsp[..size], capabilities::State::new()))
    }
}
