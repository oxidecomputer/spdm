// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::{algorithms, expect, RequesterError};
use crate::config;
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
    pub fn write_msg<'a>(
        &mut self,
        buf: &'a mut [u8],
        transcript: &mut Transcript,
    ) -> Result<&'a [u8], RequesterError> {
        let msg = config_to_get_capabilities_msg()?;
        let size = msg.write(buf)?;
        transcript.extend(&buf[..size])?;
        self.requester_ct_exponent = Some(msg.ct_exponent);
        self.requester_cap = Some(msg.flags);
        Ok(&buf[..size])
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

// TODO: This whole things should probably move to config generation...
// We would then just abort if the parsing fails
fn config_to_get_capabilities_msg() -> Result<GetCapabilities, RequesterError> {
    let mut flags = ReqFlags::default();
    for s in config::CAPABILITIES {
        flags |= s.parse()?;
    }
    Ok(GetCapabilities {
        // TODO: Don't hardcode this - take it from config
        // See https://github.com/oxidecomputer/spdm/issues/23
        ct_exponent: 12,
        flags,
    })
}
