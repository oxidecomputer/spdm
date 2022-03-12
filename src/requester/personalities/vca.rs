// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The VCA personality only performs the handshake messages of the protocol.
//! This is useful to demonstrate usage of a requester and to bring up new boards
//! where crypto is not yet implemented.

use crate::msgs::capabilities::ReqFlags;
use crate::requester::{algorithms, capabilities, version, RequesterError};
use crate::Transcript;

/// A requester that only goes through the Version, Capabilities, and Algorithms
/// message exchanges.
pub struct Requester {
    capabilities: ReqFlags,
    transcript: Transcript,

    // This Option allows us to move between States variants at runtime, without
    // having to take self by value.
    state: Option<States>,
}

impl Requester {
    pub fn new() -> Requester {
        Requester {
            capabilities: ReqFlags::empty(),
            transcript: Transcript::new(),
            state: Some(version::State {}.into()),
        }
    }

    /// The user calls `next_request` to write the next SPDM request into the
    /// provided buffer. The user can then send that request over the transport.
    ///
    /// A `RequesterError::InitializationComplete` error  will be returned if
    /// this method is called when initialization is complete. In this case,
    /// the user should call the `begin_session` method.
    pub fn next_request<'b>(
        &mut self,
        buf: &'b mut [u8],
    ) -> Result<&'b [u8], RequesterError> {
        let state = self.data.state.as_mut().unwrap();
        if let States::NewSession = state {
            return Err(RequesterError::InitializationComplete);
        }
        state.write_req(buf, &mut self.data.transcript)
    }

    /// The user calls `handle_msg` when a response is received over the
    /// transport.
    ///
    /// `Ok(true)` will be returned when the protocol is complete.
    pub fn handle_msg<'b>(
        &mut self,
        rsp: &[u8],
    ) -> Result<bool, RequesterError> {
        let state = self.data.state.take().unwrap();
        match state.handle_msg(
            rsp,
            &mut self.data.transcript,
            &self.data.root_cert,
        ) {
            Ok(next_state) => {
                self.data.state = Some(next_state);
                if let Some(States::Complete) = self.data.state {
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Err(e) => {
                self.data.state = Some(States::Error);
                Err(e)
            }
        }
    }

    // Return the current state of the requester
    pub fn state(&self) -> &States {
        self.data.state.as_ref().unwrap()
    }

    pub fn transcript(&self) -> &Transcript {
        &self.data.transcript
    }
}

// TODO: // Use `derive_more` for the From impls below
pub enum States {
    Complete,
    Error,
    Version(version::State),
    Capabilities(capabilities::State),
    Algorithms(algorithms::State),
}

impl From<version::State> for States {
    fn from(state: version::State) -> States {
        States::Version(state)
    }
}

impl From<capabilities::State> for States {
    fn from(state: capabilities::State) -> States {
        States::Capabilities(state)
    }
}

impl From<algorithms::State> for States {
    fn from(state: algorithms::State) -> States {
        States::Algorithms(state)
    }
}

impl States {
    fn write_req<'a>(
        &mut self,
        buf: &'a mut [u8],
        transcript: &mut Transcript,
    ) -> Result<&'a [u8], RequesterError> {
        match self {
            States::Version(state) => state.write_get_version(buf, transcript),
            States::Capabilities(state) => state.write_msg(buf, transcript),
            States::Algorithms(state) => state.write_msg(buf, transcript),
            States::Error => Err(RequesterError::Wedged),
            States::Complete => Err(RequesterError::Complete),
        }
    }

    fn handle_msg<'a>(
        self,
        rsp: &[u8],
        transcript: &mut Transcript,
        root_cert: &'a [u8],
    ) -> Result<States, RequesterError> {
        match self {
            States::Version(state) => {
                state.handle_msg(rsp, transcript).map(|s| s.into())
            }
            States::Capabilities(state) => {
                state.handle_msg(rsp, transcript).map(|s| s.into())
            }
            States::Algorithms(mut state) => {
                state.handle_msg(rsp, transcript)?;
                Ok(States::Complete)
            }
            state => state,
        }
    }

    // Return the name of the current state
    pub fn name(&self) -> &'static str {
        match self {
            States::Complete => "Complete",
            States::Error => "Error",
            States::Version(_) => "Version",
            States::Capabilities(_) => "Capabilities",
            States::Algorithms(_) => "Algorithms",
        }
    }
}
