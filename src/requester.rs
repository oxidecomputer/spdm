// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A requester follows the typestate pattern
//! <https://cliffle.com/blog/rust-typestate/>
//!
//!
//! As this code is no_std, we can't use a box to minimize the size of the type
//! states. Therefore we limit the contained state, and pass in any large state
//! when needed by given parameters. We pass in parameters rather than store
//! mutable references, because we also want States to be Send, so we can use
//! them in async code outside a no_std environment.

pub mod algorithms;
pub mod capabilities;
pub mod challenge;
pub mod id_auth;
pub mod version;

mod error;

use crate::msgs::Msg;
use crate::Transcript;
pub use error::RequesterError;

use crate::config;
use crate::crypto::{FilledSlot, Signer};

use core::convert::From;

/// We expect a messsage of the given type.
///
/// Return an error if the header doesn't match the given type.
///
/// This is just an ergonomic wrapper around `Msg::parse_header` for when
/// only one message type is expected.
pub fn expect<T: Msg>(buf: &[u8]) -> Result<(), RequesterError> {
    match T::parse_header(buf) {
        Ok(true) => Ok(()),
        Ok(false) => Err(RequesterError::UnexpectedMsg {
            expected: T::NAME,
            got: buf[0],
        }),
        Err(e) => Err(e.into()),
    }
}

// Internal data shared between `RequesterInit` and `RequesterSession` states.
struct RequesterData<'a, S: Signer> {
    // Do we need more than one of these? Do we expect that different slots for
    // a responder will have different root certs?
    root_cert: &'a [u8],

    // Will eventually be used for mutual auth
    slots: [Option<FilledSlot<'a, S>>; config::NUM_SLOTS],

    transcript: Transcript,
    // This Option allows us to move between AllStates variants at runtime, without having
    // to take self by value.
    state: Option<AllStates>,
}

/// The `RequesterInit` state handles the "autonomous" part of the
/// protocol, as dictated by negotiated capabilities, until a secure session is
/// established. Once a secure session is established, users can send and
/// receive application specific messages from the `RequesterSession` state.
pub struct RequesterInit<'a, S: Signer> {
    data: RequesterData<'a, S>,
}

/// In the `RequesterSession` state, the a secure session has been
/// established and the user can send encrypted messages and request
/// measurements at will.
pub struct RequesterSession<'a, S: Signer> {
    _data: RequesterData<'a, S>,
}

impl<'a, S: Signer> From<RequesterInit<'a, S>> for RequesterSession<'a, S> {
    fn from(state: RequesterInit<'a, S>) -> Self {
        RequesterSession { _data: state.data }
    }
}

impl<'a, S: Signer> RequesterInit<'a, S> {
    pub fn new(
        root_cert: &'a [u8],
        slots: [Option<FilledSlot<'a, S>>; config::NUM_SLOTS],
    ) -> RequesterInit<'a, S> {
        RequesterInit {
            data: RequesterData {
                root_cert,
                slots,
                transcript: Transcript::new(),
                state: Some(version::State {}.into()),
            },
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
        if let AllStates::NewSession = state {
            return Err(RequesterError::InitializationComplete);
        }
        state.write_req(buf, &mut self.data.transcript)
    }

    /// The user calls `handle_msg` when a response is received over the
    /// transport.
    ///
    /// `Ok(true)` will be returned when initialization is complete. At this
    /// point the user should call the `begin_session` method.
    pub fn handle_msg<'b>(
        &mut self,
        rsp: &[u8],
    ) -> Result<bool, RequesterError> {
        let state = self.data.state.take().unwrap();
        let (next_state, result) = state.handle_msg(
            rsp,
            &mut self.data.transcript,
            &self.data.root_cert,
        );
        self.data.state = Some(next_state);

        match result {
            Ok(()) => {
                if let Some(AllStates::NewSession) = self.data.state {
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Transition to the RequesterSession state
    pub fn begin_session(self) -> RequesterSession<'a, S> {
        self.into()
    }

    // Return the current state of the requester
    pub fn state(&self) -> &AllStates {
        self.data.state.as_ref().unwrap()
    }

    pub fn transcript(&self) -> &Transcript {
        &self.data.transcript
    }

    pub fn slots(&self) -> &[Option<FilledSlot<'a, S>>; config::NUM_SLOTS] {
        &self.data.slots
    }
}

/// `AllStates` is a container for all the states in a Requester.
///
/// It serves to make the internal typestate pattern more egronomic for users,
/// and hide the details of the SPDM protocol. The protocol states are moved
/// between based on the capability negotiation of the requester and responder.
pub enum AllStates {
    // A special state that indicates the responder has terminated and the
    // transport should close its "connection".
    Error,
    Version(version::State),
    Capabilities(capabilities::State),
    Algorithms(algorithms::State),
    IdAuth(id_auth::State),
    Challenge(challenge::State),

    // TODO: Fill this in with an actual state once sessions are implemented.
    NewSession,
}
impl From<version::State> for AllStates {
    fn from(state: version::State) -> AllStates {
        AllStates::Version(state)
    }
}

impl From<capabilities::State> for AllStates {
    fn from(state: capabilities::State) -> AllStates {
        AllStates::Capabilities(state)
    }
}

impl From<algorithms::State> for AllStates {
    fn from(state: algorithms::State) -> AllStates {
        AllStates::Algorithms(state)
    }
}

impl From<id_auth::State> for AllStates {
    fn from(state: id_auth::State) -> AllStates {
        AllStates::IdAuth(state)
    }
}

impl From<challenge::State> for AllStates {
    fn from(state: challenge::State) -> AllStates {
        AllStates::Challenge(state)
    }
}

impl AllStates {
    fn write_req<'a>(
        &mut self,
        buf: &'a mut [u8],
        transcript: &mut Transcript,
    ) -> Result<&'a [u8], RequesterError> {
        match self {
            AllStates::Version(state) => {
                state.write_get_version(buf, transcript)
            }
            AllStates::Capabilities(state) => state.write_msg(buf, transcript),
            AllStates::Algorithms(state) => state.write_msg(buf, transcript),
            AllStates::IdAuth(state) => {
                if state.digests.is_none() {
                    // We need to send the GET_DIGESTS request
                    state.write_get_digests_msg(buf, transcript)
                } else {
                    // TODO: Retrieve certs for all slots that have digests.
                    // See SPDM 1.2 sec 10.4.1: Connection Behavior after VCA
                    //
                    // This requires changes to the id_auth state to not
                    // automatically transition after retrieving one cert.
                    //
                    // Tracked in https://github.com/oxidecomputer/spdm/issues/29
                    let slot = 0;
                    state.write_get_certificate_msg(slot, buf, transcript)
                }
            }
            AllStates::Challenge(state) => state.write_msg(buf, transcript),
            _ => unimplemented!(),
        }
    }

    fn handle_msg<'a>(
        self,
        rsp: &[u8],
        transcript: &mut Transcript,
        root_cert: &'a [u8],
    ) -> (AllStates, Result<(), RequesterError>) {
        let result = match self {
            AllStates::Version(state) => {
                state.handle_msg(rsp, transcript).map(|s| s.into())
            }
            AllStates::Capabilities(state) => {
                state.handle_msg(rsp, transcript).map(|s| s.into())
            }
            AllStates::Algorithms(state) => {
                state.handle_msg(rsp, transcript).map(|s| s.into())
            }
            AllStates::IdAuth(mut state) => {
                if state.digests.is_none() {
                    // Self is taken by ref here so we return immediately.
                    let result = state.handle_digests(rsp, transcript);
                    return (state.into(), result);
                } else {
                    state.handle_certificate(rsp, transcript).map(|s| s.into())
                }
            }
            AllStates::Challenge(state) => {
                // We haven't implemented any other states, so just go to
                // `NewSession`.
                let result = state.handle_msg(rsp, transcript, root_cert);
                return (AllStates::NewSession, result.map(|_| ()));
            }
            _ => unimplemented!(),
        };
        match result {
            Ok(next_state) => (next_state, Ok(())),
            Err(e) => (AllStates::Error, Err(e)),
        }
    }

    // Return the name of the current state
    pub fn name(&self) -> &'static str {
        match self {
            AllStates::Error => "Error",
            AllStates::Version(_) => "Version",
            AllStates::Capabilities(_) => "Capabilities",
            AllStates::Algorithms(_) => "Algorithms",
            AllStates::IdAuth(_) => "IdAuth",
            AllStates::Challenge(_) => "Challenge",
            AllStates::NewSession => "NewSession",
        }
    }
}
