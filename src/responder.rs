// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A responder follows the typestate pattern internally
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

use crate::config;
use crate::crypto::{FilledSlot, Signer};
use crate::msgs::{self, CertificateChain, Msg};
use crate::Transcript;
pub use error::ResponderError;

use core::convert::From;

/// `AllStates` is a container for all the states in a responder.
///
/// This library follows a typestate pattern, where each state has a specific
/// API and is only accessible one at a time. However, this is a bit cumbersome
/// to use for a consumer as it consists of taking `self` by value and returning
/// the next state. Furthermore, since SPDM is a fairly complicated protocol,
/// using this pattern means that a user of the protocol must look up the
/// states of the protocol and figure out how they fit together to use them,
/// even when the states are driven by messages, and potential errors, which the
/// user does not control.
///
/// Such an architecture means that this message handling and state transition
/// code must be duplicated at each consumer, rather than written once. We
/// elminate this duplication and provide roughly the same level of type safety
/// by only implementing state transitions between states directly in the states
/// themselves, and then putting the resulting output state into a global state
/// enum, `AllStates`. We then provide a wrapper `Responder` API around
/// `AllStates` that a user can consume without having to know all the internal
/// details of the SPDM protocol.
pub enum AllStates {
    // A special state that indicates the responder has terminated and the
    // transport should close its "connection".
    Error,
    Version(version::State),
    Capabilities(capabilities::State),
    Algorithms(algorithms::State),
    IdAuth(id_auth::State),
    Challenge(challenge::State),
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
    fn handle<'a, 'b, S: Signer>(
        self,
        req: &[u8],
        rsp: &'a mut [u8],
        transcript: &mut Transcript,
        slots: &'b [Option<FilledSlot<'b, S>>; config::NUM_SLOTS],
    ) -> (&'a [u8], AllStates, Result<(), ResponderError>) {
        let res = match self {
            AllStates::Version(state) => state.handle_msg(req, rsp, transcript),
            AllStates::Capabilities(state) => {
                state.handle_msg(req, rsp, transcript)
            }
            AllStates::Algorithms(state) => {
                state.handle_msg(req, rsp, transcript)
            }
            AllStates::IdAuth(state) => {
                let mut cert_chains: [Option<CertificateChain<'b>>;
                    config::NUM_SLOTS] = [None; config::NUM_SLOTS];
                for i in 0..slots.len() {
                    cert_chains[i] =
                        slots[i].as_ref().map(|s| s.cert_chain.clone());
                }
                state.handle_msg(&cert_chains, req, rsp, transcript)
            }
            AllStates::Challenge(state) => {
                state.handle_msg(slots, req, rsp, transcript)
            }
            _ => unimplemented!(),
        };
        match res {
            Ok((size, state)) => (&rsp[..size], state, Ok(())),
            Err(responder_err) => {
                // Write an error message into `rsp` and return it along with
                // the error.
                let err_msg: msgs::Error = (&responder_err).into();

                // If we fail writing the error, just return the empty slice.
                match err_msg.write(rsp) {
                    Ok(size) => {
                        (&rsp[..size], AllStates::Error, Err(responder_err))
                    }
                    Err(_) => {
                        (&rsp[0..0], AllStates::Error, Err(responder_err))
                    }
                }
            }
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
        }
    }
}

/// A wrapper around the Responder state machine states contained in
/// `AllStates`.
pub struct Responder<'a, S: Signer> {
    slots: [Option<FilledSlot<'a, S>>; config::NUM_SLOTS],
    transcript: Transcript,
    // This Option allows us to move between states at runtime, without having
    // to take self by value.
    state: Option<AllStates>,
}

impl<'a, S: Signer> Responder<'a, S> {
    pub fn new(
        slots: [Option<FilledSlot<'a, S>>; config::NUM_SLOTS],
    ) -> Responder<'a, S> {
        Responder {
            slots,
            transcript: Transcript::new(),
            state: Some(version::State {}.into()),
        }
    }

    // Return the serialized output message, including the serialized error
    // response, and an error if the responder should be shutdown.
    pub fn handle_msg<'b>(
        &mut self,
        req: &[u8],
        rsp: &'b mut [u8],
    ) -> (&'b [u8], Result<(), ResponderError>) {
        let state = self.state.take().unwrap();
        let (out, next_state, result) =
            state.handle(req, rsp, &mut self.transcript, &self.slots);
        self.state = Some(next_state);
        (out, result)
    }

    // Return the current state of the responder
    //
    // It's safe to unwrap here, as the invariant of a Responder is that the
    // `state` Option is only `None` during a `recv` call.
    pub fn state(&self) -> &AllStates {
        self.state.as_ref().unwrap()
    }

    pub fn transcript(&self) -> &Transcript {
        &self.transcript
    }

    pub fn slots(&self) -> &[Option<FilledSlot<'a, S>>; config::NUM_SLOTS] {
        &self.slots
    }
}

/// Go back to the Version state and process a GetVersion message.
///
/// GET_VERSION messages can arrive at any time from a requester and reset the
/// protocol to its initial state without forcing a reconnection. This macro
/// checks for a GET_VERSION message and handles it appropriately. If a GET_VERSION
/// message has not been received, no action is taken.
#[macro_export]
macro_rules! reset_on_get_version {
    ($req:ident, $rsp:ident, $transcript:ident) => {
        use crate::msgs::GetVersion;
        use crate::responder::version;
        match GetVersion::parse_header($req) {
            Ok(true) => {
                // Go back to the beginning!
                let (size, cap_state) =
                    version::State {}.handle_msg($req, $rsp, $transcript)?;

                return Ok((size, cap_state));
            }
            Err(e) => return Err(e.into()),
            _ => (),
        }
    };
}

/// We expect a messsage of the given type.
///
/// Return an error if the header doesn't match the given type.
///
/// This is just an ergonomic wrapper around `Msg::parse_header` for when
/// only one message type is expected.
pub fn expect<T: Msg>(buf: &[u8]) -> Result<(), ResponderError> {
    match T::parse_header(buf) {
        Ok(true) => Ok(()),
        Ok(false) => Err(ResponderError::UnexpectedMsg {
            expected: T::NAME,
            got: buf[0],
        }),
        Err(e) => Err(e.into()),
    }
}
