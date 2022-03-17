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

use crate::config::RequesterConfig;
use crate::crypto::{pki, Digests};
use crate::msgs::capabilities::ReqFlags;

use core::convert::From;
use derive_more::From;
use tinyvec::SliceVec;

/// We expect a messsage of the given type.
///
/// Return an error if the header doesn't match the given type.
///
/// This is just an ergonomic wrapper around `Msg::parse_header` for when
/// only one message type is expected.
pub fn expect<T: Msg>(buf: &[u8]) -> Result<(), RequesterError> {
    match T::parse_header(buf) {
        Ok(true) => Ok(()),
        Ok(false) => Err(RequesterError::UnexpectedMsgCode {
            expected: T::SPDM_CODE,
            got: buf[0],
        }),
        Err(e) => Err(e.into()),
    }
}

pub struct Requester<'a, D, V> {
    config: RequesterConfig<'a, D, V>,
    transcript: Transcript,

    // This Option allows us to move between AllStates variants at runtime, without having
    // to take self by value.
    state: Option<AllStates>,
}

impl<'a, D, V> Requester<'a, D, V>
where
    D: Digests,
    V: for<'c> pki::Validator<'c>,
{
    pub fn new(config: RequesterConfig<'a, D, V>) -> Requester<'a, D, V> {
        Requester {
            config,
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
        &'a mut self,
        buf: &'b mut [u8],
    ) -> Result<&'b [u8], RequesterError> {
        if let AllStates::Complete = &self.state.unwrap() {
            return Err(RequesterError::Complete);
        }
        let state = self.state.take().unwrap();
        state.write_req(buf, &self.config, &mut self.transcript)
    }

    /// The user calls `handle_msg` when a response is received over the
    /// transport.
    ///
    /// `Ok(true)` will be returned when the requester state machine has
    /// reached the `Complete` state.
    pub fn handle_msg<'b>(
        &'a mut self,
        rsp: &[u8],
    ) -> Result<bool, RequesterError> {
        let state = self.state.take().unwrap();
        match state.handle_msg(rsp, &mut self.config, &mut self.transcript) {
            Ok(next_state) => {
                self.state = Some(next_state);
                if let Some(AllStates::Complete) = self.state {
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Err(e) => {
                self.state = Some(AllStates::Error);
                Err(e)
            }
        }
    }

    // Return the current state of the requester
    pub fn state(&self) -> &AllStates {
        self.state.as_ref().unwrap()
    }

    pub fn transcript(&self) -> &Transcript {
        &self.transcript
    }

    pub fn my_opaque_data(&mut self) -> &mut SliceVec<'a, u8> {
        self.config.my_opaque_data()
    }
}

/// `AllStates` is a container for all the states in a Requester.
///
/// It serves to make the internal typestate pattern more egronomic for users,
/// and hide the details of the SPDM protocol. The protocol states are moved
/// between based on the capability negotiation of the requester and responder.
#[derive(From)]
pub enum AllStates {
    Error,
    Complete,
    Version(version::State),
    Capabilities(capabilities::State),
    Algorithms(algorithms::State),
    IdAuth(id_auth::State),
    Challenge(challenge::State),
}

impl AllStates {
    fn write_req<'a, 'b, D, V>(
        &mut self,
        buf: &'a mut [u8],
        config: &'b RequesterConfig<'b, D, V>,
        transcript: &mut Transcript,
    ) -> Result<&'a [u8], RequesterError>
    where
        D: Digests,
        V: for<'c> pki::Validator<'c>,
    {
        match self {
            AllStates::Version(state) => {
                state.write_get_version(buf, transcript)
            }
            AllStates::Capabilities(state) => {
                state.write_msg(buf, transcript, config.capabilities())
            }
            AllStates::Algorithms(state) => state.write_msg(
                buf,
                transcript,
                config.digests(),
                config.asym_algos_supported(),
            ),
            AllStates::IdAuth(state) => state.write_get_certificate_msg(
                buf,
                transcript,
                &mut config.responder_certs(),
            ),
            AllStates::Challenge(state) => state.write_msg(buf, transcript),
            AllStates::Complete => Err(RequesterError::Complete),
            AllStates::Error => Err(RequesterError::Wedged),
        }
    }

    fn handle_msg<'a, D, V>(
        self,
        rsp: &[u8],
        config: &'a mut RequesterConfig<'a, D, V>,
        transcript: &mut Transcript,
    ) -> Result<AllStates, RequesterError>
    where
        D: Digests,
        V: for<'b> pki::Validator<'b>,
    {
        match self {
            AllStates::Version(state) => {
                state.handle_msg(rsp, transcript).map(|s| s.into())
            }
            AllStates::Capabilities(state) => {
                let next_state = state.handle_msg(rsp, transcript)?;
                Self::ensure_responder_capabilities(&state)?;
                Ok(next_state.into())
            }
            AllStates::Algorithms(mut state) => {
                state.handle_msg(rsp, transcript).map(|_| {
                    if state.requester_cap.contains(ReqFlags::CERT_CAP) {
                        id_auth::State::from(state).into()
                    } else {
                        AllStates::Complete
                    }
                })
            }
            AllStates::IdAuth(mut state) => {
                // We always retrieve the full cert chain in one request, so
                // we have no need for the result here. The cert chain has
                // already been writtento the slot.
                //
                // TODO: When we support receiving CERTIFICATE messages with
                // multiple messages, we will care about the return value.
                let _ = state.handle_certificate(
                    rsp,
                    transcript,
                    &mut config.responder_certs(),
                )?;
                if state.requester_cap.contains(ReqFlags::CHAL_CAP) {
                    Ok(challenge::State::from(state).into())
                } else {
                    Ok(AllStates::Complete)
                }
            }
            AllStates::Challenge(state) => {
                state.handle_msg(
                    rsp,
                    transcript,
                    &config.digests().unwrap(),
                    &config.validator().unwrap(),
                    config.responder_certs(),
                )?;
                Ok(AllStates::Complete)
            }
            AllStates::Complete => Err(RequesterError::Complete),
            AllStates::Error => Err(RequesterError::Wedged),
        }
    }

    /// Return the name of the current state
    pub fn name(&self) -> &'static str {
        match self {
            AllStates::Error => "Error",
            AllStates::Complete => "Complete",
            AllStates::Version(_) => "Version",
            AllStates::Capabilities(_) => "Capabilities",
            AllStates::Algorithms(_) => "Algorithms",
            AllStates::IdAuth(_) => "IdAuth",
            AllStates::Challenge(_) => "Challenge",
        }
    }

    // Ensure that all the capabilities supported by the requester are also
    // supported by the responder. The requester supported capabilities are
    // implicitly the required capabilities in this implementation so as to
    // prevent skipping required message exchanges and reducing security.
    fn ensure_responder_capabilities(
        state: &capabilities::State,
    ) -> Result<(), RequesterError> {
        // The responder capabilities are a strict superset of the requester
        // capabilities. Convert the RspFlags into ReqFlags dropping bits that
        // don't exist in ReqFlags.
        let rsp_flags =
            ReqFlags::from_bits_truncate(state.responder_cap.unwrap().bits());
        let err_bits = state.requester_cap.unwrap() - rsp_flags;
        if err_bits.is_empty() {
            Ok(())
        } else {
            Err(RequesterError::CapabilitiesNotSupportedByResponder(err_bits))
        }
    }
}
