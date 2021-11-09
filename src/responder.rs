//! A responder follows the typestate pattern
//! https://cliffle.com/blog/rust-typestate/
//!
//!
//! As this code is no_std, we can't use a box to minimize the size of the type
//! states. Therefore we limit the contained state, and pass in any large state
//! when needed by given parameters. We pass in parameters rather than store
//! mutable references, because we also want States to be Send, so we can use
//! them in async code outside a no_std environment.

pub mod algorithms;
pub mod capabilities;
pub mod id_auth;
pub mod version;

mod error;

use crate::msgs::Msg;
pub use error::ResponderError;

pub fn start() -> version::State {
    version::State {}
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

                return Ok((size, Transition::Capabilities(cap_state)));
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
