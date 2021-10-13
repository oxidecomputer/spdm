//! A requester follows the typestate pattern
//! https://cliffle.com/blog/rust-typestate/
//!
//!
//! As this code is no_std, we can't use a box to minimize the size of the type
//! states. Therefore we limit the contained state, and pass in any large state
//! when needed by given parameters. We pass in parameters rather than store
//! mutable references, because we also want States to be Send, so we can use
//! them in async code outside a no_std environment.

mod capabilities;
mod error;
mod version;
mod algorithms;
mod responder_id_auth;

pub use capabilities::CapabilitiesState;
pub use error::RequesterError;
pub use version::{VersionState, VersionTransition};
pub use algorithms::AlgorithmsState;
pub use responder_id_auth::ResponderIdAuthState;


pub fn start() -> VersionState {
    VersionState {}
}
