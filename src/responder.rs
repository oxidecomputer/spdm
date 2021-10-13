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
pub mod error;
pub mod version;
pub mod requester_id_auth;

pub use error::ResponderError;

pub fn start() -> version::State {
    version::State {}
}
