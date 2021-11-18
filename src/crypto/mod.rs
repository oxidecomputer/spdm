//! The crypto module provides the traits that the rest of the SPDM code relies
//! on to implement the cryptographic parts of the protocol.
//!
//! An initial implementation based on <https://github.com/briansmith/ring>
//! is provided for digests and signing. An initial implementation of
//! certificate validation and signature verification is provided by
//! [webpki](https://github.com/briansmith/webpki), itself backed by `ring`.
//!
//! It is expected that all implementations provided by the spdm crate will be
//! behind features, although this is not done yet. A given deployment of a
//! system using SPDM is likely only to support a few of these implementations,
//! and just as likely to implement a few of its own to support specific
//! hardware.
pub mod digest;
pub mod pki;
pub mod signing;
