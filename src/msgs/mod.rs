// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The `msgs` module contains all messages defined by the SPDM specification.
//!
//! Messages are utilized by the typestates of requesters and responders, and
//! users do not create them directly in most cases.
//!
//! All messages implement the Msg trait. Calling code serializes messages with
//! the provided `write` method. Received messages are differentiated via the
//! `parse_header` method. Each message should  equivalently have a method for
//! parsing the body, but it is not part of the `Msg` trait because it may take
//! different forms.

pub mod algorithms;
pub mod capabilities;
pub mod certificates;
pub mod challenge;
pub mod digest;
pub mod encoding;
mod error;
pub mod version;

pub use algorithms::{Algorithms, NegotiateAlgorithms};
pub use capabilities::{Capabilities, GetCapabilities};
pub use certificates::{Certificate, CertificateChain, GetCertificate};
pub use challenge::{Challenge, ChallengeAuth, MeasurementHashType};
pub use digest::{Digests, GetDigests};
use encoding::Writer;
pub use encoding::{ReadError, ReadErrorKind, WriteError};
pub use error::Error;
pub use version::{GetVersion, Version, VersionEntry};

pub const HEADER_SIZE: usize = 2;

// All messages defined in the SPDM spec implement this trait.
pub trait Msg {
    /// The name of a message as written in the spec (UPPER_SNAKE_CASE).
    const NAME: &'static str;

    // The version of the message as in the SPDM spec
    const SPDM_VERSION: u8;
    // The code of the message as in the SPDM spec.
    const SPDM_CODE: u8;

    /// Write the body of the message, not including the header.
    fn write_body(&self, w: &mut Writer) -> Result<usize, WriteError>;

    /// Parse the 2 byte message header and ensure the version field is
    /// correct for the given message type.
    ///
    /// Return `Ok(true)` if the writed header is of the given type and has a correct version.
    /// Return `Ok(false)` if the header is another message type.
    /// Return an error if the version is wrong for a GetVersion message.
    ///
    /// Prerequisite buf >= 2 bytes
    fn parse_header(buf: &[u8]) -> Result<bool, ReadError> {
        assert!(buf.len() > 2);
        if buf[1] != Self::SPDM_CODE {
            Ok(false)
        } else {
            if buf[0] == Self::SPDM_VERSION {
                Ok(true)
            } else {
                Err(ReadError::new(Self::NAME, ReadErrorKind::Header))
            }
        }
    }

    /// This provided method serializes the header and body of a message into
    /// `buf`.
    fn write(&self, buf: &mut [u8]) -> Result<usize, WriteError> {
        let mut w = Writer::new(Self::NAME, buf);
        Self::write_header(&mut w)?;
        self.write_body(&mut w)
    }

    /// This provided method serializes the 2 byte header common to all SPDM
    /// messages.
    ///
    /// Note that the SPDM spec states that each message has a 4 byte header,
    /// and simply calls the next two bytes `param1` and `param2`. However, in
    /// many cases these bytes are reserved, and in others they are specific to the
    /// message type. For that reason we have the message serialize them in
    /// `write_body`.
    fn write_header(w: &mut Writer) -> Result<usize, WriteError> {
        w.put(Self::SPDM_VERSION)?;
        w.put(Self::SPDM_CODE)
    }
}
