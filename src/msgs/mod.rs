pub mod algorithms;
pub mod capabilities;
pub mod encoding;
pub mod version;
pub mod digest;
pub mod certificates;
pub mod challenge;

use encoding::Writer;
pub use encoding::{ReadError, ReadErrorKind, WriteError};
pub use version::{GetVersion, Version, VersionEntry};
pub use capabilities::{GetCapabilities, Capabilities};
pub use algorithms::{NegotiateAlgorithms, Algorithms};
pub use digest::{GetDigests, Digests};
pub use certificates::{GetCertificate, Certificate, CertificateChain};
pub use challenge::{Challenge, ChallengeAuth, MeasurementHashType};

pub const HEADER_SIZE: usize = 2;

pub trait Msg {
    // Names should be written as in the spec (UPPER_SNAKE_CASE).
    const NAME: &'static str;
    const SPDM_VERSION: u8;
    const SPDM_CODE: u8;

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

    fn write(&self, buf: &mut [u8]) -> Result<usize, WriteError> {
        let mut w = Writer::new(Self::NAME, buf);
        Self::write_header(&mut w)?;
        self.write_body(&mut w)
    }

    fn write_header(w: &mut Writer) -> Result<usize, WriteError> {
        w.put(Self::SPDM_VERSION)?;
        w.put(Self::SPDM_CODE)
    }
}
