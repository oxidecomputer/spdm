pub mod encoding;
pub mod version;

use encoding::Writer;
pub use encoding::{ReadError, ReadErrorKind, WriteError};
pub use version::{GetVersion, Version, VersionEntry};

pub const HEADER_SIZE: usize = 2;

pub trait Msg {
    // Names should be written as in the spec (UPPER_SNAKE_CASE).
    fn name() -> &'static str;
    fn spdm_version() -> u8;
    fn spdm_code() -> u8;
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
        if buf[1] != Self::spdm_code() {
            Ok(false)
        } else {
            if buf[0] == Self::spdm_version() {
                Ok(true)
            } else {
                Err(ReadError::new(Self::name(), ReadErrorKind::Header))
            }
        }
    }

    fn write(&self, buf: &mut [u8]) -> Result<usize, WriteError> {
        let mut w = Writer::new(Self::name(), buf);
        Self::write_header(&mut w)?;
        self.write_body(&mut w)
    }

    fn write_header(w: &mut Writer) -> Result<usize, WriteError> {
        w.push(Self::spdm_version())?;
        w.push(Self::spdm_code())
    }
}
