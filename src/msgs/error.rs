// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::common::{VendorId, VendorRegistryId};
use super::encoding::{ReadError, ReadErrorKind, Reader, WriteError, Writer};
use super::Msg;

use core::convert::TryFrom;

const MAX_OPAQUE_ERROR_DATA_SIZE: usize = 32;

// This is a SPDM Error response message
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    InvalidRequest,
    Busy,
    UnexpectedRequest,
    Unspecified,
    DecryptError,
    UnsupportedRequest(u8),
    RequestInFlight,
    InvalidResponseCode,
    SessionLimitExceeded,
    SessionRequired,
    ResetRequired,
    ResponseTooLarge(u32),
    RequestTooLarge,
    LargeResponse(u8),
    MessageLost,
    VersionMismatch,
    ResponseNotReady(ResponseNotReady),
    RequestResynch,
    VendorDefined(VendorRegistryId, VendorDefined),
}

#[derive(Debug, Clone, PartialEq)]
pub struct VendorDefined {
    vendor_id: VendorId,

    // The actual length of `opaque_error_data`
    opaque_len: usize,
    opaque_error_data: [u8; MAX_OPAQUE_ERROR_DATA_SIZE],
}

impl VendorDefined {
    pub fn empty() -> Self {
        VendorDefined {
            vendor_id: VendorId::Empty,
            opaque_len: 0,
            opaque_error_data: [0u8; MAX_OPAQUE_ERROR_DATA_SIZE],
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResponseNotReady {
    rdt_exponent: u8,
    request_code: u8,
    token: u8,
    rdtm: u8,
}

impl Msg for Error {
    const NAME: &'static str = "ERROR";
    const SPDM_VERSION: u8 = 0x12;
    const SPDM_CODE: u8 = 0x7F;

    fn write_body(&self, w: &mut Writer) -> Result<usize, WriteError> {
        match self {
            Error::InvalidRequest => {
                w.put(0x1)?;
                w.put(0)?;
            }
            Error::Busy => {
                w.put(0x3)?;
                w.put(0)?;
            }
            Error::UnexpectedRequest => {
                w.put(0x4)?;
                w.put(0)?;
            }
            Error::Unspecified => {
                w.put(0x5)?;
                w.put(0)?;
            }
            Error::DecryptError => {
                w.put(0x6)?;
                w.put(0)?;
            }
            Error::UnsupportedRequest(req_code) => {
                w.put(0x7)?;
                w.put(*req_code)?;
            }
            Error::RequestInFlight => {
                w.put(0x8)?;
                w.put(0)?;
            }
            Error::InvalidResponseCode => {
                w.put(0x9)?;
                w.put(0)?;
            }
            Error::SessionLimitExceeded => {
                w.put(0xA)?;
                w.put(0)?;
            }
            Error::SessionRequired => {
                w.put(0xB)?;
                w.put(0)?;
            }
            Error::ResetRequired => {
                w.put(0xC)?;
                w.put(0)?;
            }
            Error::ResponseTooLarge(actual_size) => {
                w.put(0xD)?;
                w.put(0)?;
                w.put_u32(*actual_size)?;
            }
            Error::RequestTooLarge => {
                w.put(0xE)?;
                w.put(0)?;
            }
            Error::LargeResponse(handle) => {
                w.put(0xF)?;
                w.put(0)?;
                w.put(*handle)?;
            }
            Error::MessageLost => {
                w.put(0x10)?;
                w.put(0)?;
            }
            Error::VersionMismatch => {
                w.put(0x41)?;
                w.put(0)?;
            }
            Error::ResponseNotReady(val) => {
                w.put(0x42)?;
                w.put(0)?;
                w.put(val.rdt_exponent)?;
                w.put(val.request_code)?;
                w.put(val.token)?;
                w.put(val.rdtm)?;
            }
            Error::RequestResynch => {
                w.put(0x43)?;
                w.put(0)?;
            }
            Error::VendorDefined(id, val) => {
                w.put(0xFF)?;
                w.put(*id as u8)?;
                val.vendor_id.write(w)?;
                w.extend(&val.opaque_error_data[..val.opaque_len])?;
            }
        }
        Ok(w.offset())
    }
}

impl Error {
    pub fn parse_body(buf: &[u8]) -> Result<Error, ReadError> {
        let mut r = Reader::new(Self::NAME, buf);
        let code = r.get_byte()?;
        let data = r.get_byte()?;

        let msg = match code {
            0x1 => Error::InvalidRequest,
            0x3 => Error::Busy,
            0x4 => Error::UnexpectedRequest,
            0x5 => Error::Unspecified,
            0x6 => Error::DecryptError,
            0x7 => Error::UnsupportedRequest(data),
            0x8 => Error::RequestInFlight,
            0x9 => Error::InvalidResponseCode,
            0xA => Error::SessionLimitExceeded,
            0xB => Error::SessionRequired,
            0xC => Error::ResetRequired,
            0xD => {
                let actual_size = r.get_u32()?;
                Error::ResponseTooLarge(actual_size)
            }
            0xE => Error::RequestTooLarge,
            0xF => {
                let handle = r.get_byte()?;
                Error::LargeResponse(handle)
            }
            0x10 => Error::MessageLost,
            0x41 => Error::VersionMismatch,
            0x42 => {
                let rdt_exponent = r.get_byte()?;
                let request_code = r.get_byte()?;
                let token = r.get_byte()?;
                let rdtm = r.get_byte()?;
                Error::ResponseNotReady(ResponseNotReady {
                    rdt_exponent,
                    request_code,
                    token,
                    rdtm,
                })
            }
            0x43 => Error::RequestResynch,

            // TODO: Figure out how to parse opaque_error_data. Use `buf.len()`?
            // See https://github.com/oxidecomputer/spdm/issues/20
            //
            // TODO: Should we also validate that the VendorId lengths match the
            // values in table 50 of the 1.2 spec?
            0xFF => {
                let vendor_registry_id = VendorRegistryId::try_from(data)?;
                let vendor_id_len = r.get_byte()?;
                let vendor_id = VendorId::read(&mut r, vendor_id_len)?;
                Error::VendorDefined(
                    vendor_registry_id,
                    VendorDefined { vendor_id, ..VendorDefined::empty() },
                )
            }
            _ => {
                return Err(ReadError::new(
                    "ERROR",
                    ReadErrorKind::UnexpectedValue,
                ))
            }
        };
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut buf = [0u8; 64];
        let msg = Error::ResponseTooLarge(56789);
        let size = msg.write(&mut buf).unwrap();
        assert_eq!(8, size);
        assert_eq!(msg, Error::parse_body(&buf[2..]).unwrap());

        let msg = Error::UnexpectedRequest;
        let size = msg.write(&mut buf).unwrap();
        assert_eq!(4, size);
        assert_eq!(msg, Error::parse_body(&buf[2..]).unwrap());

        let msg = Error::ResponseNotReady(ResponseNotReady {
            rdt_exponent: 1,
            request_code: 2,
            token: 3,
            rdtm: 4,
        });
        let size = msg.write(&mut buf).unwrap();
        assert_eq!(8, size);
        assert_eq!(msg, Error::parse_body(&buf[2..]).unwrap());

        let msg = Error::VendorDefined(
            VendorRegistryId::Jedec,
            VendorDefined {
                vendor_id: VendorId::U16(0x1234),
                opaque_len: 0,
                opaque_error_data: [0u8; MAX_OPAQUE_ERROR_DATA_SIZE],
            },
        );
        let size = msg.write(&mut buf).unwrap();
        assert_eq!(7, size);
        assert_eq!(msg, Error::parse_body(&buf[2..]).unwrap());

        // Invalid VendorId length triggers UnexpectedValue error
        buf[4] = 6;
        assert_eq!(
            Err(ReadError::new("ERROR", ReadErrorKind::UnexpectedValue)),
            Error::parse_body(&buf[2..])
        );
    }
}
