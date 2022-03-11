// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::encoding::{BufferFullError, ReadError, Reader, Writer};
use super::Msg;

use bitflags::bitflags;
use core::str::FromStr;

bitflags! {
    /// The Capabilities defined by the requester
    #[derive(Default)]
    pub struct  ReqFlags: u32 {
        const CERT_CAP = 0b0000_0010;
        const CHAL_CAP = 0b0000_0100;
        const ENCRYPT_CAP = 0b0100_0000;
        const MAC_CAP = 0b1000_0000;
        const MUT_AUTH_CAP = 0b0000_0001_0000_0000;
        const KEY_EX_CAP = 0b0000_0010_0000_0000;
        const PSK_CAP = 0b0000_0100_0000_0000;
        const PSK_CAP_MASK = Self::PSK_CAP.bits | 0b0000_1000_0000_0000;
        const ENCAP_CAP = 0b0001_0000_0000_0000;
        const HBEAT_CAP = 0b0010_0000_0000_0000;
        const KEY_UPD_CAP = 0b0100_0000_0000_0000;
        const HANDSHAKE_IN_THE_CLEAR_CAP = 0b1000_0000_0000_0000;
        const PUB_KEY_ID_CAP = 0b0000_0001_0000_0000_0000_0000;
    }
}

/// The capability failed to parse
#[derive(Debug, PartialEq)]
pub struct ParseReqCapabilityError;

// We only allow strings for fields we want the user to configure, excluding
// things like `PSK_CAP_MASK`.
impl FromStr for ReqFlags {
    type Err = ParseReqCapabilityError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let flag = match s {
            "CERT_CAP" => ReqFlags::CERT_CAP,
            "CHAL_CAP" => ReqFlags::CHAL_CAP,
            "ENCRYPT_CAP" => ReqFlags::ENCRYPT_CAP,
            "MAC_CAP" => ReqFlags::MAC_CAP,
            "MUT_AUTH_CAP" => ReqFlags::MUT_AUTH_CAP,
            "KEY_EX_CAP" => ReqFlags::KEY_EX_CAP,
            "PSK_CAP" => ReqFlags::PSK_CAP,
            "ENCAP_CAP" => ReqFlags::ENCAP_CAP,
            "HBEAT_CAP" => ReqFlags::HBEAT_CAP,
            "KEY_UPD_CAP" => ReqFlags::KEY_UPD_CAP,
            "HANDSHAKE_IN_THE_CLEAR_CAP" => {
                ReqFlags::HANDSHAKE_IN_THE_CLEAR_CAP
            }
            "PUB_KEY_ID_CAP" => ReqFlags::PUB_KEY_ID_CAP,
            _ => {
                return Err(ParseReqCapabilityError);
            }
        };
        Ok(flag)
    }
}

#[derive(Debug, PartialEq)]
pub enum ParseGetCapabilitiesError {
    InvalidBitsSet,
    Read(ReadError),
}

impl From<ReadError> for ParseGetCapabilitiesError {
    fn from(e: ReadError) -> Self {
        ParseGetCapabilitiesError::Read(e)
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct GetCapabilities {
    pub ct_exponent: u8,
    pub flags: ReqFlags,
}

impl Msg for GetCapabilities {
    const NAME: &'static str = "GET_CAPABILITIES";

    const SPDM_VERSION: u8 = 0x11;

    const SPDM_CODE: u8 = 0xE1;

    type WriteError = BufferFullError;

    fn write_body(&self, w: &mut Writer) -> Result<usize, BufferFullError> {
        w.put_reserved(3)?;
        w.put(self.ct_exponent)?;
        w.put_reserved(2)?;
        w.put_u32(self.flags.bits())
    }
}

impl GetCapabilities {
    pub fn parse_body(
        buf: &[u8],
    ) -> Result<GetCapabilities, ParseGetCapabilitiesError> {
        let mut reader = Reader::new(buf);
        reader.skip_reserved(3)?;
        let ct_exponent = reader.get_byte()?;
        reader.skip_reserved(2)?;
        let flags = reader.get_u32()?;
        let flags = ReqFlags::from_bits(flags)
            .ok_or_else(|| ParseGetCapabilitiesError::InvalidBitsSet)?;
        Ok(GetCapabilities { ct_exponent, flags })
    }
}

bitflags! {
    /// The Capabilities defined by the responder
    #[derive(Default)]
    pub struct RspFlags: u32 {
        const CACHE_CAP = 0b000_0001;
        const CERT_CAP = 0b0000_0010;
        const CHAL_CAP = 0b0000_0100;
        const MEAS_CAP_NO_SIG = 0b0000_1000;
        const MEAS_CAP_SIG = 0b0001_0000;
        const MEAS_FRESH_CAP = 0b0010_0000;
        const ENCRYPT_CAP = 0b0100_0000;
        const MAC_CAP = 0b1000_0000;
        const MUT_AUTH_CAP = 0b0000_0001_0000_0000;
        const KEY_EX_CAP = 0b0000_0010_0000_0000;
        const PSK_CAP = 0b0000_0100_0000_0000;
        const PSX_CAP_WITH_CONTEXT = 0b0000_1000_0000_0000;
        const ENCAP_CAP = 0b0001_0000_0000_0000;
        const HBEAT_CAP = 0b0010_0000_0000_0000;
        const KEY_UPD_CAP = 0b0100_0000_0000_0000;
        const HANDSHAKE_IN_THE_CLEAR_CAP = 0b1000_0000_0000_0000;
        const PUB_KEY_ID_CAP = 0b0000_0001_0000_0000_0000_0000;
    }
}

/// The capability failed to parse
#[derive(Debug, PartialEq)]
pub struct ParseRspCapabilityError;

// We only allow strings for fields we want the user to configure, excluding
// things like `PSK_CAP_MASK`.impl FromStr for RspFlags {
impl FromStr for RspFlags {
    type Err = ParseRspCapabilityError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let flag = match s {
            "CACHE_CAP" => RspFlags::CACHE_CAP,
            "CERT_CAP" => RspFlags::CERT_CAP,
            "CHAL_CAP" => RspFlags::CHAL_CAP,
            "MEAS_FRESH_CAP" => RspFlags::MEAS_FRESH_CAP,
            "ENCRYPT_CAP" => RspFlags::ENCRYPT_CAP,
            "MAC_CAP" => RspFlags::MAC_CAP,
            "MUT_AUTH_CAP" => RspFlags::MUT_AUTH_CAP,
            "KEY_EX_CAP" => RspFlags::KEY_EX_CAP,
            "PSK_CAP" => RspFlags::PSK_CAP,
            "ENCAP_CAP" => RspFlags::ENCAP_CAP,
            "HBEAT_CAP" => RspFlags::HBEAT_CAP,
            "KEY_UPD_CAP" => RspFlags::KEY_UPD_CAP,
            "HANDSHAKE_IN_THE_CLEAR_CAP" => {
                RspFlags::HANDSHAKE_IN_THE_CLEAR_CAP
            }
            "PUB_KEY_ID_CAP" => RspFlags::PUB_KEY_ID_CAP,
            _ => {
                return Err(ParseRspCapabilityError);
            }
        };
        Ok(flag)
    }
}

#[derive(Debug, PartialEq)]
pub enum ParseCapabilitiesError {
    InvalidBitsSet,
    Read(ReadError),
}

impl From<ReadError> for ParseCapabilitiesError {
    fn from(e: ReadError) -> Self {
        ParseCapabilitiesError::Read(e)
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    pub ct_exponent: u8,
    pub flags: RspFlags,
}

impl Msg for Capabilities {
    const NAME: &'static str = "CAPABILITIES";

    const SPDM_VERSION: u8 = 0x11;

    const SPDM_CODE: u8 = 0x61;

    type WriteError = BufferFullError;

    fn write_body(&self, w: &mut Writer) -> Result<usize, BufferFullError> {
        w.put_reserved(3)?;
        w.put(self.ct_exponent)?;
        w.put_reserved(2)?;
        w.put_u32(self.flags.bits())
    }
}

impl Capabilities {
    pub fn parse_body(
        buf: &[u8],
    ) -> Result<Capabilities, ParseCapabilitiesError> {
        let mut reader = Reader::new(buf);
        reader.skip_reserved(3)?;
        let ct_exponent = reader.get_byte()?;
        reader.skip_reserved(2)?;
        let flags = reader.get_u32()?;
        let flags = RspFlags::from_bits(flags)
            .ok_or_else(|| ParseCapabilitiesError::InvalidBitsSet)?;
        Ok(Capabilities { ct_exponent, flags })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_capabilities_parses_correctly() {
        let mut buf = [0u8; 16];
        let msg = GetCapabilities {
            ct_exponent: 12,
            flags: ReqFlags::CERT_CAP
                | ReqFlags::CHAL_CAP
                | ReqFlags::ENCRYPT_CAP
                | ReqFlags::MAC_CAP
                | ReqFlags::KEY_EX_CAP
                | ReqFlags::MUT_AUTH_CAP,
        };

        // This message serializes into 12 bytes
        assert_eq!(12, msg.write(&mut buf).unwrap());
        assert_eq!(Ok(true), GetCapabilities::parse_header(&buf));
        let msg2 = GetCapabilities::parse_body(&buf[2..]).unwrap();
        assert_eq!(msg, msg2);
    }

    #[test]
    fn get_capabilities_fails_to_parse_with_invalid_flags() {
        let mut buf = [0u8; 16];
        let msg = GetCapabilities {
            ct_exponent: 12,
            flags: ReqFlags::CERT_CAP
                | ReqFlags::CHAL_CAP
                | ReqFlags::ENCRYPT_CAP
                | ReqFlags::MAC_CAP
                | ReqFlags::KEY_EX_CAP
                | ReqFlags::MUT_AUTH_CAP,
        };

        assert_eq!(12, msg.write(&mut buf).unwrap());

        // Set bit 0 of flags (which is reserved and must be 0).
        let invalid = 0x1;
        buf[8] = invalid;

        assert!(GetCapabilities::parse_body(&buf[2..]).is_err());
    }
}
