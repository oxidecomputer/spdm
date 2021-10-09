use super::encoding::{ReadError, ReadErrorKind, Reader, WriteError, Writer};
use super::Msg;

use bitflags::bitflags;

bitflags! {
    #[derive(Default)]
    struct ReqFlags: u32 {
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

pub struct GetCapabilities {
    ct_exponent: u8,
    flags: ReqFlags,
}

impl Msg for GetCapabilities {
    fn name() -> &'static str {
        "GET_CAPABILITIES"
    }

    fn spdm_version() -> u8 {
        0x11
    }

    fn spdm_code() -> u8 {
        0xE1
    }

    fn write_body(&self, w: &mut Writer) -> Result<usize, WriteError> {
        w.put_reserved(3)?;
        w.put(self.ct_exponent)?;
        w.put_reserved(2)?;
        w.put_u32(self.flags.bits())
    }
}

impl GetCapabilities {
    pub fn parse_body(buf: &[u8]) -> Result<GetCapabilities, ReadError> {
        let mut reader = Reader::new(Self::name(), buf);
        reader.skip_reserved(3)?;
        let ct_exponent = reader.get_byte()?;
        reader.skip_reserved(2)?;
        let flags = reader.get_u32()?;
        let flags = ReqFlags::from_bits(flags).ok_or_else(|| {
            ReadError::new(Self::name(), ReadErrorKind::InvalidBitsSet)
        })?;
        Ok(GetCapabilities { ct_exponent, flags })
    }
}
