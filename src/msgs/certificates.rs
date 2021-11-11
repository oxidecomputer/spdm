use super::encoding::{ReadError, ReadErrorKind, Reader, WriteError, Writer};
use super::Msg;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetCertificate {
    pub slot: u8,
    pub offset: u16,
    pub length: u16,
}

impl Msg for GetCertificate {
    const NAME: &'static str = "GET_CERTIFICATE";

    const SPDM_VERSION: u8 = 0x11;

    const SPDM_CODE: u8 = 0x82;

    fn write_body(&self, w: &mut Writer) -> Result<usize, WriteError> {
        w.put(self.slot)?;
        w.put_reserved(1)?;
        w.put_u16(self.offset)?;
        w.put_u16(self.length)
    }
}

impl GetCertificate {
    pub fn parse_body(buf: &[u8]) -> Result<GetCertificate, ReadError> {
        let mut r = Reader::new(Self::NAME, buf);
        let slot = r.get_byte()?;
        r.skip_reserved(1)?;
        let offset = r.get_u16()?;
        let length = r.get_u16()?;

        Ok(GetCertificate { slot, offset, length })
    }
}

/// While the max size of a cert chain is 0xFFFF bytes, most cert chains in
/// practical use are much smaller. On memory constrained systems, to avoid
/// allocating the absolute max size, we instead limit the max size via the
/// const parameter: `N`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate<const N: usize> {
    pub slot: u8,
    pub portion_length: u16,
    pub remainder_length: u16,
    pub cert_chain: [u8; N],
}

impl<const N: usize> Msg for Certificate<N> {
    const NAME: &'static str = "CERTIFICATE";

    const SPDM_VERSION: u8 = 0x11;

    const SPDM_CODE: u8 = 0x02;

    fn write_body(&self, w: &mut Writer) -> Result<usize, WriteError> {
        w.put(self.slot)?;
        w.put_reserved(1)?;
        w.put_u16(self.portion_length)?;
        w.put_u16(self.remainder_length)?;
        w.extend(&self.cert_chain[..self.portion_length as usize])
    }
}

impl<const N: usize> Certificate<N> {
    pub fn parse_body(buf: &[u8]) -> Result<Certificate<N>, ReadError> {
        let mut r = Reader::new(Self::NAME, buf);
        let slot = r.get_byte()?;
        r.skip_reserved(1)?;
        let portion_length = r.get_u16()?;
        if portion_length as usize > N {
            return Err(ReadError::new(
                Self::NAME,
                ReadErrorKind::ImplementationLimitReached,
            ));
        }
        let remainder_length = r.get_u16()?;
        let mut cert_chain = [0u8; N];
        cert_chain[0..portion_length as usize]
            .copy_from_slice(r.get_slice(portion_length as usize)?);

        Ok(Certificate { slot, portion_length, remainder_length, cert_chain })
    }
}

#[cfg(test)]
mod tests {
    use super::super::HEADER_SIZE;
    use super::*;

    #[test]
    fn get_certificate_round_trip() {
        let msg = GetCertificate { slot: 0, offset: 0, length: 1000 };
        let mut buf = [0u8; 128];
        let _ = msg.write(&mut buf).unwrap();

        let msg2 = GetCertificate::parse_body(&buf[HEADER_SIZE..]).unwrap();
        assert_eq!(msg, msg2);
    }

    #[test]
    fn certificate_round_trip() {
        let mut msg = Certificate {
            slot: 0,
            portion_length: 800,
            remainder_length: 0,
            cert_chain: [0u8; 0xFFFF],
        };
        // Ensure the remaining bytes are 0s, since they aren't part of the
        // simulated data.
        msg.cert_chain[800..].copy_from_slice(&[0u8; 0xFFFF - 800]);

        let mut buf = [0u8; 1200];
        let _ = msg.write(&mut buf).unwrap();

        let msg2 = Certificate::parse_body(&buf[HEADER_SIZE..]).unwrap();
        assert_eq!(msg, msg2);
    }
}
