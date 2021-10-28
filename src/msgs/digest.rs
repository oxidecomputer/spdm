use core::cmp::PartialEq;

use super::encoding::{ReadError, Reader, WriteError, Writer};
use super::Msg;

pub struct GetDigests {}

impl Msg for GetDigests {
    fn name() -> &'static str {
        "GET_DIGESTS"
    }

    fn spdm_version() -> u8 {
        0x11
    }

    fn spdm_code() -> u8 {
        0x81
    }

    fn write_body(&self, w: &mut Writer) -> Result<usize, WriteError> {
        w.put_reserved(2)
    }
}

impl GetDigests {
    pub fn parse_body(buf: &[u8]) -> Result<GetDigests, ReadError> {
        let mut reader = Reader::new(Self::name(), buf);
        reader.skip_reserved(2)?;
        Ok(GetDigests {})
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DigestBuf {
    pub buf: [u8; 64],
}

impl DigestBuf {
    pub fn as_slice(&self, len: usize) -> &[u8] {
        &self.buf[..len]
    }

    pub fn as_mut(&mut self, len: usize) -> &mut [u8] {
        &mut self.buf[..len]
    }
}

impl Default for DigestBuf {
    fn default() -> Self {
        DigestBuf { buf: [0; 64] }
    }
}

#[derive(Debug, Clone)]
pub struct Digests<const NUM_SLOTS: usize> {
    pub digest_size: u8,
    pub slot_mask: u8,

    // Digests are mapped to their slot number
    // They are *not* put on the wire this way.
    pub digests: [DigestBuf; NUM_SLOTS],
}

impl<const NUM_SLOTS: usize> PartialEq for Digests<NUM_SLOTS> {
    fn eq(&self, other: &Self) -> bool {
        if self.digest_size != other.digest_size
            || self.slot_mask != other.slot_mask
        {
            return false;
        }
        let len = self.digest_size as usize;
        for i in 0..self.digests.len() {
            if self.digests[i].as_slice(len) != other.digests[i].as_slice(len) {
                return false;
            }
        }
        true
    }
}

impl<const NUM_SLOTS: usize> Eq for Digests<NUM_SLOTS> {}

impl<const NUM_SLOTS: usize> Msg for Digests<NUM_SLOTS> {
    fn name() -> &'static str {
        "DIGESTS"
    }

    fn spdm_version() -> u8 {
        0x11
    }

    fn spdm_code() -> u8 {
        0x01
    }

    fn write_body(&self, w: &mut Writer) -> Result<usize, WriteError> {
        w.put_reserved(1)?;
        w.put(self.slot_mask)?;
        self.write_digests(w)
    }
}

impl<const NUM_SLOTS: usize> Digests<NUM_SLOTS> {
    // Read in digest using size of the digest agreed upon in NegotiateAlgorithms
    pub fn parse_body(
        digest_size: u8,
        buf: &[u8],
    ) -> Result<Digests<NUM_SLOTS>, ReadError> {
        assert!(digest_size == 32 || digest_size == 48 || digest_size == 64);
        let mut r = Reader::new(Self::name(), buf);
        r.skip_reserved(1)?;
        let slot_mask = r.get_byte()?;
        Self::read_digests(slot_mask, digest_size, &mut r)
    }

    fn read_digests(
        slot_mask: u8,
        digest_size: u8,
        r: &mut Reader,
    ) -> Result<Digests<NUM_SLOTS>, ReadError> {
        let mut digests = [DigestBuf::default(); NUM_SLOTS];
        let mut bits = slot_mask;
        let mut k = bits.trailing_zeros() as usize;
        while k < NUM_SLOTS {
            digests[k].buf[..digest_size as usize]
                .copy_from_slice(r.get_slice(digest_size as usize)?);
            bits ^= 1 << k;
            k = bits.trailing_zeros() as usize;
        }
        Ok(Digests { digest_size, slot_mask, digests })
    }

    // Write out the digests for each active slot k, in slot order, where
    // slot k is the kth bit set in `self.slot_mask`.
    //
    // We loop over the ones from low to high in `self.slot_mask`.
    fn write_digests(&self, w: &mut Writer) -> Result<usize, WriteError> {
        let mut bits = self.slot_mask;
        let mut offset = w.offset();
        let mut k = bits.trailing_zeros() as usize;
        while k < NUM_SLOTS {
            let buf = &self.digests[k].buf[..self.digest_size as usize];
            offset = w.extend(buf)?;
            bits ^= 1 << k;
            k = bits.trailing_zeros() as usize;
        }
        Ok(offset)
    }
}

#[cfg(test)]
mod tests {
    use super::super::HEADER_SIZE;
    use super::*;

    fn test_digest(magic: u8) -> DigestBuf {
        DigestBuf { buf: [magic; 64] }
    }

    fn test_digests() -> [DigestBuf; 8] {
        [
            test_digest(0),
            test_digest(1),
            test_digest(2),
            test_digest(3),
            test_digest(4),
            test_digest(5),
            test_digest(6),
            test_digest(7),
        ]
    }

    #[test]
    fn digest_32_order_0x5_mask() {
        let d = Digests {
            digest_size: 32,
            slot_mask: 0x5, // 0th and 2nd slot occupied
            digests: test_digests(),
        };
        let mut buf = [0u8; 68];
        let size = d.write(&mut buf).unwrap();
        assert_eq!(size, 68);
        assert_eq!(buf[3], 0x5);
        // Bits 0 and 2 are set in the slot mask, and the appropriate digests
        // are written out.
        assert_eq!(&buf[4..36], test_digest(0).as_slice(32));
        assert_eq!(&buf[36..68], test_digest(2).as_slice(32));
    }

    #[test]
    fn digest_32_order_0x16_mask() {
        let d = Digests {
            digest_size: 32,
            slot_mask: 0x16, // Bits 1, 2, 4 set
            digests: test_digests(),
        };
        let mut buf = [0u8; 100];
        let size = d.write(&mut buf).unwrap();
        assert_eq!(size, 100);
        assert_eq!(buf[3], 0x16);
        // Bits 1,2,4 are set in the slot mask, and the appropriate digests
        // are written out.
        assert_eq!(&buf[4..36], test_digest(1).as_slice(32));
        assert_eq!(&buf[36..68], test_digest(2).as_slice(32));
        assert_eq!(&buf[68..100], test_digest(4).as_slice(32));
    }

    #[test]
    fn round_trip_digest_32_0x5_mask() {
        let mut digests = [DigestBuf::default(); 8];
        digests[0] = test_digest(0);
        digests[2] = test_digest(2);
        let d = Digests {
            digest_size: 32,
            slot_mask: 0x5, // 0th and 2nd slot occupied
            digests,
        };
        let mut buf = [0u8; 68];
        let _ = d.write(&mut buf).unwrap();

        let digest_size = 32;
        let d2 = Digests::parse_body(digest_size, &buf[HEADER_SIZE..]).unwrap();
        assert_eq!(d, d2);
    }

    #[test]
    fn round_trip_digest_32_0x16_mask() {
        let mut digests = [DigestBuf::default(); 8];
        digests[1] = test_digest(1);
        digests[2] = test_digest(2);
        digests[4] = test_digest(2);
        let d = Digests {
            digest_size: 32,
            slot_mask: 0x16, // 0th and 2nd slot occupied
            digests,
        };
        let mut buf = [0u8; 100];
        let _ = d.write(&mut buf).unwrap();

        let digest_size = 32;
        let d2 = Digests::parse_body(digest_size, &buf[HEADER_SIZE..]).unwrap();
        assert_eq!(d, d2);
    }

    #[test]
    fn round_trip_digest_32_0xff_mask() {
        let d = Digests {
            digest_size: 32,
            slot_mask: 0xFF,
            digests: test_digests(),
        };
        let mut buf = [0u8; 324];
        let _ = d.write(&mut buf).unwrap();

        let digest_size = 32;
        let d2 = Digests::parse_body(digest_size, &buf[HEADER_SIZE..]).unwrap();
        assert_eq!(d, d2);
    }

    #[test]
    fn round_trip_digest_48_0x2_mask() {
        let digest_size = 48;
        let mut digests = [DigestBuf::default(); 8];
        digests[1] = DigestBuf { buf: [2; 64] };
        let d = Digests { digest_size: 48, slot_mask: 0x2, digests };

        let mut buf = [0u8; 52];
        let size = d.write(&mut buf).unwrap();
        assert_eq!(52, size);

        let d2 = Digests::parse_body(digest_size, &buf[HEADER_SIZE..]).unwrap();
        assert_eq!(d, d2);
    }
}
