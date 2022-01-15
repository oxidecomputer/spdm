// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use core::cmp::PartialEq;

use super::common::{DigestBuf, DigestSize};
use super::encoding::{ReadError, Reader, WriteError, Writer};
use super::Msg;

use crate::config::NUM_SLOTS;

/// Request Digests for all certificates in the responder.
///
/// This mechanism is used as an optimization to allow caching certificates. If
/// the digest for the given slot has not changed, the certificate does not have to
/// be re-fetched. The current implementation does not yet support this
/// functionality, but to satisfy the protocol GET_DIGESTS must be issued
/// before GET_CERTIFICATE.
pub struct GetDigests {}

impl Msg for GetDigests {
    const NAME: &'static str = "GET_DIGESTS";

    const SPDM_VERSION: u8 = 0x11;

    const SPDM_CODE: u8 = 0x81;

    fn write_body(&self, w: &mut Writer) -> Result<usize, WriteError> {
        w.put_reserved(2)
    }
}

impl GetDigests {
    pub fn parse_body(buf: &[u8]) -> Result<GetDigests, ReadError> {
        let mut reader = Reader::new(Self::NAME, buf);
        reader.skip_reserved(2)?;
        Ok(GetDigests {})
    }
}

/// The response to a GET_DIGESTS msg
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digests {
    pub slot_mask: u8,

    // Digests are mapped to their slot number
    // They are *not* put on the wire this way.
    pub digests: [Option<DigestBuf>; NUM_SLOTS],
}

impl Msg for Digests {
    const NAME: &'static str = "DIGESTS";

    const SPDM_VERSION: u8 = 0x11;

    const SPDM_CODE: u8 = 0x01;

    fn write_body(&self, w: &mut Writer) -> Result<usize, WriteError> {
        w.put_reserved(1)?;
        w.put(self.slot_mask)?;
        self.write_digests(w)
    }
}

impl Digests {
    // Read in digest using size of the digest agreed upon in NegotiateAlgorithms
    pub fn parse_body(
        digest_size: DigestSize,
        buf: &[u8],
    ) -> Result<Digests, ReadError> {
        let mut r = Reader::new(Self::NAME, buf);
        r.skip_reserved(1)?;
        let slot_mask = r.get_byte()?;
        Self::read_digests(slot_mask, digest_size, &mut r)
    }

    fn read_digests(
        slot_mask: u8,
        digest_size: DigestSize,
        r: &mut Reader,
    ) -> Result<Digests, ReadError> {
        // Avoid need to make DigestBuf copy
        const VAL: Option<DigestBuf> = None;
        let mut digests = [VAL; NUM_SLOTS];
        let mut bits = slot_mask;
        let mut k = bits.trailing_zeros() as usize;
        while k < NUM_SLOTS {
            let mut digest = DigestBuf::new(digest_size);
            r.get_slice(digest_size.into(), digest.as_mut())?;
            digests[k] = Some(digest);
            bits ^= 1 << k;
            k = bits.trailing_zeros() as usize;
        }
        Ok(Digests { slot_mask, digests })
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
            offset = w.extend(self.digests[k].as_ref().unwrap().as_ref())?;
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

    use std::convert::TryFrom;

    fn empty_digests() -> [Option<DigestBuf>; NUM_SLOTS] {
        // Avoid requiring DigestBuf to be Copy
        const VAL: Option<DigestBuf> = None;
        [VAL; NUM_SLOTS]
    }

    fn test_digest(size: DigestSize, magic: u8) -> Option<DigestBuf> {
        Some(DigestBuf::new_with_magic(size, magic))
    }

    fn test_digests(size: DigestSize) -> [Option<DigestBuf>; NUM_SLOTS] {
        let mut digests = empty_digests();
        for i in 0..NUM_SLOTS {
            digests[i] = test_digest(size, i as u8);
        }
        digests
    }

    #[test]
    fn digest_32_order_0x5_mask() {
        let digest_size = DigestSize::try_from(32).unwrap();
        let d = Digests {
            slot_mask: 0x5, // 0th and 2nd slot occupied
            digests: test_digests(digest_size),
        };
        let mut buf = [0u8; 68];
        let size = d.write(&mut buf).unwrap();
        assert_eq!(size, 68);
        assert_eq!(buf[3], 0x5);
        // Bits 0 and 2 are set in the slot mask, and the appropriate digests
        // are written out.
        assert_eq!(&buf[4..36], test_digest(digest_size, 0).unwrap().as_ref());
        assert_eq!(&buf[36..68], test_digest(digest_size, 2).unwrap().as_ref());
    }

    #[test]
    fn digest_32_order_0x16_mask() {
        let digest_size = DigestSize::try_from(32).unwrap();
        let d = Digests {
            slot_mask: 0x16, // Bits 1, 2, 4 set
            digests: test_digests(digest_size),
        };
        let mut buf = [0u8; 100];
        let size = d.write(&mut buf).unwrap();
        assert_eq!(size, 100);
        assert_eq!(buf[3], 0x16);
        // Bits 1,2,4 are set in the slot mask, and the appropriate digests
        // are written out.
        assert_eq!(&buf[4..36], test_digest(digest_size, 1).unwrap().as_ref());
        assert_eq!(&buf[36..68], test_digest(digest_size, 2).unwrap().as_ref());
        assert_eq!(
            &buf[68..100],
            test_digest(digest_size, 4).unwrap().as_ref()
        );
    }

    #[test]
    fn round_trip_digest_32_0x5_mask() {
        let digest_size = DigestSize::try_from(32).unwrap();
        let mut digests = empty_digests();
        digests[0] = test_digest(digest_size, 0);
        digests[2] = test_digest(digest_size, 2);
        let d = Digests {
            slot_mask: 0x5, // 0th and 2nd slot occupied
            digests,
        };
        let mut buf = [0u8; 68];
        let _ = d.write(&mut buf).unwrap();

        let d2 = Digests::parse_body(digest_size, &buf[HEADER_SIZE..]).unwrap();
        assert_eq!(d, d2);
    }

    #[test]
    fn round_trip_digest_32_0x16_mask() {
        let digest_size = DigestSize::try_from(32).unwrap();
        let mut digests = empty_digests();
        digests[1] = test_digest(digest_size, 1);
        digests[2] = test_digest(digest_size, 2);
        digests[4] = test_digest(digest_size, 2);
        let d = Digests {
            slot_mask: 0x16, // 0th and 2nd slot occupied
            digests,
        };
        let mut buf = [0u8; 100];
        let _ = d.write(&mut buf).unwrap();

        let d2 = Digests::parse_body(digest_size, &buf[HEADER_SIZE..]).unwrap();
        assert_eq!(d, d2);
    }

    #[test]
    fn round_trip_digest_32_0xff_mask() {
        let digest_size = DigestSize::try_from(32).unwrap();
        let d = Digests { slot_mask: 0xFF, digests: test_digests(digest_size) };
        let mut buf = [0u8; 324];
        let _ = d.write(&mut buf).unwrap();

        let d2 = Digests::parse_body(digest_size, &buf[HEADER_SIZE..]).unwrap();
        assert_eq!(d, d2);
    }

    #[test]
    fn round_trip_digest_48_0x2_mask() {
        let digest_size = DigestSize::try_from(48).unwrap();
        let mut digests = empty_digests();
        digests[1] = test_digest(digest_size, 2);
        let d = Digests { slot_mask: 0x2, digests };

        let mut buf = [0u8; 52];
        let size = d.write(&mut buf).unwrap();
        assert_eq!(52, size);

        let d2 = Digests::parse_body(digest_size, &buf[HEADER_SIZE..]).unwrap();
        assert_eq!(d, d2);
    }
}
