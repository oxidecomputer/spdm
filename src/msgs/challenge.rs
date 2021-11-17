use core::cmp::PartialEq;
use core::convert::{TryFrom, TryInto};

use rand::{rngs::OsRng, RngCore};

use super::encoding::{ReadError, ReadErrorKind, Reader, WriteError, Writer};
use super::Msg;
use crate::config::{
    MAX_DIGEST_SIZE, MAX_OPAQUE_DATA_SIZE, MAX_SIGNATURE_SIZE,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MeasurementHashType {
    None = 0x0,
    Tcb = 0x1,
    All = 0xFF,
}

impl TryFrom<u8> for MeasurementHashType {
    type Error = ReadError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0x0 => Ok(MeasurementHashType::None),
            0x1 => Ok(MeasurementHashType::Tcb),
            0xFF => Ok(MeasurementHashType::All),
            _ => {
                Err(ReadError::new("CHALLENGE", ReadErrorKind::UnexpectedValue))
            }
        }
    }
}

pub fn nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub slot: u8,
    pub measurement_hash_type: MeasurementHashType,
    pub nonce: [u8; 32],
}

impl Challenge {
    pub fn new(slot: u8, measurement_hash_type: MeasurementHashType) -> Self {
        let nonce = nonce();
        Challenge { slot, measurement_hash_type, nonce }
    }
}

impl Msg for Challenge {
    const NAME: &'static str = "CHALLENGE";
    const SPDM_VERSION: u8 = 0x11;
    const SPDM_CODE: u8 = 0x83;

    fn write_body(&self, w: &mut Writer) -> Result<usize, WriteError> {
        w.put(self.slot)?;
        w.put(self.measurement_hash_type as u8)?;
        w.extend(&self.nonce)
    }
}

impl Challenge {
    pub fn parse_body(buf: &[u8]) -> Result<Challenge, ReadError> {
        let mut r = Reader::new(Self::NAME, buf);
        let slot = r.get_byte()?;
        let measurement_hash_type = r.get_byte()?.try_into()?;
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(r.get_slice(32)?);
        Ok(Challenge { slot, measurement_hash_type, nonce })
    }
}

#[derive(Debug, Clone)]
pub struct ChallengeAuth {
    // Set to 0xF if the responder's public key was pre-provisioned on the
    // requester.
    pub slot: u8,
    pub slot_mask: u8,
    pub use_mutual_auth: bool,
    pub digest_size: u8,
    pub cert_chain_hash: [u8; MAX_DIGEST_SIZE],
    pub nonce: [u8; 32],
    pub measurement_summary_hash: [u8; MAX_DIGEST_SIZE],
    pub opaque_data_len: u16,
    pub opaque_data: [u8; MAX_OPAQUE_DATA_SIZE],
    pub signature_size: usize,
    pub signature: [u8; MAX_SIGNATURE_SIZE],
}

// We can't derive PartialEq because hashes and signature buffers may only be
// partially full.
impl PartialEq for ChallengeAuth {
    fn eq(&self, other: &Self) -> bool {
        self.slot == other.slot
            && self.slot_mask == other.slot_mask
            && self.digest_size == other.digest_size
            && self.cert_chain_hash[..self.digest_size as usize]
                == other.cert_chain_hash[..other.digest_size as usize]
            && self.nonce == other.nonce
            && self.measurement_summary_hash[..self.digest_size as usize]
                == other.measurement_summary_hash[..other.digest_size as usize]
            && self.opaque_data_len == other.opaque_data_len
            && self.opaque_data[..self.opaque_data_len as usize]
                == other.opaque_data[..other.opaque_data_len as usize]
            && self.signature_size == other.signature_size
            && self.signature[..self.signature_size as usize]
                == other.signature[..other.signature_size as usize]
    }
}

impl Eq for ChallengeAuth {}

impl Msg for ChallengeAuth {
    const NAME: &'static str = "CHALLENGE_AUTH";
    const SPDM_VERSION: u8 = 0x11;
    const SPDM_CODE: u8 = 0x03;

    fn write_body(&self, w: &mut Writer) -> Result<usize, WriteError> {
        assert!(self.slot < 8);
        if self.use_mutual_auth {
            w.put(self.slot & (1 << 7))?;
        } else {
            w.put(self.slot)?;
        }
        w.put(self.slot_mask)?;
        w.extend(&self.cert_chain_hash[..self.digest_size as usize])?;
        w.extend(&self.nonce)?;
        w.extend(&self.measurement_summary_hash[..self.digest_size as usize])?;
        w.put_u16(self.opaque_data_len)?;
        if self.opaque_data_len > 0 {
            w.extend(&self.opaque_data[..self.opaque_data_len as usize])?;
        }
        w.extend(&self.signature[..self.signature_size as usize])
    }
}

impl ChallengeAuth {
    pub fn new(
        slot: u8,
        slot_mask: u8,
        use_mutual_auth: bool,
        cert_chain_digest: &[u8],
        nonce: [u8; 32],
        measurement_summary_digest: &[u8],
        opaque: &[u8],
        sig: &[u8],
    ) -> ChallengeAuth {
        let digest_size = cert_chain_digest.len();

        let mut cert_chain_hash = [0u8; MAX_DIGEST_SIZE];
        cert_chain_hash[..digest_size]
            .copy_from_slice(cert_chain_digest.as_ref());

        let mut measurement_summary_hash = [0u8; MAX_DIGEST_SIZE];
        measurement_summary_hash[..digest_size]
            .copy_from_slice(measurement_summary_digest.as_ref());

        let opaque_data_len = opaque.len();
        let mut opaque_data = [0u8; MAX_OPAQUE_DATA_SIZE];
        opaque_data[..opaque_data_len].copy_from_slice(opaque);

        let signature_size = sig.len();
        let mut signature = [0u8; MAX_SIGNATURE_SIZE];
        signature[..signature_size].copy_from_slice(sig);

        ChallengeAuth {
            slot,
            slot_mask,
            use_mutual_auth,
            digest_size: u8::try_from(digest_size).unwrap(),
            cert_chain_hash,
            nonce,
            measurement_summary_hash,
            opaque_data_len: u16::try_from(opaque_data_len).unwrap(),
            opaque_data,
            signature_size,
            signature,
        }
    }

    pub fn cert_chain_hash(&self) -> &[u8] {
        &self.cert_chain_hash[..self.digest_size as usize]
    }

    pub fn measurement_summary_hash(&self) -> &[u8] {
        &self.measurement_summary_hash[..self.digest_size as usize]
    }

    pub fn opaque_date(&self) -> &[u8] {
        &self.opaque_data[..self.opaque_data_len as usize]
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature[..self.signature_size]
    }

    pub fn parse_body(
        buf: &[u8],
        digest_size: u8,
        signature_size: usize,
    ) -> Result<ChallengeAuth, ReadError> {
        let mut r = Reader::new(Self::NAME, buf);
        let slot = r.get_bits(4)?;
        let _ = r.get_bits(3)?;
        let use_mutual_auth = r.get_bit()? == 1;
        let slot_mask = r.get_byte()?;

        let mut cert_chain_hash = [0u8; MAX_DIGEST_SIZE];
        cert_chain_hash[..digest_size as usize]
            .copy_from_slice(r.get_slice(digest_size as usize)?);

        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(r.get_slice(32)?);

        let mut measurement_summary_hash = [0u8; MAX_DIGEST_SIZE];
        measurement_summary_hash[..digest_size as usize]
            .copy_from_slice(r.get_slice(digest_size as usize)?);

        let opaque_data_len = r.get_u16()?;
        if opaque_data_len as usize > MAX_OPAQUE_DATA_SIZE {
            return Err(ReadError::new(
                Self::NAME,
                ReadErrorKind::ImplementationLimitReached,
            ));
        }
        let mut opaque_data = [0u8; MAX_OPAQUE_DATA_SIZE];
        opaque_data[..opaque_data_len as usize]
            .copy_from_slice(r.get_slice(opaque_data_len as usize)?);

        let mut signature = [0u8; MAX_SIGNATURE_SIZE];
        signature[..signature_size as usize]
            .copy_from_slice(r.get_slice(signature_size as usize)?);

        Ok(ChallengeAuth {
            slot,
            use_mutual_auth,
            slot_mask,
            digest_size,
            cert_chain_hash,
            nonce,
            measurement_summary_hash,
            opaque_data_len,
            opaque_data,
            signature_size,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::HEADER_SIZE;
    use super::*;

    #[test]
    fn round_trip_challenge() {
        let c = Challenge::new(0, MeasurementHashType::Tcb);
        let mut buf = [0u8; 64];
        let _ = c.write(&mut buf).unwrap();
        let c2 = Challenge::parse_body(&buf[HEADER_SIZE..]).unwrap();
        assert_eq!(c, c2);
    }

    #[test]
    fn round_trip_challenge_auth() {
        let digest_size = 32;
        let signature_size = 64;
        let c = ChallengeAuth {
            slot: 0,
            use_mutual_auth: false,
            slot_mask: 0x1,
            digest_size,
            cert_chain_hash: [9u8; MAX_DIGEST_SIZE],
            nonce: [0x13; 32],
            measurement_summary_hash: [7u8; MAX_DIGEST_SIZE],
            opaque_data_len: 0,
            opaque_data: [0u8; 0],
            signature_size,
            signature: [1u8; MAX_SIGNATURE_SIZE],
        };
        let mut buf = [0u8; 256];
        let _ = c.write(&mut buf).unwrap();
        let c2 = ChallengeAuth::parse_body(
            &buf[HEADER_SIZE..],
            digest_size,
            signature_size,
        )
        .unwrap();

        assert_eq!(c, c2);
    }
}
