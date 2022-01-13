// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use core::cmp::PartialEq;
use core::convert::{TryFrom, TryInto};

use rand::{rngs::OsRng, RngCore};

use super::common::{DigestBuf, OpaqueData, SignatureBuf};
use super::encoding::{
    ReadError, ReadErrorKind, Reader, WriteError, WriteErrorKind, Writer,
};
use super::Msg;
use crate::config::NUM_SLOTS;

const MAX_OPAQUE_DATA_SIZE: usize = 1024;

/// The type of measurement requested in a CHALLENGE request
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

/// Generate a 32 byte nonce
pub fn nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// The requester side of challenge authentication
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
        r.get_slice(32, &mut nonce)?;
        Ok(Challenge { slot, measurement_hash_type, nonce })
    }
}

/// The responder side of challenge authentication
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeAuth {
    // Set to 0xF if the responder's public key was pre-provisioned on the
    // requester.
    pub slot: u8,
    pub slot_mask: u8,
    pub use_mutual_auth: bool,
    pub cert_chain_hash: DigestBuf,
    pub nonce: [u8; 32],
    pub measurement_summary_hash: DigestBuf,
    pub opaque_data: OpaqueData,
    pub signature: SignatureBuf,
}

impl Msg for ChallengeAuth {
    const NAME: &'static str = "CHALLENGE_AUTH";
    const SPDM_VERSION: u8 = 0x11;
    const SPDM_CODE: u8 = 0x03;

    fn write_body(&self, w: &mut Writer) -> Result<usize, WriteError> {
        self.validate()?;
        if self.use_mutual_auth {
            w.put(self.slot & (1 << 7))?;
        } else {
            w.put(self.slot)?;
        }
        w.put(self.slot_mask)?;
        w.extend(&self.cert_chain_hash.as_slice())?;
        w.extend(&self.nonce)?;
        w.extend(&self.measurement_summary_hash.as_slice())?;
        w.put_u16(self.opaque_data.serialized_size() as u16)?;
        self.opaque_data.write(w)?;
        w.extend(&self.signature.as_slice())
    }
}

impl ChallengeAuth {
    pub fn validate(&self) -> Result<(), WriteError> {
        if self.slot as usize >= NUM_SLOTS {
            return Err(WriteError::new(
                Self::NAME,
                WriteErrorKind::UnexpectedValue("slot"),
            ));
        }
        let opaque_size = self.opaque_data.serialized_size();
        if opaque_size > MAX_OPAQUE_DATA_SIZE {
            return Err(WriteError::new(
                Self::NAME,
                WriteErrorKind::TooLarge {
                    field: "OpaqueData",
                    max_size: MAX_OPAQUE_DATA_SIZE,
                    actual_size: opaque_size,
                },
            ));
        }
        Ok(())
    }

    pub fn new(
        slot: u8,
        slot_mask: u8,
        use_mutual_auth: bool,
        cert_chain_digest: &[u8],
        nonce: [u8; 32],
        measurement_summary_digest: &[u8],
        opaque_data: OpaqueData,
        sig: &[u8],
    ) -> Result<ChallengeAuth, WriteError> {
        let cert_chain_hash = cert_chain_digest.try_into()?;
        let measurement_summary_hash = measurement_summary_digest.try_into()?;
        let signature = sig.try_into()?;

        Ok(ChallengeAuth {
            slot,
            slot_mask,
            use_mutual_auth,
            cert_chain_hash,
            nonce,
            measurement_summary_hash,
            opaque_data,
            signature,
        })
    }

    /// Deserialize the body of the ChallengeAuth message, given the digest_size
    /// and signature_size that correspond to the negotiated algorithms in previous
    /// steps of the protocol.
    pub fn parse_body(
        buf: &[u8],
        digest_size: u8,
        signature_size: u16,
    ) -> Result<ChallengeAuth, ReadError> {
        let mut r = Reader::new(Self::NAME, buf);
        let slot = r.get_bits(4)?;
        let _ = r.get_bits(3)?;
        let use_mutual_auth = r.get_bit()? == 1;
        let slot_mask = r.get_byte()?;

        let mut cert_chain_hash = DigestBuf::new(digest_size);
        r.get_slice(digest_size as usize, cert_chain_hash.as_mut())?;

        let mut nonce = [0u8; 32];
        r.get_slice(32, &mut nonce)?;

        let mut measurement_summary_hash = DigestBuf::new(digest_size);
        r.get_slice(digest_size as usize, measurement_summary_hash.as_mut())?;

        let opaque_data_len = r.get_u16()?;

        if opaque_data_len as usize > MAX_OPAQUE_DATA_SIZE {
            return Err(ReadError::new(
                Self::NAME,
                ReadErrorKind::SpdmLimitReached,
            ));
        }
        let opaque_data = OpaqueData::read(&mut r)?;

        let mut signature = SignatureBuf::new(signature_size);
        r.get_slice(signature_size as usize, signature.as_mut())?;

        Ok(ChallengeAuth {
            slot,
            slot_mask,
            use_mutual_auth,
            cert_chain_hash,
            nonce,
            measurement_summary_hash,
            opaque_data,
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
            cert_chain_hash: DigestBuf::new_with_magic(digest_size, 9),
            nonce: [0x13; 32],
            measurement_summary_hash: DigestBuf::new_with_magic(digest_size, 7),
            opaque_data: OpaqueData::default(),
            signature: SignatureBuf::new_with_magic(signature_size, 1),
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
