// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use core::cmp::PartialEq;
use core::convert::{TryFrom, TryInto};

use crate::crypto::Nonce;

use super::common::{
    DigestBuf, DigestSize, OpaqueData, ParseOpaqueDataError, SignatureBuf,
    SignatureSize, WriteOpaqueElementError,
};
use super::encoding::{BufferFullError, ReadError, Reader, Writer};
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

#[derive(Debug)]
pub struct ParseMeasurementHashTypeError;

impl TryFrom<u8> for MeasurementHashType {
    type Error = ParseMeasurementHashTypeError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0x0 => Ok(MeasurementHashType::None),
            0x1 => Ok(MeasurementHashType::Tcb),
            0xFF => Ok(MeasurementHashType::All),
            _ => Err(ParseMeasurementHashTypeError),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum ParseChallengeError {
    InvalidMeasurementHashType,
    Read(ReadError),
}

impl From<ReadError> for ParseChallengeError {
    fn from(e: ReadError) -> Self {
        ParseChallengeError::Read(e)
    }
}

impl From<ParseMeasurementHashTypeError> for ParseChallengeError {
    fn from(_: ParseMeasurementHashTypeError) -> Self {
        ParseChallengeError::InvalidMeasurementHashType
    }
}

/// The requester side of challenge authentication
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub slot: u8,
    pub measurement_hash_type: MeasurementHashType,
    pub nonce: Nonce,
}

impl Challenge {
    pub fn new(slot: u8, measurement_hash_type: MeasurementHashType) -> Self {
        Challenge { slot, measurement_hash_type, nonce: Nonce::new() }
    }
}

impl Msg for Challenge {
    const NAME: &'static str = "CHALLENGE";
    const SPDM_VERSION: u8 = 0x11;
    const SPDM_CODE: u8 = 0x83;

    type WriteError = BufferFullError;

    fn write_body(&self, w: &mut Writer) -> Result<usize, BufferFullError> {
        w.put(self.slot)?;
        w.put(self.measurement_hash_type as u8)?;
        w.extend(&self.nonce.as_ref())
    }
}

impl Challenge {
    pub fn parse_body(buf: &[u8]) -> Result<Challenge, ParseChallengeError> {
        let mut r = Reader::new(buf);
        let slot = r.get_byte()?;
        let measurement_hash_type = r.get_byte()?.try_into()?;
        let nonce = Nonce::read(&mut r)?;
        Ok(Challenge { slot, measurement_hash_type, nonce })
    }
}

#[derive(Debug, PartialEq)]
pub enum WriteChallengeAuthError {
    MaxSlotNumberExceeded,
    MaxOpaqueDataSizeExceeded,
    BufferFull,
    WriteOpaqueElement(WriteOpaqueElementError),
}

impl From<BufferFullError> for WriteChallengeAuthError {
    fn from(_: BufferFullError) -> Self {
        WriteChallengeAuthError::BufferFull
    }
}

impl From<WriteOpaqueElementError> for WriteChallengeAuthError {
    fn from(e: WriteOpaqueElementError) -> Self {
        WriteChallengeAuthError::WriteOpaqueElement(e)
    }
}

#[derive(Debug, PartialEq)]
pub enum ParseChallengeAuthError {
    MaxSlotNumberExceeded,
    MaxOpaqueDataSizeExceeded,
    ParseOpaqueData(ParseOpaqueDataError),
    Read(ReadError),
}

impl From<ReadError> for ParseChallengeAuthError {
    fn from(e: ReadError) -> Self {
        ParseChallengeAuthError::Read(e)
    }
}

impl From<ParseOpaqueDataError> for ParseChallengeAuthError {
    fn from(e: ParseOpaqueDataError) -> Self {
        ParseChallengeAuthError::ParseOpaqueData(e)
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
    pub nonce: Nonce,
    pub measurement_summary_hash: DigestBuf,
    pub opaque_data: OpaqueData,
    pub signature: SignatureBuf,
}

impl Msg for ChallengeAuth {
    const NAME: &'static str = "CHALLENGE_AUTH";
    const SPDM_VERSION: u8 = 0x11;
    const SPDM_CODE: u8 = 0x03;

    type WriteError = WriteChallengeAuthError;

    fn write_body(
        &self,
        w: &mut Writer,
    ) -> Result<usize, WriteChallengeAuthError> {
        self.validate()?;
        if self.use_mutual_auth {
            w.put(self.slot & (1 << 7))?;
        } else {
            w.put(self.slot)?;
        }
        w.put(self.slot_mask)?;
        w.extend(&self.cert_chain_hash.as_ref())?;
        w.extend(&self.nonce.as_ref())?;
        w.extend(&self.measurement_summary_hash.as_ref())?;
        w.put_u16(self.opaque_data.serialized_size() as u16)?;
        self.opaque_data.write(w)?;
        w.extend(&self.signature.as_ref())?;
        Ok(w.offset())
    }
}

impl ChallengeAuth {
    pub fn validate(&self) -> Result<(), WriteChallengeAuthError> {
        if self.slot as usize >= NUM_SLOTS {
            return Err(WriteChallengeAuthError::MaxSlotNumberExceeded);
        }
        let opaque_size = self.opaque_data.serialized_size();
        if opaque_size > MAX_OPAQUE_DATA_SIZE {
            return Err(WriteChallengeAuthError::MaxOpaqueDataSizeExceeded);
        }
        Ok(())
    }

    pub fn new(
        slot: u8,
        slot_mask: u8,
        use_mutual_auth: bool,
        cert_chain_digest: &[u8],
        nonce: Nonce,
        measurement_summary_digest: &[u8],
        opaque_data: OpaqueData,
        sig: &[u8],
    ) -> ChallengeAuth {
        // Fail fast in case of a configuration error
        let cc_hash = cert_chain_digest.try_into().unwrap();
        let ms_hash = measurement_summary_digest.try_into().unwrap();
        let signature = sig.try_into().unwrap();

        ChallengeAuth {
            slot,
            slot_mask,
            use_mutual_auth,
            cert_chain_hash: cc_hash,
            nonce,
            measurement_summary_hash: ms_hash,
            opaque_data,
            signature,
        }
    }

    /// Deserialize the body of the ChallengeAuth message, given the digest_size
    /// and signature_size that correspond to the negotiated algorithms in previous
    /// steps of the protocol.
    pub fn parse_body(
        buf: &[u8],
        digest_size: DigestSize,
        signature_size: SignatureSize,
    ) -> Result<ChallengeAuth, ParseChallengeAuthError> {
        let mut r = Reader::new(buf);
        let slot = r.get_bits(4)?;
        if slot as usize > NUM_SLOTS {
            return Err(ParseChallengeAuthError::MaxOpaqueDataSizeExceeded);
        }
        let _ = r.get_bits(3)?;
        let use_mutual_auth = r.get_bit()? == 1;
        let slot_mask = r.get_byte()?;

        let cert_chain_hash = DigestBuf::read(digest_size, &mut r)?;
        let nonce = Nonce::read(&mut r)?;
        let measurement_summary_hash = DigestBuf::read(digest_size, &mut r)?;
        let opaque_data_len = r.get_u16()?;

        if opaque_data_len as usize > MAX_OPAQUE_DATA_SIZE {
            return Err(ParseChallengeAuthError::MaxOpaqueDataSizeExceeded);
        }
        let opaque_data = OpaqueData::read(&mut r)?;
        let signature = SignatureBuf::read(signature_size, &mut r)?;

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
        let digest_size = DigestSize::try_from(32).unwrap();
        let signature_size = SignatureSize::try_from(64).unwrap();
        let c = ChallengeAuth {
            slot: 0,
            use_mutual_auth: false,
            slot_mask: 0x1,
            cert_chain_hash: DigestBuf::new_with_magic(digest_size, 9),
            nonce: Nonce::new_with_magic(13),
            measurement_summary_hash: DigestBuf::new_with_magic(digest_size, 7),
            opaque_data: OpaqueData::default(),
            signature: SignatureBuf::new_with_magic(signature_size, 1),
        };

        let mut buf = [0u8; 256];
        let _ = c.write(&mut buf).unwrap();
        let c2 = ChallengeAuth::parse_body(
            &buf[HEADER_SIZE..],
            digest_size.try_into().unwrap(),
            signature_size.try_into().unwrap(),
        )
        .unwrap();

        assert_eq!(c, c2);
    }
}
