// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::challenge;
use super::encoding::{
    ReadError, ReadErrorKind, Reader, WriteError, WriteErrorKind, Writer,
};
use super::Msg;
use crate::config;

use core::convert::{From, TryFrom, TryInto};

#[derive(Debug, Clone, PartialEq)]
pub struct RequestAttributes {
    // If this field is set, the nonce field must be present.
    pub signature_requested: bool,
    pub raw_bit_stream_requested: bool,
}

impl From<&RequestAttributes> for u8 {
    fn from(val: &RequestAttributes) -> u8 {
        let mut out = 0u8;
        if val.signature_requested {
            out |= 0x1;
        }
        if val.raw_bit_stream_requested {
            out |= 0x2;
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum MeasurementIndex {
    TotalNumberOfMeasurementsAvailable,
    AllMeasurements,

    // 0x1 - 0xEF
    ImplementationDefined(u8),

    // These indexes are assigned by the DMTF for specific purposes
    //
    // 0xF0 - 0xFC
    Reserved(u8),
    MeasurementManifest,
    DeviceMode,
}

impl From<u8> for MeasurementIndex {
    fn from(val: u8) -> Self {
        match val {
            0 => MeasurementIndex::TotalNumberOfMeasurementsAvailable,
            0xFF => MeasurementIndex::AllMeasurements,
            index @ 0x01..=0xEF => {
                MeasurementIndex::ImplementationDefined(index)
            }
            index @ 0xF0..=0xFC => MeasurementIndex::Reserved(index),
            0xFD => MeasurementIndex::MeasurementManifest,
            0xFE => MeasurementIndex::DeviceMode,
        }
    }
}

impl TryFrom<&MeasurementIndex> for u8 {
    type Error = WriteError;
    fn try_from(val: &MeasurementIndex) -> Result<Self, Self::Error> {
        let index = match val {
            MeasurementIndex::TotalNumberOfMeasurementsAvailable => 0,
            MeasurementIndex::AllMeasurements => 0xFF,
            MeasurementIndex::ImplementationDefined(index) => {
                if *index < 0x1 || *index > 0xEF {
                    return Err(WriteError::new(
                        "GET_MEASUREMENTS",
                        WriteErrorKind::InvalidRange(
                            "MeasurementIndex (ImplementationDefined)",
                        ),
                    ));
                }
                *index
            }
            MeasurementIndex::Reserved(index) => {
                if *index < 0xF0 || *index > 0xFC {
                    return Err(WriteError::new(
                        "GET_MEASUREMENTS",
                        WriteErrorKind::InvalidRange(
                            "MeasurementIndex (Reserved)",
                        ),
                    ));
                }
                *index
            }
            MeasurementIndex::MeasurementManifest => 0xFD,
            MeasurementIndex::DeviceMode => 0xFE,
        };
        Ok(index)
    }
}

// Request measurements from a responder.
#[derive(Debug, Clone, PartialEq)]
pub struct GetMeasurements {
    // Param1
    attributes: RequestAttributes,

    // Param2
    index: MeasurementIndex,

    // Only valid if signature_requested attribute is set
    nonce: Option<[u8; 32]>,

    // Slot number of the responder certificate chain used for measurement auth
    // Only present on the wire if signature_requested attribute is set.
    slot_id: u8,
}

impl GetMeasurements {
    pub fn new(
        attributes: RequestAttributes,
        index: MeasurementIndex,
        slot_id: u8,
    ) -> Result<GetMeasurements, WriteError> {
        if (slot_id as usize) >= config::NUM_SLOTS {
            return Err(WriteError::new(
                Self::NAME,
                WriteErrorKind::InvalidRange("slot_id"),
            ));
        }
        let mut nonce = None;
        if attributes.signature_requested {
            nonce = Some(challenge::nonce());
        }
        Ok(GetMeasurements { attributes, index, slot_id, nonce })
    }
}

impl Msg for GetMeasurements {
    const NAME: &'static str = "GET_MEASUREMENTS";
    const SPDM_VERSION: u8 = 0x12;
    const SPDM_CODE: u8 = 0xE0;

    fn write_body(&self, w: &mut Writer) -> Result<usize, WriteError> {
        w.put((&self.attributes).into())?;
        w.put((&self.index).try_into()?)?;
        if self.attributes.signature_requested {
            w.extend(&self.nonce.unwrap())?;
            w.put(self.slot_id)?;
        }
        Ok(w.offset())
    }
}

impl GetMeasurements {
    pub fn parse_body(buf: &[u8]) -> Result<GetMeasurements, ReadError> {
        let mut r = Reader::new(Self::NAME, buf);
        let attributes = RequestAttributes {
            signature_requested: r.get_bit()? == 1,
            raw_bit_stream_requested: r.get_bit()? == 1,
        };

        // Skip over next 6 reserved bits
        if r.get_bits(6)? != 0 {
            return Err(ReadError::new(
                Self::NAME,
                ReadErrorKind::InvalidBitsSet,
            ));
        }

        let index = r.get_byte()?.into();
        let mut nonce = None;
        let mut slot_id = 0;
        if attributes.signature_requested {
            nonce = Some([0u8; 32]);
            nonce.as_mut().unwrap().copy_from_slice(r.get_slice(32)?);
            slot_id = r.get_byte()?;
            if (slot_id as usize) >= config::NUM_SLOTS {
                return Err(ReadError::new(
                    Self::NAME,
                    ReadErrorKind::UnexpectedValue,
                ));
            }
        }

        Ok(GetMeasurements { attributes, index, nonce, slot_id })
    }
}

#[cfg(test)]
mod tests {

    use super::super::HEADER_SIZE;
    use super::*;

    #[test]
    fn get_measurements_roundtrip() {
        let mut buf = [0u8; 64];
        let mut msg = GetMeasurements::new(
            RequestAttributes {
                signature_requested: true,
                raw_bit_stream_requested: true,
            },
            MeasurementIndex::AllMeasurements,
            0,
        )
        .unwrap();

        assert_eq!(37, msg.write(&mut buf).unwrap());

        assert_eq!(
            msg,
            GetMeasurements::parse_body(&buf[HEADER_SIZE..]).unwrap(),
        );

        // When signature_requested = false, the nonce and slot id are not
        // serialized.
        msg.attributes.signature_requested = false;
        assert_eq!(4, msg.write(&mut buf).unwrap());

        // Clear out the nonce so the parsed message matches
        msg.nonce = None;

        assert_eq!(
            msg,
            GetMeasurements::parse_body(&buf[HEADER_SIZE..]).unwrap(),
        );
    }

    #[test]
    fn get_measurements_constructor_err() {
        // slot_id is outside valid range
        let slot_id = 9;
        assert!(GetMeasurements::new(
            RequestAttributes {
                signature_requested: false,
                raw_bit_stream_requested: false
            },
            MeasurementIndex::AllMeasurements,
            slot_id
        )
        .is_err())
    }

    #[test]
    fn get_measurements_write_err() {
        let mut buf = [0u8; 64];
        let mut msg = GetMeasurements::new(
            RequestAttributes {
                signature_requested: true,
                raw_bit_stream_requested: true,
            },
            // 0x5 is not a reserved bit
            MeasurementIndex::Reserved(0x5),
            0,
        )
        .unwrap();

        assert!(msg.write(&mut buf).is_err());

        // Invalid implementation defined value
        msg.index = MeasurementIndex::ImplementationDefined(0xFE);
        assert!(msg.write(&mut buf).is_err());

        // This is valid
        msg.index = MeasurementIndex::ImplementationDefined(0x4);
        assert!(msg.write(&mut buf).is_ok());
    }

    #[test]
    fn get_measurements_read_err() {
        let mut buf = [0u8; 64];
        let msg = GetMeasurements::new(
            RequestAttributes {
                signature_requested: true,
                raw_bit_stream_requested: true,
            },
            // 0x5 is not a reserved bit
            MeasurementIndex::DeviceMode,
            0,
        )
        .unwrap();

        assert_eq!(37, msg.write(&mut buf).unwrap());

        // This parses successfully
        assert_eq!(
            msg,
            GetMeasurements::parse_body(&buf[HEADER_SIZE..]).unwrap()
        );

        // Write an invalid attribute field to the serialized msg
        // Only 0x1, 0x2, and 0x3 are valid values (0th and 1st bit set)
        let saved = buf[2];
        buf[2] = 0xCE;
        assert!(GetMeasurements::parse_body(&buf[HEADER_SIZE..]).is_err());

        // Reset attributes to the correct values
        buf[2] = saved;

        // Corrupt the slot number
        buf[36] = config::NUM_SLOTS as u8;
        assert!(GetMeasurements::parse_body(&buf[HEADER_SIZE..]).is_err());
    }
}
