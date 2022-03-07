// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::algorithms::MeasurementSpec;
use super::common::{
    DigestBuf, OpaqueData, SignatureBuf, WriteOpaqueElementError,
};
use super::encoding::{BufferFullError, ReadError, Reader, Writer};
use super::Msg;
use crate::config;
use crate::crypto::Nonce;

use bitflags::bitflags;
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

    // 0xFD
    MeasurementManifest,

    // 0xFE
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

#[derive(Debug)]
pub enum WriteMeasurementIndexError {
    InvalidImplementationDefinedIndex,
    InvalidReservedIndex,
}

impl TryFrom<&MeasurementIndex> for u8 {
    type Error = WriteMeasurementIndexError;
    fn try_from(val: &MeasurementIndex) -> Result<Self, Self::Error> {
        let index = match val {
            MeasurementIndex::TotalNumberOfMeasurementsAvailable => 0,
            MeasurementIndex::AllMeasurements => 0xFF,
            MeasurementIndex::ImplementationDefined(index) => {
                if *index < 0x1 || *index > 0xEF {
                    return Err(WriteMeasurementIndexError::InvalidImplementationDefinedIndex);
                }
                *index
            }
            MeasurementIndex::Reserved(index) => {
                if *index < 0xF0 || *index > 0xFC {
                    return Err(
                        WriteMeasurementIndexError::InvalidReservedIndex,
                    );
                }
                *index
            }
            MeasurementIndex::MeasurementManifest => 0xFD,
            MeasurementIndex::DeviceMode => 0xFE,
        };
        Ok(index)
    }
}

#[derive(Debug)]
pub enum WriteGetMeasurementsError {
    BufferFull,
    MeasurementIndex(WriteMeasurementIndexError),
    CryptoDisabled,
}

impl From<BufferFullError> for WriteGetMeasurementsError {
    fn from(_: BufferFullError) -> Self {
        WriteGetMeasurementsError::BufferFull
    }
}

impl From<WriteMeasurementIndexError> for WriteGetMeasurementsError {
    fn from(e: WriteMeasurementIndexError) -> Self {
        WriteGetMeasurementsError::MeasurementIndex(e)
    }
}

#[derive(Debug)]
pub enum ParseGetMeasurementsError {
    ReservedBitsNotZero,
    MaxSlotNumberExceeded,
    Read(ReadError),
}

impl From<ReadError> for ParseGetMeasurementsError {
    fn from(e: ReadError) -> Self {
        ParseGetMeasurementsError::Read(e)
    }
}

/// Request measurements from a responder.
#[derive(Debug, Clone, PartialEq)]
pub struct GetMeasurements {
    // Param1
    attributes: RequestAttributes,

    // Param2
    index: MeasurementIndex,

    // Only valid if signature_requested attribute is set
    nonce: Option<Nonce>,

    // Slot number of the responder certificate chain used for measurement auth
    // Only present on the wire if signature_requested attribute is set.
    slot_id: u8,
}

impl GetMeasurements {
    pub fn new(
        attributes: RequestAttributes,
        index: MeasurementIndex,
        slot_id: u8,
    ) -> GetMeasurements {
        assert!((slot_id as usize) < config::NUM_SLOTS);
        let mut nonce = None;
        if attributes.signature_requested {
            nonce = Some(Nonce::new());
        }
        GetMeasurements { attributes, index, slot_id, nonce }
    }
}

impl Msg for GetMeasurements {
    const NAME: &'static str = "GET_MEASUREMENTS";
    const SPDM_VERSION: u8 = 0x12;
    const SPDM_CODE: u8 = 0xE0;

    type WriteError = WriteGetMeasurementsError;

    fn write_body(
        &self,
        w: &mut Writer,
    ) -> Result<usize, WriteGetMeasurementsError> {
        w.put((&self.attributes).into())?;
        w.put((&self.index).try_into()?)?;

        // TODO: Ensure measurement capability for signatures is available and
        // return error if not.
        if self.attributes.signature_requested {
            w.extend(&self.nonce.as_ref().unwrap().as_ref())?;
            w.put(self.slot_id)?;
        }
        Ok(w.offset())
    }
}

impl GetMeasurements {
    pub fn parse_body(
        buf: &[u8],
    ) -> Result<GetMeasurements, ParseGetMeasurementsError> {
        let mut r = Reader::new(buf);
        let attributes = RequestAttributes {
            signature_requested: r.get_bit()? == 1,
            raw_bit_stream_requested: r.get_bit()? == 1,
        };

        // Skip over next 6 reserved bits
        if r.get_bits(6)? != 0 {
            return Err(ParseGetMeasurementsError::ReservedBitsNotZero);
        }

        let index = r.get_byte()?.into();
        let mut nonce = None;
        let mut slot_id = 0;

        // TODO: Ensure measurement capability for signatures is available and
        // return error if not.
        if attributes.signature_requested {
            nonce = Some(Nonce::read(&mut r)?);
            slot_id = r.get_byte()?;
            if (slot_id as usize) >= config::NUM_SLOTS {
                return Err(ParseGetMeasurementsError::MaxSlotNumberExceeded);
            }
        }

        Ok(GetMeasurements { attributes, index, nonce, slot_id })
    }
}

/// Bits 5:4 of Param2 in MEASUREMENTS message
#[derive(Debug, Clone, PartialEq)]
pub enum ContentChanged {
    // 0b00
    NotSupported,
    // 0b01
    True,
    // 0b10
    False,
}

// Bit 7 of byte 0 (DMTFSpecMeasurementValueType) in Table 45 of DMTF 1.2.0 spec
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DmtfMeasurementValueRepresentation {
    Digest = 0x00,
    RawBitStream = 0x80,
}

// Bits 6:0 of byte 0 (DMTFSpecMeasurementValueType) in Table 45 of DMTF 1.2.0
// spec
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DmtfMeasurementValueType {
    ImmutableRom = 0x00,
    MutableFirmware = 0x01,
    HardwareConfig = 0x02,
    FirmwareConfig = 0x03,
    MeasurementManifest = 0x04,
    DeviceMode = 0x05,
    MutableFirmwareVersion = 0x06,
    MutableFirmwareSecurityVersion = 0x07,
}

// TODO: Add to config
const MAX_MEASUREMENT_SIZE: usize = 16;

/// A raw measurement
#[derive(Debug, Clone)]
pub struct BitStream {
    len: usize,
    buf: [u8; MAX_MEASUREMENT_SIZE],
}

impl BitStream {
    pub fn new(data: &[u8]) -> BitStream {
        let mut buf = [0u8; MAX_MEASUREMENT_SIZE];
        buf[..data.len()].copy_from_slice(data);
        BitStream { len: data.len(), buf }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

impl PartialEq for BitStream {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.as_slice() == other.as_slice()
    }
}

impl Eq for BitStream {}

// Bytes 3+ (DMTFSpecMeasurementValue) in Table 45 of DMTF 1.2.0 spec
#[derive(Debug, Clone, PartialEq)]
pub enum DmtfMeasurementValue {
    Digest(DigestBuf),
    BitStream(BitStream),
}

impl DmtfMeasurementValue {
    pub fn len(&self) -> usize {
        match self {
            DmtfMeasurementValue::Digest(buf) => buf.len(),
            DmtfMeasurementValue::BitStream(s) => s.len(),
        }
    }

    pub fn write(&self, w: &mut Writer) -> Result<usize, BufferFullError> {
        match self {
            DmtfMeasurementValue::Digest(buf) => w.extend(buf.as_ref()),
            DmtfMeasurementValue::BitStream(s) => w.extend(s.as_slice()),
        }
    }
}

bitflags! {
    /// Fields 0 and 1 of DeviceMode
    #[derive(Default)]
    pub struct OperationalModeBits : u32 {
        const MANUFACTURING = 0x1;
        const VALIDATION = 0x2;
        const NORMAL = 0x4;
        const RECOVERY = 0x8;
        const RMA = 0x10;
        const DECOMMISSIONED = 0x20;
    }
}

bitflags! {
    /// Fields 2 and 3 of DeviceMode
    #[derive(Default)]
    pub struct DeviceModeBits : u32 {
        const NON_INVASIVE_DEBUG = 0x1;
        const INVASIVE_DEBUG = 0x2;
        const NON_INVASIVE_DEBUG_RESET_CYCLE = 0x4;
        const INVASIVE_DEBUG_RESET_CYCLE = 0x8;
        const INVASIVE_DEBUG_AT_LEAST_ONCE_AFTER_MANUFACTURING_MODE = 0x20;
    }

}

// Used when DmtfMeasurementValueType::DeviceMode is set
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceMode {
    pub operational_mode_capabilities: OperationalModeBits,
    pub operational_mode_state: OperationalModeBits,
    pub device_mode_capabilities: DeviceModeBits,
    pub device_mode_state: DeviceModeBits,
}

/// Table 45 of DMTF 1.2.0 spec
#[derive(Debug, Clone, PartialEq)]
pub struct DmtfMeasurement {
    pub value_representation: DmtfMeasurementValueRepresentation,
    pub value_type: DmtfMeasurementValueType,
    pub value: DmtfMeasurementValue,
}

impl DmtfMeasurement {
    fn serialized_size(&self) -> usize {
        3 + self.value.len()
    }

    fn write(&self, w: &mut Writer) -> Result<usize, BufferFullError> {
        // Set bit 7 of byte 0
        let mut byte0 = self.value_representation as u8;

        // Set bits [6:0] of byte 0
        byte0 |= self.value_type as u8;

        w.put(byte0)?;
        w.put_u16(self.value.len().try_into().unwrap())?;
        self.value.write(w)
    }
}

/// Table 44 of DMTF 1.2.0 spec
#[derive(Debug, Clone, PartialEq)]
pub struct MeasurementBlock {
    pub index: u8,
    pub measurement_spec_selected: MeasurementSpec,
    pub measurement: DmtfMeasurement,
}

impl MeasurementBlock {
    fn serialized_size(&self) -> usize {
        4 + self.measurement.serialized_size()
    }

    fn write(&self, w: &mut Writer) -> Result<usize, BufferFullError> {
        w.put(self.index)?;
        w.put(self.measurement_spec_selected.bits())?;
        w.put_u16(self.measurement.serialized_size().try_into().unwrap())?;
        self.measurement.write(w)
    }
}

#[derive(Debug)]
pub enum WriteMeasurementsError {
    BufferFull,
    WriteOpaqueElement(WriteOpaqueElementError),
}

impl From<BufferFullError> for WriteMeasurementsError {
    fn from(_: BufferFullError) -> Self {
        WriteMeasurementsError::BufferFull
    }
}

impl From<WriteOpaqueElementError> for WriteMeasurementsError {
    fn from(e: WriteOpaqueElementError) -> Self {
        WriteMeasurementsError::WriteOpaqueElement(e)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MeasurementBlocks {
    pub len: usize,
    pub blocks: [Option<MeasurementBlock>; config::MAX_MEASUREMENT_BLOCKS],
}

impl Default for MeasurementBlocks {
    fn default() -> Self {
        const BLOCK: Option<MeasurementBlock> = None;
        MeasurementBlocks {
            len: 0,
            blocks: [BLOCK; config::MAX_MEASUREMENT_BLOCKS],
        }
    }
}

impl MeasurementBlocks {
    // All options returned are `Some` variants.
    //
    // TODO: Use MaybeUninit and return a `&[MeasurementBlock]`?
    pub fn as_slice(&self) -> &[Option<MeasurementBlock>] {
        &self.blocks[..self.len]
    }

    fn serialized_size(&self) -> usize {
        self.as_slice()
            .iter()
            .fold(0, |acc, b| acc + b.as_ref().unwrap().serialized_size())
    }

    // Write out bytes 4 - 8+L in `Measurements` message
    fn write(&self, w: &mut Writer) -> Result<usize, BufferFullError> {
        w.put(self.len.try_into().unwrap())?;
        w.put_u24(self.serialized_size())?;
        for i in 0..self.len {
            self.blocks[i].as_ref().unwrap().write(w)?;
        }
        Ok(w.offset())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Measurements {
    // Param1
    pub total_blocks: u8,

    // Param2
    pub content_changed: ContentChanged,

    // slot_id of cert chain specified in GET_MEASUREMENTS request
    // Only used for signature generation.
    // Set to 0 if no signature in this message
    //
    // Bits 3:0 of Param2
    pub slot_id: u8,

    pub blocks: MeasurementBlocks,
    pub nonce: Nonce,
    pub opaque_data: OpaqueData,
    pub signature: Option<SignatureBuf>,
}

impl Measurements {
    /// Return a Measurements message filled in with the total number of
    ///  measurement blocks available.
    ///
    /// The value created by this function is returned when `Param2` of
    /// `GetMeasurements` is set to `0x0`.
    pub fn new_with_num_measurements(
        total_blocks: u8,
        content_changed: ContentChanged,
        slot_id: u8,
        nonce: Nonce,
        opaque_data: OpaqueData,
        signature: Option<SignatureBuf>,
    ) -> Measurements {
        Measurements {
            total_blocks,
            content_changed,
            slot_id,
            blocks: MeasurementBlocks::default(),
            nonce,
            opaque_data,
            signature,
        }
    }

    /// Return a measurements message with all measurements filled in or a
    /// single measurement block, depending upon the `GetMeasurements` request.
    pub fn new_with_measurements(
        content_changed: ContentChanged,
        slot_id: u8,
        blocks: MeasurementBlocks,
        nonce: Nonce,
        opaque_data: OpaqueData,
        signature: Option<SignatureBuf>,
    ) -> Measurements {
        Measurements {
            total_blocks: 0,
            content_changed,
            slot_id,
            blocks,
            nonce,
            opaque_data,
            signature,
        }
    }

    fn write_param2(
        &self,
        w: &mut Writer,
    ) -> Result<usize, WriteMeasurementsError> {
        let mut param2 = 0u8;
        match self.content_changed {
            ContentChanged::True => param2 |= 1 << 4,
            ContentChanged::False => param2 |= 1 << 5,
            _ => (),
        }
        if self.signature.is_some() {
            param2 |= self.slot_id;
        }
        w.put(param2)?;
        Ok(w.offset())
    }
}

impl Msg for Measurements {
    const NAME: &'static str = "MEASUREMENTS";
    const SPDM_VERSION: u8 = 0x12;
    const SPDM_CODE: u8 = 0x60;

    type WriteError = WriteMeasurementsError;

    fn write_body(
        &self,
        w: &mut Writer,
    ) -> Result<usize, WriteMeasurementsError> {
        w.put(self.total_blocks)?;
        self.write_param2(w)?;

        // Write out `NumberOfBlocks`, `MeasurementRecordLength`, and
        // `MeasurementRecordData`
        self.blocks.write(w)?;

        w.extend(self.nonce.as_ref())?;
        w.put_u16(self.opaque_data.serialized_size().try_into().unwrap())?;
        self.opaque_data.write(w)?;
        if self.signature.is_some() {
            w.extend(&self.signature.as_ref().unwrap().as_ref())?;
        }
        Ok(w.offset())
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
        );

        // We only support signatures/nonces when rand is enabled
        if cfg!(feature = "rand") {
            assert_eq!(37, msg.write(&mut buf).unwrap());
            assert_eq!(
                msg,
                GetMeasurements::parse_body(&buf[HEADER_SIZE..]).unwrap(),
            );
        }

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
        );

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
        // Don't worry about crypto being enabled by setting
        // `signature_requested = false`
        let msg = GetMeasurements::new(
            RequestAttributes {
                signature_requested: true,
                raw_bit_stream_requested: true,
            },
            // 0x5 is not a reserved bit
            MeasurementIndex::DeviceMode,
            0,
        );

        msg.write(&mut buf).unwrap();

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

        // This is only valid if we have a nonce
        if cfg!(feature = "rand") {
            // Corrupt the slot number
            buf[36] = config::NUM_SLOTS as u8;
            assert!(GetMeasurements::parse_body(&buf[HEADER_SIZE..]).is_err());
        }
    }
}
