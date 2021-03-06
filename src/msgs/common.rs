// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Common types used in other messages

use super::{BufferFullError, ReadError, Reader, Writer};
use crate::config;

use core::convert::{From, TryFrom, TryInto};

#[derive(Debug, PartialEq)]
pub enum ParseOpaqueDataError {
    Read(ReadError),
    ParseOpaqueElement(ParseOpaqueElementError),
}

impl From<ReadError> for ParseOpaqueDataError {
    fn from(e: ReadError) -> Self {
        ParseOpaqueDataError::Read(e)
    }
}

impl From<ParseOpaqueElementError> for ParseOpaqueDataError {
    fn from(e: ParseOpaqueElementError) -> Self {
        ParseOpaqueDataError::ParseOpaqueElement(e)
    }
}

/// General opaque data format used in other messages.
///
/// Table 92 From section 14 in SPDM spec version 1.2.0
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct OpaqueData {
    total_elements: u8,
    elements: [OpaqueElement; config::MAX_OPAQUE_ELEMENTS],
}

impl OpaqueData {
    pub fn serialized_size(&self) -> usize {
        4 + self.elements[..self.total_elements as usize]
            .iter()
            .fold(0, |acc, e| acc + e.serialized_size())
    }

    pub fn write(&self, w: &mut Writer) -> Result<(), WriteOpaqueElementError> {
        w.put(self.total_elements)?;
        w.put_reserved(3)?;
        for element in &self.elements[..self.total_elements as usize] {
            element.write(w)?;
        }
        Ok(())
    }

    pub fn read(r: &mut Reader) -> Result<OpaqueData, ParseOpaqueDataError> {
        let total_elements = r.get_byte()?;
        r.skip_reserved(3)?;
        let mut elements =
            [OpaqueElement::default(); config::MAX_OPAQUE_ELEMENTS];
        for i in 0..total_elements as usize {
            elements[i] = OpaqueElement::read(r)?;
        }
        Ok(OpaqueData { total_elements, elements })
    }
}

#[derive(Debug, PartialEq)]
pub enum WriteOpaqueElementError {
    BufferFull,

    // The vendor Id does not match the registry format
    InvalidVendorId,
}

impl From<BufferFullError> for WriteOpaqueElementError {
    fn from(_: BufferFullError) -> Self {
        WriteOpaqueElementError::BufferFull
    }
}

#[derive(Debug, PartialEq)]
pub enum ParseOpaqueElementError {
    Read(ReadError),

    // The vendor Id does not match the registry format
    InvalidVendorId,

    ParseVendorRegistryId,
    ParseVendorId(ParseVendorIdError),
}

impl From<ReadError> for ParseOpaqueElementError {
    fn from(e: ReadError) -> Self {
        ParseOpaqueElementError::Read(e)
    }
}

impl From<ParseVendorIdError> for ParseOpaqueElementError {
    fn from(e: ParseVendorIdError) -> Self {
        ParseOpaqueElementError::ParseVendorId(e)
    }
}

impl From<ParseVendorRegistryIdError> for ParseOpaqueElementError {
    fn from(_: ParseVendorRegistryIdError) -> Self {
        ParseOpaqueElementError::ParseVendorRegistryId
    }
}

/// An element in an OpaqueList
///
/// Table 93 in SPDM spec version 1.2.0
#[derive(Debug, Clone, Copy)]
pub struct OpaqueElement {
    registry_id: VendorRegistryId,
    vendor_id: VendorId,

    // Defined by the vendor or standards body
    data_len: u16,
    data: [u8; config::MAX_OPAQUE_ELEMENT_DATA_SIZE],
}

// We can't derive PartialEq because data may only be
// partially full.
impl PartialEq for OpaqueElement {
    fn eq(&self, other: &Self) -> bool {
        self.registry_id == other.registry_id
            && self.vendor_id == other.vendor_id
            && self.data_len == other.data_len
            && self.data[..self.data_len as usize]
                == other.data[..other.data_len as usize]
    }
}

impl Eq for OpaqueElement {}

impl Default for OpaqueElement {
    fn default() -> Self {
        OpaqueElement {
            registry_id: VendorRegistryId::Dmtf,
            vendor_id: VendorId::Empty,
            data_len: 0,
            data: [0u8; config::MAX_OPAQUE_ELEMENT_DATA_SIZE],
        }
    }
}

impl OpaqueElement {
    pub fn serialized_size(&self) -> usize {
        let raw = 4
            + self.registry_id.vendor_id_len() as usize
            + self.data_len as usize;
        raw + Self::padding(raw)
    }

    // Pad for 4 byte alignment
    fn padding(raw: usize) -> usize {
        let remainder = raw % 4;
        if remainder == 0 {
            0
        } else {
            4 - remainder
        }
    }

    pub fn write(&self, w: &mut Writer) -> Result<(), WriteOpaqueElementError> {
        w.put(self.registry_id as u8)?;
        let vendor_len = self.vendor_id.write(w)? as usize;

        ensure_vendor_id_len_matches_registry_id(
            vendor_len as u8,
            self.registry_id,
        )
        .map_err(|_| WriteOpaqueElementError::InvalidVendorId)?;

        w.put_u16(self.data_len)?;
        w.extend(&self.data[..self.data_len as usize])?;

        // Each element must be aligned on a 4 byte boundary
        let bytes_written = 4 + vendor_len + self.data_len as usize;
        w.put_reserved(Self::padding(bytes_written) as u8)?;
        Ok(())
    }

    pub fn read(
        r: &mut Reader,
    ) -> Result<OpaqueElement, ParseOpaqueElementError> {
        let registry_id = r.get_byte()?.try_into()?;
        let vendor_id_len = r.get_byte()?;
        ensure_vendor_id_len_matches_registry_id(vendor_id_len, registry_id)?;

        let vendor_id = VendorId::read(r, vendor_id_len)?;
        let data_len = r.get_u16()?;
        let mut data = [0u8; config::MAX_OPAQUE_ELEMENT_DATA_SIZE];
        r.get_slice(data_len as usize, &mut data)?;
        let bytes_read = 4 + vendor_id_len as usize + data_len as usize;
        r.skip_reserved(Self::padding(bytes_read))?;
        Ok(OpaqueElement { registry_id, vendor_id, data_len, data })
    }
}

// Each registry id defines a specific vendor id len. Ensure they are the
// same.
fn ensure_vendor_id_len_matches_registry_id(
    vendor_id_len: u8,
    registry_id: VendorRegistryId,
) -> Result<(), ParseOpaqueElementError> {
    if vendor_id_len == registry_id.vendor_id_len() {
        Ok(())
    } else {
        Err(ParseOpaqueElementError::InvalidVendorId)
    }
}

#[derive(Debug, PartialEq)]
pub enum ParseVendorIdError {
    Read(ReadError),

    // The encoded vendor id length is invalid
    InvalidLen,
}

impl From<ReadError> for ParseVendorIdError {
    fn from(e: ReadError) -> Self {
        ParseVendorIdError::Read(e)
    }
}

/// VendorIds have various sizes that correspond to `VendorRegistryId::len()`
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum VendorId {
    Empty,
    U16(u16),
    U32(u32),
}

impl VendorId {
    // Return the length of the vendor_id on success
    pub fn write(&self, w: &mut Writer) -> Result<u8, BufferFullError> {
        let vendor_len = match self {
            VendorId::Empty => {
                w.put(0)?;
                0
            }
            VendorId::U16(val) => {
                w.put(2)?;
                w.put_u16(*val)?;
                2
            }
            VendorId::U32(val) => {
                w.put(4)?;
                w.put_u32(*val)?;
                4
            }
        };
        Ok(vendor_len)
    }

    pub fn read(
        r: &mut Reader,
        vendor_id_len: u8,
    ) -> Result<VendorId, ParseVendorIdError> {
        let id = match vendor_id_len {
            0 => VendorId::Empty,
            2 => VendorId::U16(r.get_u16()?),
            4 => VendorId::U32(r.get_u32()?),
            _ => {
                return Err(ParseVendorIdError::InvalidLen);
            }
        };
        Ok(id)
    }
}

#[derive(Debug, PartialEq)]
pub struct ParseVendorRegistryIdError;

/// Table 50 from spec 1.2.0a
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VendorRegistryId {
    Dmtf = 0x0,
    Tcg = 0x1,
    Usb = 0x2,
    PciSig = 0x3,
    Iana = 0x4,
    HDBaseT = 0x5,
    Mipi = 0x6,
    Cxl = 0x7,
    Jedec = 0x8,
}

impl TryFrom<u8> for VendorRegistryId {
    type Error = ParseVendorRegistryIdError;
    fn try_from(val: u8) -> Result<Self, Self::Error> {
        let id = match val {
            0 => VendorRegistryId::Dmtf,
            1 => VendorRegistryId::Tcg,
            2 => VendorRegistryId::Usb,
            3 => VendorRegistryId::PciSig,
            4 => VendorRegistryId::Iana,
            5 => VendorRegistryId::HDBaseT,
            6 => VendorRegistryId::Mipi,
            7 => VendorRegistryId::Cxl,
            8 => VendorRegistryId::Jedec,
            _ => {
                return Err(ParseVendorRegistryIdError);
            }
        };
        Ok(id)
    }
}

impl VendorRegistryId {
    pub fn vendor_id_len(&self) -> u8 {
        match self {
            VendorRegistryId::Dmtf => 0,
            VendorRegistryId::Tcg => 2,
            VendorRegistryId::Usb => 2,
            VendorRegistryId::PciSig => 2,
            VendorRegistryId::Iana => 4,
            VendorRegistryId::HDBaseT => 4,
            VendorRegistryId::Mipi => 2,
            VendorRegistryId::Cxl => 2,
            VendorRegistryId::Jedec => 2,
        }
    }
}

#[derive(Debug)]
pub struct DigestTooLargeError;

/// A checked size type that we can safely trust downstream without asserts
/// Thanks for the idea Cliff!
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct DigestSize(usize);

impl From<DigestSize> for usize {
    fn from(size: DigestSize) -> Self {
        size.0
    }
}

impl TryFrom<usize> for DigestSize {
    type Error = DigestTooLargeError;
    fn try_from(x: usize) -> Result<Self, Self::Error> {
        if x <= config::MAX_DIGEST_SIZE {
            Ok(Self(x))
        } else {
            Err(DigestTooLargeError)
        }
    }
}

/// An buffer capable of storing digests of unknown size at compile time.
#[derive(Debug, Clone)]
pub struct DigestBuf {
    size: DigestSize,
    buf: [u8; config::MAX_DIGEST_SIZE],
}

impl DigestBuf {
    pub fn new(size: DigestSize) -> DigestBuf {
        DigestBuf { size, buf: [0; config::MAX_DIGEST_SIZE] }
    }

    pub fn read(
        size: DigestSize,
        r: &mut Reader,
    ) -> Result<DigestBuf, ReadError> {
        let mut digest = DigestBuf::new(size);
        r.get_slice(size.0, digest.as_mut())?;
        Ok(digest)
    }

    pub fn len(&self) -> usize {
        self.size.0
    }
}

impl AsRef<[u8]> for DigestBuf {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.size.0]
    }
}

impl AsMut<[u8]> for DigestBuf {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.size.0]
    }
}

impl TryFrom<&[u8]> for DigestBuf {
    type Error = DigestTooLargeError;
    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let size = DigestSize::try_from(buf.len())?;
        let mut digest = DigestBuf::new(size);
        digest.as_mut().copy_from_slice(buf);
        Ok(digest)
    }
}

// We can't derive PartialEq because buf may only be
// partially full.
impl PartialEq for DigestBuf {
    fn eq(&self, other: &Self) -> bool {
        self.size == other.size && self.as_ref() == other.as_ref()
    }
}

impl Eq for DigestBuf {}

#[derive(Debug)]
pub struct SignatureTooLargeError;

/// A checked size type that we can safely trust downstream without asserts
/// Thanks for the idea Cliff!
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct SignatureSize(usize);

impl From<SignatureSize> for usize {
    fn from(size: SignatureSize) -> Self {
        size.0
    }
}

impl TryFrom<usize> for SignatureSize {
    type Error = SignatureTooLargeError;
    fn try_from(x: usize) -> Result<Self, Self::Error> {
        if x <= config::MAX_SIGNATURE_SIZE {
            Ok(Self(x))
        } else {
            Err(SignatureTooLargeError)
        }
    }
}

/// A buffer capable of storing signatures of unknown size at compile time.
#[derive(Debug, Clone)]
pub struct SignatureBuf {
    size: SignatureSize,
    buf: [u8; config::MAX_SIGNATURE_SIZE],
}

impl SignatureBuf {
    pub fn new(size: SignatureSize) -> SignatureBuf {
        SignatureBuf { size, buf: [0; config::MAX_SIGNATURE_SIZE] }
    }

    pub fn read(
        size: SignatureSize,
        r: &mut Reader,
    ) -> Result<SignatureBuf, ReadError> {
        let mut sig = SignatureBuf::new(size);
        r.get_slice(size.0, sig.as_mut())?;
        Ok(sig)
    }

    pub fn len(&self) -> usize {
        self.size.0
    }
}

impl AsRef<[u8]> for SignatureBuf {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.size.0]
    }
}

impl AsMut<[u8]> for SignatureBuf {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.size.0]
    }
}

impl TryFrom<&[u8]> for SignatureBuf {
    type Error = SignatureTooLargeError;
    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let size = SignatureSize::try_from(buf.len())?;
        let mut digest = SignatureBuf::new(size);
        digest.as_mut().copy_from_slice(buf);
        Ok(digest)
    }
}

// We can't derive PartialEq because buf may only be
// partially full.
impl PartialEq for SignatureBuf {
    fn eq(&self, other: &Self) -> bool {
        self.size == other.size && self.as_ref() == other.as_ref()
    }
}

impl Eq for SignatureBuf {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `new_with_magic` methods are useful for manually parsing serialized
    /// buffers and are available for testing only.
    impl DigestBuf {
        pub fn new_with_magic(size: DigestSize, magic: u8) -> DigestBuf {
            DigestBuf { size, buf: [magic; config::MAX_DIGEST_SIZE] }
        }
    }

    impl SignatureBuf {
        pub fn new_with_magic(size: SignatureSize, magic: u8) -> SignatureBuf {
            SignatureBuf { size, buf: [magic; config::MAX_SIGNATURE_SIZE] }
        }
    }

    #[test]
    fn roundtrip_opaque_data() {
        let elements = [
            OpaqueElement {
                registry_id: VendorRegistryId::Dmtf,
                vendor_id: VendorId::Empty,
                data_len: 1,
                data: [1u8; config::MAX_OPAQUE_ELEMENT_DATA_SIZE],
            },
            OpaqueElement {
                registry_id: VendorRegistryId::Tcg,
                vendor_id: VendorId::U16(0x2222),
                data_len: 4,
                data: [4u8; config::MAX_OPAQUE_ELEMENT_DATA_SIZE],
            },
        ];
        let data = OpaqueData { total_elements: 2, elements };

        let mut buf = [0u8; 1024];
        {
            let mut w = Writer::new(&mut buf);
            data.write(&mut w).unwrap();
        }
        let mut r = Reader::new(&mut buf);
        let data2 = OpaqueData::read(&mut r).unwrap();
        assert_eq!(data, data2);
    }

    #[test]
    fn mismatched_vendor_register_id_detected_during_write() {
        let element = OpaqueElement {
            registry_id: VendorRegistryId::Tcg,
            vendor_id: VendorId::Empty,
            data_len: 4,
            data: [4u8; config::MAX_OPAQUE_ELEMENT_DATA_SIZE],
        };

        let mut buf = [0u8; 1024];
        let mut w = Writer::new(&mut buf);
        assert!(element.write(&mut w).is_err());
    }

    #[test]
    fn mismatched_vendor_register_id_detected_during_read() {
        let element = OpaqueElement {
            registry_id: VendorRegistryId::Tcg,
            vendor_id: VendorId::U16(0x1111),
            data_len: 4,
            data: [4u8; config::MAX_OPAQUE_ELEMENT_DATA_SIZE],
        };

        let mut buf = [0u8; 1024];
        {
            let mut w = Writer::new(&mut buf);
            element.write(&mut w).unwrap();
        }

        // Modify vendor_len to mismatch registry id
        buf[1] = 4;

        let mut r = Reader::new(&mut buf);
        assert!(OpaqueElement::read(&mut r).is_err());
    }
}
