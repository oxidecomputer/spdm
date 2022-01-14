// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Common types used in other messages

use super::{
    ReadError, ReadErrorKind, Reader, WriteError, WriteErrorKind, Writer,
};
use crate::config;

use core::convert::{TryFrom, TryInto};
use heapless::Vec;
use rand::{rngs::OsRng, RngCore};

/// General opaque data format used in other messages.
///
/// Table 92 From section 14 in SPDM spec version 1.2.0
#[derive(Default, Debug, Clone, PartialEq)]
pub struct OpaqueData {
    elements: Vec<OpaqueElement, { config::MAX_OPAQUE_ELEMENTS }>,
}

impl OpaqueData {
    pub fn serialized_size(&self) -> usize {
        4 + self.elements.iter().fold(0, |acc, e| acc + e.serialized_size())
    }

    pub fn write(&self, w: &mut Writer) -> Result<(), WriteError> {
        w.put(self.elements.len() as u8)?;
        w.put_reserved(3)?;
        for element in &self.elements {
            element.write(w)?;
        }
        Ok(())
    }

    pub fn read(r: &mut Reader) -> Result<OpaqueData, ReadError> {
        let total_elements = r.get_byte()?;
        r.skip_reserved(3)?;
        let mut elements = Vec::new();
        for _ in 0..total_elements as usize {
            elements.push(OpaqueElement::read(r)?).map_err(|_| {
                ReadError::new("OpaqueData", ReadErrorKind::UnexpectedValue)
            })?;
        }
        Ok(OpaqueData { elements })
    }
}

/// An element in an OpaqueList
///
/// Table 93 in SPDM spec version 1.2.0
#[derive(Debug, Clone, PartialEq)]
pub struct OpaqueElement {
    registry_id: VendorRegistryId,
    vendor_id: VendorId,

    // Defined by the vendor or standards body
    data: Vec<u8, { config::MAX_OPAQUE_ELEMENT_DATA_SIZE }>,
}

impl OpaqueElement {
    pub fn serialized_size(&self) -> usize {
        let raw =
            4 + self.registry_id.vendor_id_len() as usize + self.data.len();
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

    pub fn write(&self, w: &mut Writer) -> Result<(), WriteError> {
        w.put(self.registry_id as u8)?;
        let vendor_len = self.vendor_id.write(w)? as usize;

        ensure_vendor_id_len_matches_registry_id(
            vendor_len as u8,
            self.registry_id,
        )
        .map_err(|_| {
            WriteError::new(
                "OpaqueElement",
                WriteErrorKind::UnexpectedValue("vendor_id"),
            )
        })?;

        w.put_u16(self.data.len() as u16)?;
        w.extend(&self.data)?;

        // Each element must be aligned on a 4 byte boundary
        let bytes_written = 4 + vendor_len + self.data.len();
        w.put_reserved(Self::padding(bytes_written) as u8)?;
        Ok(())
    }

    pub fn read(r: &mut Reader) -> Result<OpaqueElement, ReadError> {
        let registry_id = r.get_byte()?.try_into()?;
        let vendor_id_len = r.get_byte()?;
        ensure_vendor_id_len_matches_registry_id(vendor_id_len, registry_id)?;

        let vendor_id = VendorId::read(r, vendor_id_len)?;
        let data_len = r.get_u16()?;
        let data =
            Vec::from_slice(r.get_slice(data_len as usize)?).map_err(|_| {
                ReadError::new("OpaqueElement", ReadErrorKind::UnexpectedValue)
            })?;
        let bytes_read = 4 + vendor_id_len as usize + data.len();
        r.skip_reserved(Self::padding(bytes_read))?;
        Ok(OpaqueElement { registry_id, vendor_id, data })
    }
}

// Each registry id defines a specific vendor id len. Ensure they are the
// same.
fn ensure_vendor_id_len_matches_registry_id(
    vendor_id_len: u8,
    registry_id: VendorRegistryId,
) -> Result<(), ReadError> {
    if vendor_id_len == registry_id.vendor_id_len() {
        Ok(())
    } else {
        Err(ReadError::new("OpaqueElement", ReadErrorKind::UnexpectedValue))
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
    pub fn write(&self, w: &mut Writer) -> Result<u8, WriteError> {
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
    ) -> Result<VendorId, ReadError> {
        let id = match vendor_id_len {
            0 => VendorId::Empty,
            2 => VendorId::U16(r.get_u16()?),
            4 => VendorId::U32(r.get_u32()?),
            _ => {
                return Err(ReadError::new(
                    "ERROR",
                    ReadErrorKind::UnexpectedValue,
                ))
            }
        };
        Ok(id)
    }
}

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
    type Error = ReadError;
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
                return Err(ReadError::new(
                    "ERROR",
                    ReadErrorKind::UnexpectedValue,
                ));
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

pub type DigestBuf = Vec<u8, { config::MAX_DIGEST_SIZE }>;
pub type SignatureBuf = Vec<u8, { config::MAX_SIGNATURE_SIZE }>;

/// A unique random value used for cryptographic purposes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nonce([u8; 32]);

impl Nonce {
    pub fn new() -> Nonce {
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        Nonce(nonce)
    }

    pub fn read(r: &mut Reader) -> Result<Nonce, ReadError> {
        let mut nonce = [0u8; 32];
        nonce.as_mut().copy_from_slice(r.get_slice(32)?);
        Ok(Nonce(nonce))
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Nonce {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Nonce {
        pub fn new_with_magic(magic: u8) -> Nonce {
            Nonce([magic; 32])
        }
    }

    #[test]
    fn roundtrip_opaque_data() {
        let elements = Vec::from_slice(&[
            OpaqueElement {
                registry_id: VendorRegistryId::Dmtf,
                vendor_id: VendorId::Empty,
                data: Vec::from_slice(&[1]).unwrap(),
            },
            OpaqueElement {
                registry_id: VendorRegistryId::Tcg,
                vendor_id: VendorId::U16(0x2222),
                data: Vec::from_slice(&[4, 4, 4, 4]).unwrap(),
            },
        ])
        .unwrap();
        let data = OpaqueData { elements };

        let mut buf = [0u8; 1024];
        {
            let mut w = Writer::new("OpaqueData", &mut buf);
            data.write(&mut w).unwrap();
        }
        let mut r = Reader::new("OpaqueData", &mut buf);
        let data2 = OpaqueData::read(&mut r).unwrap();
        assert_eq!(data, data2);
    }

    #[test]
    fn mismatched_vendor_register_id_detected_during_write() {
        let element = OpaqueElement {
            registry_id: VendorRegistryId::Tcg,
            vendor_id: VendorId::Empty,
            data: Vec::from_slice(&[4, 4, 4, 4]).unwrap(),
        };

        let mut buf = [0u8; 1024];
        let mut w = Writer::new("OpaqueData", &mut buf);
        assert!(element.write(&mut w).is_err());
    }

    #[test]
    fn mismatched_vendor_register_id_detected_during_read() {
        let element = OpaqueElement {
            registry_id: VendorRegistryId::Tcg,
            vendor_id: VendorId::U16(0x1111),
            data: Vec::from_slice(&[4, 4, 4, 4]).unwrap(),
        };

        let mut buf = [0u8; 1024];
        {
            let mut w = Writer::new("OpaqueData", &mut buf);
            element.write(&mut w).unwrap();
        }

        // Modify vendor_len to mismatch registry id
        buf[1] = 4;

        let mut r = Reader::new("OpaqueData", &mut buf);
        assert!(OpaqueElement::read(&mut r).is_err());
    }
}
