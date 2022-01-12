// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Common types used in other messages

use super::{ReadError, ReadErrorKind, Reader, WriteError, Writer};
use crate::config;

use core::convert::{TryFrom, TryInto};

/// General opaque data format used in other messages.
///
/// Table 92 From section 14 in SPDM spec version 1.2.0
#[derive(Debug, Clone, PartialEq)]
pub struct OpaqueData {
    total_elements: u8,
    elements: [OpaqueElement; config::MAX_OPAQUE_ELEMENTS],
}

/// An element in an OpaqueList
///
/// Table 93 in SPDM spec version 1.2.0
#[derive(Debug, Clone, PartialEq)]
pub struct OpaqueElement {
    registry_id: VendorRegistryId,
    vendor_id: VendorId,

    // Defined by the vendor or standards body
    data_len: u16,
    data: [u8; config::MAX_OPAQUE_ELEMENT_DATA_SIZE],
}

impl OpaqueElement {
    pub fn write(&self, w: &mut Writer) -> Result<(), WriteError> {
        w.put(self.registry_id as u8)?;
        let vendor_len = self.vendor_id.write(w)? as usize;
        w.put_u16(self.data_len)?;
        w.extend(&self.data[..self.data_len as usize])?;

        // Each element must be aligned on a 4 byte boundary
        let bytes_written = 4 + vendor_len + self.data_len as usize;
        let padding = (bytes_written % 4) as u8;
        w.put_reserved(padding)?;
        Ok(())
    }

    pub fn read(r: &mut Reader) -> Result<OpaqueElement, ReadError> {
        let registry_id = r.get_byte()?.try_into()?;
        let vendor_id_len = r.get_byte()?;
        let vendor_id = VendorId::read(r, vendor_id_len)?;
        let data_len = r.get_u16()?;
        let mut data = [0u8; config::MAX_OPAQUE_ELEMENT_DATA_SIZE];
        data[..data_len as usize]
            .copy_from_slice(r.get_slice(data_len as usize)?);
        let padding = (4 + vendor_id_len as usize + data_len as usize) % 4;
        r.skip_reserved(padding as u8)?;
        Ok(OpaqueElement { registry_id, vendor_id, data_len, data })
    }
}

/// VendorIds have various sizes that correspond to `VendorRegistryId::len()`
#[derive(Debug, Clone, PartialEq)]
pub enum VendorId {
    Empty,
    U16(u16),
    U32(u32),
}

// TODO: Should we validate that the length of a vendor id corresponds
// to the registry id?
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
    pub fn id_len(&self) -> u8 {
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
