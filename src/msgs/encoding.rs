// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use core::convert::TryInto;

#[derive(Debug, PartialEq, Eq)]
pub struct BufferFullError;

/// The mechanism used for serializing SPDM messages
pub struct Writer<'a> {
    buf: &'a mut [u8],
    offset: usize,
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Writer<'a> {
        Writer { buf, offset: 0 }
    }

    /// Append a byte onto the buffer.
    ///
    /// Return the amount of the buffer used or an error if the buffer is full.
    pub fn put(&mut self, value: u8) -> Result<usize, BufferFullError> {
        if self.is_full() {
            Err(BufferFullError)
        } else {
            self.buf[self.offset] = value;
            self.offset += 1;
            Ok(self.offset)
        }
    }

    /// Append `num_bytes` 0 bytes onto the buffer.
    ///
    /// This is a first class method because the protocol has so many
    /// reserved bytes.
    pub fn put_reserved(
        &mut self,
        num_bytes: u8,
    ) -> Result<usize, BufferFullError> {
        for _ in 0..num_bytes {
            self.put(0)?;
        }
        Ok(self.offset)
    }

    // Write a u16 in little endian byte order
    pub fn put_u16(&mut self, num: u16) -> Result<usize, BufferFullError> {
        let buf = num.to_le_bytes();
        for i in 0..2 {
            self.put(buf[i])?;
        }
        Ok(self.offset)
    }

    // Write a u32 in little-endian byte order
    pub fn put_u32(&mut self, num: u32) -> Result<usize, BufferFullError> {
        let buf = num.to_le_bytes();
        for i in 0..4 {
            self.put(buf[i])?;
        }
        Ok(self.offset)
    }

    // Append a slice onto the buffer
    pub fn extend(&mut self, buf: &[u8]) -> Result<usize, BufferFullError> {
        if buf.len() > self.remaining() {
            Err(BufferFullError)
        } else {
            let end = self.offset + buf.len();
            self.buf[self.offset..end].copy_from_slice(buf);
            self.offset = end;
            Ok(self.offset)
        }
    }

    /// Return true if the buffer is full, false otherwise.
    pub fn is_full(&self) -> bool {
        self.offset == self.buf.len()
    }

    /// Number of bytes remaining in buffer.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.offset
    }

    /// Return the current byte offset into the buffer.
    pub fn offset(&self) -> usize {
        self.offset
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReadError {
    /// There is no more data left in the read buffer
    BufferEmpty,

    /// Reserved bytes in messages must always be 0
    ReservedByteNotZero,

    /// An attempt to read one or more bytes not on a byte boundary
    Unaligned,

    /// An attempt to read more than 7 bits in get_bits
    TooManyBits,

    /// An attempt to convert a type via core::convert::TryInto failed. This
    /// should *never* happen.
    TypeConversionFailed,
}

/// The mechanism used  for deserializing SPDM messages
pub struct Reader<'a> {
    buf: &'a [u8],
    byte_offset: usize,
    bit_offset: u8,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, byte_offset: 0, bit_offset: 0 }
    }

    /// Return the next byte in the buffer and advance the cursor.
    pub fn get_byte(&mut self) -> Result<u8, ReadError> {
        if !self.is_aligned() {
            return Err(ReadError::Unaligned);
        }
        if self.is_empty() {
            return Err(ReadError::BufferEmpty);
        }
        let b = self.buf[self.byte_offset];
        self.byte_offset += 1;
        Ok(b)
    }

    /// Skip over the next `num_bytes` in the buffer.
    ///
    /// Ensure that these bytes are set to 0.
    pub fn skip_reserved(&mut self, num_bytes: usize) -> Result<(), ReadError> {
        for _ in 0..num_bytes {
            let byte = self.get_byte()?;
            if byte != 0 {
                return Err(ReadError::ReservedByteNotZero);
            }
        }
        Ok(())
    }

    /// Skip over the next `num_bytes` in the buffer without checking their
    /// value.
    pub fn skip_ignored(&mut self, num_bytes: usize) -> Result<(), ReadError> {
        for _ in 0..num_bytes {
            self.get_byte()?;
        }
        Ok(())
    }

    // Read least significant bits in order.
    //
    // Allow reading up to 7 bits at a time.
    // The read does not have to be aligned.
    pub fn get_bits(&mut self, count: u8) -> Result<u8, ReadError> {
        if self.is_empty() {
            return Err(ReadError::BufferEmpty);
        }
        if count > 7 {
            return Err(ReadError::TooManyBits);
        }
        let mut new_bit_offset = self.bit_offset + count;
        if new_bit_offset >= 8 {
            let new_byte_offset = self.byte_offset + 1;
            new_bit_offset = new_bit_offset - 8;
            if new_byte_offset == self.buf.len() && new_bit_offset != 0 {
                Err(ReadError::BufferEmpty)
            } else {
                // Bits from first byte become low order bits in returned byte
                let mut b = self.buf[self.byte_offset] >> self.bit_offset;

                if new_bit_offset != 0 {
                    // Bits from second byte become high order bits in returned byte
                    let low_bit = 8 - self.bit_offset;
                    let trailing_zeros = 8 - new_bit_offset;
                    let right_shift = trailing_zeros - low_bit;
                    b |= (self.buf[new_byte_offset] << trailing_zeros)
                        >> right_shift
                }
                self.byte_offset = new_byte_offset;
                self.bit_offset = new_bit_offset;
                Ok(b)
            }
        } else {
            let high = self.bit_offset + count;
            let low = self.bit_offset;
            let b = (self.buf[self.byte_offset] << (8 - high))
                >> (8 - (high - low));
            self.bit_offset = high;
            Ok(b)
        }
    }

    /// Get the next bit in the buffer.
    pub fn get_bit(&mut self) -> Result<u8, ReadError> {
        self.get_bits(1)
    }

    /// Read a u16 in little endian byte order
    ///
    /// This only works on aligned reads.
    pub fn get_u16(&mut self) -> Result<u16, ReadError> {
        if !self.is_aligned() {
            return Err(ReadError::Unaligned);
        }
        if self.remaining() < 2 {
            return Err(ReadError::BufferEmpty);
        }
        let pos = self.byte_offset;
        let buf: &[u8; 2] = &self.buf[pos..pos + 2]
            .try_into()
            .map_err(|_| ReadError::TypeConversionFailed)?;
        self.byte_offset += 2;
        Ok(u16::from_le_bytes(*buf))
    }

    /// Copy a slice of `size` into `buf` and advance the cursor.
    ///
    /// `buf` must be at least `size` bytes long
    ///
    /// This only works for aligned reads.
    pub fn get_slice(
        &mut self,
        size: usize,
        buf: &mut [u8],
    ) -> Result<(), ReadError> {
        if !self.is_aligned() {
            return Err(ReadError::Unaligned);
        }

        if self.remaining() < size {
            return Err(ReadError::BufferEmpty);
        }

        let start = self.byte_offset;
        self.byte_offset += size;
        buf[..size].copy_from_slice(&self.buf[start..self.byte_offset]);
        Ok(())
    }

    /// Read a u32 in little endian byte order
    ///
    /// This only works on aligned reads.
    pub fn get_u32(&mut self) -> Result<u32, ReadError> {
        if !self.is_aligned() {
            return Err(ReadError::Unaligned);
        }
        if self.remaining() < 4 {
            return Err(ReadError::BufferEmpty);
        }
        let pos = self.byte_offset;
        let buf: &[u8; 4] = &self.buf[pos..pos + 4]
            .try_into()
            .map_err(|_| ReadError::TypeConversionFailed)?;
        self.byte_offset += 4;
        Ok(u32::from_le_bytes(*buf))
    }

    /// Get the current cursor position of the buffer being read
    pub fn byte_offset(&self) -> usize {
        self.byte_offset
    }

    /// Return the number of bytes left in the buffer
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.byte_offset
    }

    /// Return true if there are no bytes left ro read in the buffer.
    pub fn is_empty(&self) -> bool {
        self.buf.len() == self.byte_offset
    }

    /// Return true if reads are currently on a byte boundary
    pub fn is_aligned(&self) -> bool {
        self.bit_offset == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_by_4_bits() {
        let buf = [0xF0, 0xF0];
        let mut reader = Reader::new(&buf);
        assert_eq!(0x00, reader.get_bits(4).unwrap());
        assert!(!reader.is_aligned());
        assert!(!reader.is_empty());

        assert_eq!(0x0F, reader.get_bits(4).unwrap());
        assert!(reader.is_aligned());
        assert!(!reader.is_empty());

        assert_eq!(0x00, reader.get_bits(4).unwrap());
        assert!(!reader.is_aligned());
        assert!(!reader.is_empty());

        assert_eq!(0x0F, reader.get_bits(4).unwrap());
        assert!(reader.is_aligned());
        assert!(reader.is_empty());
    }

    #[test]
    fn read_by_3_bits() {
        let buf = [0xF0, 0xF0];
        let mut reader = Reader::new(&buf);

        // 0b000
        assert_eq!(0x00, reader.get_bits(3).unwrap());
        assert!(!reader.is_aligned());
        assert!(!reader.is_empty());

        // 0b110
        assert_eq!(0x06, reader.get_bits(3).unwrap());
        assert!(!reader.is_aligned());
        assert!(!reader.is_empty());

        // Cross byte boundary
        // 0b011
        assert_eq!(0x03, reader.get_bits(3).unwrap());
        assert!(!reader.is_aligned());
        assert!(!reader.is_empty());

        // 0b000
        assert_eq!(0x00, reader.get_bits(3).unwrap());
        assert!(!reader.is_aligned());
        assert!(!reader.is_empty());

        // 0b111
        assert_eq!(0x07, reader.get_bits(3).unwrap());
        assert!(!reader.is_aligned());
        assert!(!reader.is_empty());

        assert!(reader.get_bits(3).is_err());
        assert_eq!(1, reader.byte_offset);
        assert_eq!(7, reader.bit_offset);
    }

    #[test]
    fn read_by_gt_8_bits_fails() {
        let buf = [0xF0, 0xF0];
        let mut reader = Reader::new(&buf);
        assert!(reader.get_bits(8).is_err());
        assert!(reader.get_bits(9).is_err());
        assert!(reader.get_bits(10).is_err());
    }

    #[test]
    fn get_bit_by_bit() {
        let buf = [0xF0, 0xF0];
        let mut reader = Reader::new(&buf);
        for i in 0..4 {
            if i % 2 == 0 {
                assert!(reader.is_aligned());
            }
            for _ in 0..4 {
                if i % 2 == 0 {
                    assert_eq!(0x00, reader.get_bit().unwrap());
                } else {
                    assert_eq!(0x01, reader.get_bit().unwrap());
                }
            }
        }
        assert!(reader.is_empty());
        assert!(reader.get_bit().is_err());
    }
}
