#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteError {
    msg: &'static str,
    buf_size: usize,
}

impl WriteError {
    pub fn new(msg: &'static str, buf_size: usize) -> WriteError {
        WriteError { msg, buf_size }
    }
}

pub struct Writer<'a> {
    msg: &'static str,
    buf: &'a mut [u8],
    offset: usize,
}

impl<'a> Writer<'a> {
    pub fn new(msg: &'static str, buf: &'a mut [u8]) -> Writer<'a> {
        Writer { msg, buf, offset: 0 }
    }

    /// Append a byte onto the buffer.
    ///
    /// Return the amount of the buffer used or an error if the buffer is full.
    pub fn push(&mut self, value: u8) -> Result<usize, WriteError> {
        if self.full() {
            Err(WriteError::new(self.msg, self.buf.len()))
        } else {
            self.buf[self.offset] = value;
            self.offset += 1;
            Ok(self.offset)
        }
    }

    pub fn full(&self) -> bool {
        self.offset == self.buf.len()
    }

    pub fn offset(&self) -> usize {
        self.offset
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadErrorKind {
    Header,
    Empty,
    ReservedByteNotZero,

    // An attempt to read one or more bytes not on a byte boundary
    Unaligned,

    // An attempt to read more than 7 bits in read_bits
    TooManyBits,
    TooManyEntries,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadError {
    msg: &'static str,
    kind: ReadErrorKind,
}

impl ReadError {
    pub fn new(msg: &'static str, kind: ReadErrorKind) -> ReadError {
        ReadError { msg, kind }
    }
}

pub struct Reader<'a> {
    msg: &'static str,
    buf: &'a [u8],
    byte_offset: usize,
    bit_offset: u8,
}

impl<'a> Reader<'a> {
    pub fn new(msg: &'static str, buf: &'a [u8]) -> Reader<'a> {
        Reader { msg, buf, byte_offset: 0, bit_offset: 0 }
    }

    pub fn read_byte(&mut self) -> Result<u8, ReadError> {
        if !self.aligned() {
            return Err(ReadError::new(self.msg, ReadErrorKind::Unaligned));
        }
        if self.empty() {
            return Err(ReadError::new(self.msg, ReadErrorKind::Empty));
        }
        let b = self.buf[self.byte_offset];
        self.byte_offset += 1;
        Ok(b)
    }

    // Read least significant bits in order.
    //
    // Allow reading up to 7 bits at a time.
    // The read does not have to be aligned.
    pub fn read_bits(&mut self, count: u8) -> Result<u8, ReadError> {
        if self.empty() {
            return Err(ReadError::new(self.msg, ReadErrorKind::Empty));
        }
        if count > 7 {
            return Err(ReadError::new(self.msg, ReadErrorKind::TooManyBits));
        }
        let mut new_bit_offset = self.bit_offset + count;
        if new_bit_offset >= 8 {
            let new_byte_offset = self.byte_offset + 1;
            new_bit_offset = new_bit_offset - 8;
            if new_byte_offset == self.buf.len() && new_bit_offset != 0 {
                Err(ReadError::new(self.msg, ReadErrorKind::Empty))
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

    pub fn read_bit(&mut self) -> Result<u8, ReadError> {
        self.read_bits(1)
    }

    pub fn empty(&self) -> bool {
        self.buf.len() == self.byte_offset
    }

    pub fn aligned(&self) -> bool {
        self.bit_offset == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_by_4_bits() {
        let buf = [0xF0, 0xF0];
        let mut reader = Reader::new("TEST_MSG", &buf);
        assert_eq!(0x00, reader.read_bits(4).unwrap());
        assert!(!reader.aligned());
        assert!(!reader.empty());

        assert_eq!(0x0F, reader.read_bits(4).unwrap());
        assert!(reader.aligned());
        assert!(!reader.empty());

        assert_eq!(0x00, reader.read_bits(4).unwrap());
        assert!(!reader.aligned());
        assert!(!reader.empty());

        assert_eq!(0x0F, reader.read_bits(4).unwrap());
        assert!(reader.aligned());
        assert!(reader.empty());
    }

    #[test]
    fn read_by_3_bits() {
        let buf = [0xF0, 0xF0];
        let mut reader = Reader::new("TEST_MSG", &buf);

        // 0b000
        assert_eq!(0x00, reader.read_bits(3).unwrap());
        assert!(!reader.aligned());
        assert!(!reader.empty());

        // 0b110
        assert_eq!(0x06, reader.read_bits(3).unwrap());
        assert!(!reader.aligned());
        assert!(!reader.empty());

        // Cross byte boundary
        // 0b011
        assert_eq!(0x03, reader.read_bits(3).unwrap());
        assert!(!reader.aligned());
        assert!(!reader.empty());

        // 0b000
        assert_eq!(0x00, reader.read_bits(3).unwrap());
        assert!(!reader.aligned());
        assert!(!reader.empty());

        // 0b111
        assert_eq!(0x07, reader.read_bits(3).unwrap());
        assert!(!reader.aligned());
        assert!(!reader.empty());

        assert!(reader.read_bits(3).is_err());
        assert_eq!(1, reader.byte_offset);
        assert_eq!(7, reader.bit_offset);
    }

    #[test]
    fn read_by_gt_8_bits_fails() {
        let buf = [0xF0, 0xF0];
        let mut reader = Reader::new("TEST_MSG", &buf);
        assert!(reader.read_bits(8).is_err());
        assert!(reader.read_bits(9).is_err());
        assert!(reader.read_bits(10).is_err());
    }

    #[test]
    fn read_bit_by_bit() {
        let buf = [0xF0, 0xF0];
        let mut reader = Reader::new("TEST_MSG", &buf);
        for i in 0..4 {
            if i % 2 == 0 {
                assert!(reader.aligned());
            }
            for _ in 0..4 {
                if i % 2 == 0 {
                    assert_eq!(0x00, reader.read_bit().unwrap());
                } else {
                    assert_eq!(0x01, reader.read_bit().unwrap());
                }
            }
        }
        assert!(reader.empty());
        assert!(reader.read_bit().is_err());
    }
}
