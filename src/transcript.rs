use crate::msgs::WriteError;

const TRANSCRIPT_SIZE: usize = 1024;

/// A `Transcript` is used to track contigous operations for measurement
/// purposes.
///
/// A Transcript spans multiple states, and is purposefully kept outside those
/// states to reduce the cost of the typestate pattern which takes and returns
/// states by value.
pub struct Transcript {
    buf: [u8; TRANSCRIPT_SIZE],
    offset: usize,
}

impl Transcript {
    pub fn new() -> Transcript {
        Transcript { buf: [0; TRANSCRIPT_SIZE], offset: 0 }
    }

    pub fn extend(&mut self, buf: &[u8]) -> Result<(), WriteError> {
        let end = self.offset + buf.len();
        if end > self.buf.len() {
            Err(WriteError::new("TRANSCRIPT", buf.len()))
        } else {
            self.buf[self.offset..end].copy_from_slice(buf);
            self.offset = end;
            Ok(())
        }
    }

    pub fn clear(&mut self) {
        self.offset = 0;
    }

    pub fn get(&self) -> &[u8] {
        &self.buf[0..self.offset]
    }

    pub fn len(&self) -> usize {
        self.offset
    }
}
