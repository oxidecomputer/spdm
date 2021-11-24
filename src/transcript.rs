//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//

use crate::msgs::WriteError;
use crate::config::TRANSCRIPT_SIZE;

/// A `Transcript` is used to track contigous operations for measurement
/// purposes.
///
/// A Transcript spans multiple states, and is purposefully kept outside those
/// states to reduce the cost of the typestate pattern which takes and returns
/// states by value.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Transcript {
    buf: [u8; TRANSCRIPT_SIZE],
    offset: usize,
}

impl Transcript {
    pub fn new() -> Transcript {
        Transcript { buf: [0; TRANSCRIPT_SIZE], offset: 0 }
    }

    /// Append a serialized message onto the transcript
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

    /// Empty the transcript
    pub fn clear(&mut self) {
        self.offset = 0;
    }

    /// Retrieve the transcript
    pub fn get(&self) -> &[u8] {
        &self.buf[0..self.offset]
    }

    /// Return the length of the transcript
    pub fn len(&self) -> usize {
        self.offset
    }
}
