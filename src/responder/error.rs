// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use core::fmt::{self, Display, Formatter};

use crate::msgs::{ReadError, WriteError};

/// An error returned by a responder state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponderError {
    Write(WriteError),
    Read(ReadError),

    // `got` is the code. TODO: Try to map this to a message name?
    UnexpectedMsg { expected: &'static str, got: u8 },

    // A challenge was sent with a slot that does not contain a cert
    InvalidSlot,

    // For some reason signing failed. This could be caused by a HW failure.
    SigningFailed,
}

impl From<WriteError> for ResponderError {
    fn from(e: WriteError) -> Self {
        ResponderError::Write(e)
    }
}

impl From<ReadError> for ResponderError {
    fn from(e: ReadError) -> Self {
        ResponderError::Read(e)
    }
}

impl Display for ResponderError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ResponderError::Write(e) => e.fmt(f),
            ResponderError::Read(e) => e.fmt(f),

            // TODO: print message name and not just code
            ResponderError::UnexpectedMsg { expected, got } => {
                write!(
                    f,
                    "unexpected msg: (expected: {}, got code: {})",
                    expected, got
                )
            }

            ResponderError::InvalidSlot => {
                write!(f, "the requested slot does not contain a certificate")
            }
            ResponderError::SigningFailed => {
                write!(f, "signing failed")
            }
        }
    }
}
