//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//

use core::fmt::{self, Display, Formatter};

use crate::crypto::pki;
use crate::msgs::{ReadError, Version, WriteError};

/// A requester specific error returned from state machine methods
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequesterError {
    Write(WriteError),
    Read(ReadError),

    // `got` is the code. TODO: Try to map this to a message name?
    UnexpectedMsg { expected: &'static str, got: u8 },

    //
    // Version related messages
    //
    NoSupportedVersions { received: Version },

    // The responder chose an algorithm that was not a requester option
    SelectedAlgorithmNotRequested,

    // The challenge auth response was invalid
    BadChallengeAuth,

    // A certificate could not be parsed properly
    InvalidCert,
}

impl From<WriteError> for RequesterError {
    fn from(e: WriteError) -> Self {
        RequesterError::Write(e)
    }
}

impl From<ReadError> for RequesterError {
    fn from(e: ReadError) -> Self {
        RequesterError::Read(e)
    }
}

impl From<pki::Error> for RequesterError {
    fn from(_: pki::Error) -> Self {
        RequesterError::InvalidCert
    }
}

impl Display for RequesterError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            RequesterError::Write(e) => e.fmt(f),
            RequesterError::Read(e) => e.fmt(f),
            // TODO: print message name and not just code
            RequesterError::UnexpectedMsg { expected, got } => {
                write!(
                    f,
                    "unexpected msg: (expected: {}, got code: {})",
                    expected, got
                )
            }
            RequesterError::NoSupportedVersions { received } => {
                write!(f, "no supported versions received: {:#?}", received)
            }
            RequesterError::SelectedAlgorithmNotRequested => {
                write!(
                    f,
                    "the responder selected an algorithm that the
requester does not support"
                )
            }
            RequesterError::BadChallengeAuth => {
                write!(f, "challenge authentication failed")
            }
            RequesterError::InvalidCert => {
                write!(f, "invalid certificate")
            }
        }
    }
}
