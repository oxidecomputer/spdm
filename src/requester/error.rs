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
