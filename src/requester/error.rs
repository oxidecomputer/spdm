// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::crypto::pki;
use crate::msgs::{
    algorithms::{
        ParseAlgorithmsError, ParseBaseAsymAlgoError, ParseBaseHashAlgoError,
    },
    capabilities::{ParseCapabilitiesError, ParseReqCapabilityError},
    certificates::{ParseCertificateChainError, ParseCertificateError},
    challenge::ParseChallengeAuthError,
    version::ParseVersionError,
    BufferFullError, ParseHeaderError, ReadError, Version,
};

use super::challenge::ChallengeAuthError;

/// A requester specific error returned from state machine methods
#[derive(Debug, PartialEq)]
pub enum RequesterError {
    // An error occurred when reading a message from a buffer
    Read(ReadError),

    // Reading into a buffer failed because the buffer is full
    BufferFull,

    // An unexpected message code was received in the header of a message
    UnexpectedMsgCode {
        expected: u8,
        got: u8,
    },

    /// The responder does not support the same versions as the requester
    NoSupportedVersions {
        received: Version,
    },

    // The responder chose an algorithm that was not a requester option
    SelectedAlgorithmNotRequested,

    // The challenge auth response was invalid
    ChallengeAuth(ChallengeAuthError),

    // A certificate could not be parsed properly
    ParseCert(ParseCertificateError),
    InvalidCert,

    // An Algorithms msg could not be parsed properly
    ParseAlgorithms(ParseAlgorithmsError),

    // Parsing a base asymetric signing algorithm type from a string failed
    ParseBaseAsymAlgo,

    // Parsing a base hash algorithm type from a string failed
    ParseBaseHashAlgo,

    // Parsing a Capabilities message failed
    ParseCapabilities,

    // Parsing a capability from a string failed
    ParseCapability,

    // Protocol initialization is complete and a secure session now exists.
    // The user must transition to the `RequesterSession` state.
    InitializationComplete,

    // Parsing a ChallengeAuth message failed
    ParseChallengeAuth(ParseChallengeAuthError),

    // Parsing a message header failed
    ParseHeader,

    // Parsing a Version message failed
    ParseVersion(ParseVersionError),

    // Parsing a Certificate Chain failed
    ParseCertChain(ParseCertificateChainError),

    // The protocol has reached an error state and a request was attempted
    Wedged,

    // The protocol has already completed and a new request arrived.
    Complete,
}

impl From<BufferFullError> for RequesterError {
    fn from(_: BufferFullError) -> Self {
        RequesterError::BufferFull
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

impl From<ParseCertificateError> for RequesterError {
    fn from(e: ParseCertificateError) -> Self {
        RequesterError::ParseCert(e)
    }
}

impl From<ParseAlgorithmsError> for RequesterError {
    fn from(e: ParseAlgorithmsError) -> Self {
        RequesterError::ParseAlgorithms(e)
    }
}

impl From<ParseBaseAsymAlgoError> for RequesterError {
    fn from(_: ParseBaseAsymAlgoError) -> Self {
        RequesterError::ParseBaseAsymAlgo
    }
}

impl From<ParseBaseHashAlgoError> for RequesterError {
    fn from(_: ParseBaseHashAlgoError) -> Self {
        RequesterError::ParseBaseHashAlgo
    }
}

impl From<ParseCapabilitiesError> for RequesterError {
    fn from(_: ParseCapabilitiesError) -> Self {
        RequesterError::ParseCapabilities
    }
}

impl From<ParseReqCapabilityError> for RequesterError {
    fn from(_: ParseReqCapabilityError) -> Self {
        RequesterError::ParseCapability
    }
}

impl From<ParseChallengeAuthError> for RequesterError {
    fn from(e: ParseChallengeAuthError) -> Self {
        RequesterError::ParseChallengeAuth(e)
    }
}

impl From<ParseHeaderError> for RequesterError {
    fn from(_: ParseHeaderError) -> Self {
        RequesterError::ParseHeader
    }
}

impl From<ParseVersionError> for RequesterError {
    fn from(e: ParseVersionError) -> Self {
        RequesterError::ParseVersion(e)
    }
}

impl From<ParseCertificateChainError> for RequesterError {
    fn from(e: ParseCertificateChainError) -> Self {
        RequesterError::ParseCertChain(e)
    }
}

impl From<ChallengeAuthError> for RequesterError {
    fn from(e: ChallengeAuthError) -> Self {
        RequesterError::ChallengeAuth(e)
    }
}
