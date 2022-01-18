// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::msgs::{
    self,
    algorithms::ParseNegotiateAlgorithmsError,
    capabilities::{ParseGetCapabilitiesError, ParseRspCapabilityError},
    certificates::WriteCertificateChainError,
    challenge::{ParseChallengeError, WriteChallengeAuthError},
    BufferFullError, ParseHeaderError, ReadError,
};

/// An error returned by a responder state
#[derive(Debug, PartialEq)]
pub enum ResponderError {
    // Failed to parse a message header
    ParseHeader,

    // Reading an encoded message from a buffer failed
    Read(ReadError),

    // Writing a message to a buffer failed because the buffer was full
    BufferFull,

    // We received an unexpected message type
    UnexpectedMsgCode { expected: u8, got: u8 },

    // A challenge was sent with a slot that does not contain a cert
    InvalidSlot,

    // For some reason signing failed. This could be caused by a HW failure.
    SigningFailed,

    // Failed to write a cert chain message
    WriteCertChain(WriteCertificateChainError),

    // Parsing a NegotiateAlgorithms message failed
    ParseNegotiateAlgorithms(ParseNegotiateAlgorithmsError),

    // Parsing a GetCapabilities message failed
    ParseGetCapabilities(ParseGetCapabilitiesError),

    // Parsing a capability from a string failed
    ParseCapability,

    // Parsing a Challenge message has failed
    ParseChallenge(ParseChallengeError),

    // Writing a ChallengeAuth message failed
    WriteChallengeAuth(WriteChallengeAuthError),
}

impl From<BufferFullError> for ResponderError {
    fn from(_: BufferFullError) -> Self {
        ResponderError::BufferFull
    }
}

impl From<ReadError> for ResponderError {
    fn from(e: ReadError) -> Self {
        ResponderError::Read(e)
    }
}

impl From<WriteCertificateChainError> for ResponderError {
    fn from(e: WriteCertificateChainError) -> Self {
        ResponderError::WriteCertChain(e)
    }
}

impl From<ParseHeaderError> for ResponderError {
    fn from(_: ParseHeaderError) -> Self {
        ResponderError::ParseHeader
    }
}

impl From<ParseGetCapabilitiesError> for ResponderError {
    fn from(e: ParseGetCapabilitiesError) -> Self {
        ResponderError::ParseGetCapabilities(e)
    }
}

impl From<ParseNegotiateAlgorithmsError> for ResponderError {
    fn from(e: ParseNegotiateAlgorithmsError) -> Self {
        ResponderError::ParseNegotiateAlgorithms(e)
    }
}

impl From<ParseRspCapabilityError> for ResponderError {
    fn from(_: ParseRspCapabilityError) -> Self {
        ResponderError::ParseCapability
    }
}

impl From<ParseChallengeError> for ResponderError {
    fn from(e: ParseChallengeError) -> Self {
        ResponderError::ParseChallenge(e)
    }
}

impl From<WriteChallengeAuthError> for ResponderError {
    fn from(e: WriteChallengeAuthError) -> Self {
        ResponderError::WriteChallengeAuth(e)
    }
}

impl From<&ResponderError> for msgs::Error {
    fn from(err: &ResponderError) -> Self {
        match err {
            ResponderError::ParseHeader => msgs::Error::UnexpectedRequest,
            ResponderError::BufferFull => msgs::Error::LargeResponse(0),
            ResponderError::Read(e) => read_error_to_msgs_error(e),
            ResponderError::UnexpectedMsgCode { .. } => {
                msgs::Error::UnexpectedRequest
            }
            ResponderError::InvalidSlot => msgs::Error::InvalidRequest,
            ResponderError::SigningFailed => msgs::Error::Unspecified,
            ResponderError::WriteCertChain(_) => msgs::Error::LargeResponse(0),
            ResponderError::ParseCapability => msgs::Error::Unspecified,
            ResponderError::ParseGetCapabilities(
                ParseGetCapabilitiesError::InvalidBitsSet,
            ) => msgs::Error::InvalidRequest,
            ResponderError::ParseGetCapabilities(
                ParseGetCapabilitiesError::Read(e),
            ) => read_error_to_msgs_error(e),
            ResponderError::ParseNegotiateAlgorithms(
                ParseNegotiateAlgorithmsError::Read(e),
            ) => read_error_to_msgs_error(e),
            ResponderError::ParseNegotiateAlgorithms(
                ParseNegotiateAlgorithmsError::TooLarge,
            ) => msgs::Error::RequestTooLarge,
            ResponderError::ParseNegotiateAlgorithms(_) => {
                msgs::Error::InvalidRequest
            }
            ResponderError::ParseChallenge(
                ParseChallengeError::InvalidMeasurementHashType,
            ) => msgs::Error::InvalidRequest,
            ResponderError::ParseChallenge(ParseChallengeError::Read(e)) => {
                read_error_to_msgs_error(e)
            }
            ResponderError::WriteChallengeAuth(
                WriteChallengeAuthError::BufferFull,
            ) => msgs::Error::ResponseTooLarge(0),
            ResponderError::WriteChallengeAuth(_) => {
                msgs::Error::InvalidRequest
            }
        }
    }
}

fn read_error_to_msgs_error(err: &ReadError) -> msgs::Error {
    match err {
        ReadError::BufferEmpty => msgs::Error::RequestTooLarge,
        ReadError::ReservedByteNotZero => msgs::Error::InvalidRequest,
        ReadError::Unaligned
        | ReadError::TooManyBits
        | ReadError::TypeConversionFailed => msgs::Error::Unspecified,
    }
}
