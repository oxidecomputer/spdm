use crate::msgs::{ReadError, WriteError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponderError {
    Write(WriteError),
    Read(ReadError),

    // `got` is the code. TODO: Try to map this to a message name?
    UnexpectedMsg { expected: &'static str, got: u8 },
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
