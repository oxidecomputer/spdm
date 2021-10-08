use super::{CapabilitiesState, ResponderError};
use crate::msgs::{GetVersion, Msg, Version, HEADER_SIZE};
use crate::Transcript;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionTransition {
    Capabilities(CapabilitiesState),
}

pub struct VersionState {}

impl VersionState {
    pub fn handle_msg(
        self,
        req: &[u8],
        rsp: &mut [u8],
        transcript: &mut Transcript,
    ) -> Result<(usize, VersionTransition), ResponderError> {
        match GetVersion::parse_header(req) {
            Ok(true) => self.handle_get_version(req, rsp, transcript),
            Ok(false) => Err(ResponderError::UnexpectedMsg {
                expected: GetVersion::name(),
                got: req[0],
            }),
            Err(e) => Err(e.into()),
        }
    }

    fn handle_get_version(
        self,
        req: &[u8],
        rsp: &mut [u8],
        transcript: &mut Transcript,
    ) -> Result<(usize, VersionTransition), ResponderError> {
        let _ = GetVersion::parse_body(&req[HEADER_SIZE..])?;

        // A GetVersion msg always resets the state of the protocol
        transcript.clear();
        transcript.extend(req)?;

        let size = Version::default().write(rsp)?;
        transcript.extend(&rsp[..size])?;

        Ok((size, VersionTransition::Capabilities(CapabilitiesState::new())))
    }
}
