use super::{CapabilitiesState, RequesterError};
use crate::msgs::{GetVersion, Msg, Version, VersionEntry, HEADER_SIZE};
use crate::Transcript;

/// The possible sef of state transitions out of the VersionState.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionTransition {
    Capabilities(CapabilitiesState),
}

/// A Requester starts in this state, where version negotiation is attempted.
pub struct VersionState {}

impl VersionState {
    pub fn write_get_version(
        &self,
        buf: &mut [u8],
        transcript: &mut Transcript,
    ) -> Result<usize, RequesterError> {
        let size = GetVersion {}.write(buf)?;

        // A GetVersion msg always resets the state of the protocol.
        transcript.clear();
        transcript.extend(&buf[..size])?;
        Ok(size)
    }

    // Only Version messages are acceptable here.
    pub fn handle_msg(
        self,
        buf: &[u8],
        transcript: &mut Transcript,
    ) -> Result<VersionTransition, RequesterError> {
        match Version::parse_header(buf) {
            Ok(true) => self.handle_version(buf, transcript),
            Ok(false) => Err(RequesterError::UnexpectedMsg {
                expected: Version::name(),
                got: buf[0],
            }),
            Err(e) => Err(e.into()),
        }
    }

    fn handle_version(
        self,
        buf: &[u8],
        transcript: &mut Transcript,
    ) -> Result<VersionTransition, RequesterError> {
        let version = Version::parse_body(&buf[HEADER_SIZE..])?;

        if let Some(version_entry) = Self::find_max_matching_version(&version) {
            // SUCCESS!
            transcript.extend(buf)?;
            let new_state = CapabilitiesState::new(version_entry);
            Ok(VersionTransition::Capabilities(new_state))
        } else {
            Err(RequesterError::NoSupportedVersions { received: version })
        }
    }

    fn find_max_matching_version(version: &Version) -> Option<VersionEntry> {
        let expected = Version::default();
        let mut found = VersionEntry::default();

        for i in 0..version.num_entries as usize {
            if version.entries[i] > found {
                for j in 0..expected.num_entries as usize {
                    if version.entries[i] == expected.entries[j] {
                        found = version.entries[i];
                        break;
                    }
                }
            }
        }

        if found == VersionEntry::default() {
            None
        } else {
            Some(found)
        }
    }
}
