use super::{capabilities,  RequesterError, expect};
use crate::msgs::{GetVersion, Msg, Version, VersionEntry, HEADER_SIZE};
use crate::Transcript;

/// A Requester starts in this state, where version negotiation is attempted.
pub struct State {}

impl State {
    /// Serialize a get version message into `buf` and append it to `transcript`
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
    ) -> Result<capabilities::State, RequesterError> {
        expect::<Version>(buf)?;
        let version = Version::parse_body(&buf[HEADER_SIZE..])?;

        if let Some(version_entry) = Self::find_max_matching_version(&version) {
            // SUCCESS!
            transcript.extend(buf)?;
            Ok(capabilities::State::new(version_entry))
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
