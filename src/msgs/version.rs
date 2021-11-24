// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::encoding::{ReadError, ReadErrorKind, Reader, WriteError, Writer};
use super::Msg;

/// Request the SPDM version in use at the responder.
///
/// This is the first message issued in the SPDM protocol.
pub struct GetVersion {}

impl Msg for GetVersion {
    const NAME: &'static str = "GET_VERSION";

    const SPDM_VERSION: u8 = 0x10;

    const SPDM_CODE: u8 = 0x84;

    fn write_body(&self, w: &mut Writer) -> Result<usize, WriteError> {
        w.put_reserved(2)
    }
}

impl GetVersion {
    pub fn parse_body(buf: &[u8]) -> Result<GetVersion, ReadError> {
        let mut reader = Reader::new(Self::NAME, buf);
        reader.skip_reserved(2)?;
        Ok(GetVersion {})
    }
}

// TODO: Move this to config? If new versions are supported by a responder, they
/// may not fit in the underlying array, and this would cause version
/// negotiation to fail and the protocol to be unable to proceed.
pub const MAX_ALLOWED_VERSIONS: u8 = 2;

/// The deserialized form of a specific version
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VersionEntry {
    pub major: u8,
    pub minor: u8,
    pub update: u8,
    pub alpha: u8,
}

/// A VERSION msg contains set of versions supported by a responder
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub num_entries: u8,
    pub entries: [VersionEntry; MAX_ALLOWED_VERSIONS as usize],
}

impl Version {
    fn empty() -> Version {
        Version {
            num_entries: 0,
            entries: [VersionEntry::default(); MAX_ALLOWED_VERSIONS as usize],
        }
    }
}

// There are only 2 published versions (1.0 and 1.1)
// They don't have update or alpha modifiers.
impl Default for Version {
    fn default() -> Version {
        Version {
            num_entries: 2,
            entries: [
                VersionEntry { major: 1, minor: 0, update: 0, alpha: 0 },
                VersionEntry { major: 1, minor: 1, update: 0, alpha: 0 },
            ],
        }
    }
}

impl Msg for Version {
    const NAME: &'static str = "VERSION";

    const SPDM_VERSION: u8 = 0x10;

    const SPDM_CODE: u8 = 0x04;

    fn write_body(&self, w: &mut Writer) -> Result<usize, WriteError> {
        // Reserved bytes
        w.put(0)?;
        w.put(0)?;
        w.put(0)?;

        w.put(self.num_entries)?;

        for v in self.entries.iter() {
            w.put(v.alpha | (v.update << 4))?;
            w.put(v.minor | (v.major << 4))?;
        }

        Ok(w.offset())
    }
}

impl Version {
    pub fn parse_body(buf: &[u8]) -> Result<Version, ReadError> {
        let mut reader = Reader::new(Self::NAME, buf);

        reader.skip_reserved(3)?;

        // 1 byte number of version entries
        let num_entries = reader.get_byte()?;
        if num_entries > MAX_ALLOWED_VERSIONS {
            return Err(ReadError::new(
                Self::NAME,
                ReadErrorKind::ImplementationLimitReached,
            ));
        }

        let mut version = Version::empty();
        version.num_entries = num_entries;

        // Num entries * 2 bytes
        for i in 0..(num_entries as usize) {
            version.entries[i] = VersionEntry {
                alpha: reader.get_bits(4)?,
                update: reader.get_bits(4)?,
                minor: reader.get_bits(4)?,
                major: reader.get_bits(4)?,
            };
        }

        Ok(version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_version_parses_correctly() {
        let mut buf = [0u8; 16];
        let version = Version::default();
        assert_eq!(10, version.write(&mut buf).unwrap());
        assert_eq!(Ok(true), Version::parse_header(&buf));
        let version2 = Version::parse_body(&buf[2..]).unwrap();
        assert_eq!(version, version2);
    }
}
