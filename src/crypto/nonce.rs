// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(feature = "rand")]
use rand::{rngs::OsRng, RngCore};

use crate::msgs::encoding::{ReadError, Reader};

/// A unique random value used for cryptographic purposes
///
/// Nonces are only capable of being generated if the underlying platform
/// supports `rand`
#[cfg(feature = "rand")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce([u8; 32]);

#[cfg(feature = "rand")]
impl Nonce {
    pub fn new() -> Nonce {
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        Nonce(nonce)
    }

    pub fn read(r: &mut Reader) -> Result<Nonce, ReadError> {
        let mut nonce = [0u8; 32];
        r.get_slice(32, &mut nonce)?;
        Ok(Nonce(nonce))
    }
}

#[cfg(not(feature = "rand"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce([u8; 0]);

#[cfg(not(feature = "rand"))]
impl Nonce {
    pub fn new() -> Nonce {
        Nonce([0u8; 0])
    }

    pub fn read(_: &mut Reader) -> Result<Nonce, ReadError> {
        Ok(Nonce([0u8; 0]))
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Nonce {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    impl Nonce {
        #[cfg(feature = "rand")]
        pub fn new_with_magic(magic: u8) -> Nonce {
            Nonce([magic; 32])
        }

        #[cfg(not(feature = "rand"))]
        pub fn new_with_magic(magic: u8) -> Nonce {
            Nonce([magic; 0])
        }
    }
}
