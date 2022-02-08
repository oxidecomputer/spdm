// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use core::convert::{TryFrom, TryInto};
use crypto::digest::Digest;
use ring_compat::digest::{Sha256, Sha384, Sha512};

use crate::crypto::digest::Digests;
use crate::impl_digests;
use crate::msgs::algorithms::BaseHashAlgo;

impl_digests!(
    pub enum ProvidedDigests {
        Sha256(Sha256),
        Sha384(Sha384),
        Sha512(Sha512),
    }
);

impl ProvidedDigests {
    pub fn supported_algorithms() -> BaseHashAlgo {
        BaseHashAlgo::SHA_256 | BaseHashAlgo::SHA_384 | BaseHashAlgo::SHA_512
    }
}

impl TryFrom<BaseHashAlgo> for ProvidedDigests {
    type Error = ();
    fn try_from(algo: BaseHashAlgo) -> Result<Self, Self::Error> {
        match algo {
            BaseHashAlgo::SHA_256 => Ok(ProvidedDigests::Sha256(Sha256::new())),
            BaseHashAlgo::SHA_384 => Ok(ProvidedDigests::Sha384(Sha384::new())),
            BaseHashAlgo::SHA_512 => Ok(ProvidedDigests::Sha512(Sha512::new())),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::test::from_hex;

    #[test]
    // Expected hashes from openssl output on cli
    // `echo test | openssl dgst -sha256`
    fn ring_digest_sha256() {
        let expected = from_hex(
            "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2",
        )
        .unwrap();

        let actual = ProvidedDigests::digest(BaseHashAlgo::SHA_256, b"test\n");
        assert_eq!(&expected, actual.as_ref());
    }

    #[test]
    // Expected hashes from openssl output on cli
    // `echo test | openssl dgst -sha256`
    fn ring_digest_sha256_incremental() {
        let expected = from_hex(
            "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2",
        )
        .unwrap();

        let mut digest =
            ProvidedDigests::try_from(BaseHashAlgo::SHA_256).unwrap();
        digest.update(b"te");
        digest.update(b"st");
        digest.update(b"\n");
        let actual = digest.finalize();

        assert_eq!(&expected, actual.as_ref());
    }

    #[test]
    // Expected hashes from openssl output on cli
    // `echo test | openssl dgst -sha384`
    fn ring_digest_sha384() {
        let expected = from_hex(
            "109bb6b5b6d5547c1ce03c7a8bd7d8f80c1cb0957f50c4f7fda04692079917e4f9cad52b878f3d8234e1a170b154b72d"
        )
        .unwrap();

        let actual = ProvidedDigests::digest(BaseHashAlgo::SHA_384, b"test\n");
        assert_eq!(&expected, actual.as_ref());
    }

    #[test]
    // Expected hashes from openssl output on cli
    // `echo test | openssl dgst -sha512`
    fn ring_digest_sha512() {
        let expected = from_hex(
            "0e3e75234abc68f4378a86b3f4b32a198ba301845b0cd6e50106e874345700cc6663a86c1ea125dc5e92be17c98f9a0f85ca9d5f595db2012f7cc3571945c123"
        )
        .unwrap();

        let actual = ProvidedDigests::digest(BaseHashAlgo::SHA_512, b"test\n");
        assert_eq!(&expected, actual.as_ref());
    }

    #[test]
    #[should_panic]
    fn ring_digest_unsupported() {
        ProvidedDigests::digest(BaseHashAlgo::SHA3_256, b"test\n");
    }
}
