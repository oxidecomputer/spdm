// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use core::cmp::PartialEq;

use crate::crypto::digest::Digest;
use crate::msgs::algorithms::BaseHashAlgo;

// TODO: Should this even exist? Should a single crypto provider be used for all
// mechanisms? Should we allow more than one provider per crypto mechanism?
pub type DigestImpl = RingDigest;

/// A Ring based implementation of a Digest
#[derive(Debug, Clone)]
pub struct RingDigest {
    digest: ring::digest::Digest,
}

impl PartialEq for RingDigest {
    fn eq(&self, other: &RingDigest) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for RingDigest {}

impl Digest for RingDigest {
    fn hash(algorithm: BaseHashAlgo, buf: &[u8]) -> Self {
        let algo = match algorithm {
            BaseHashAlgo::SHA_256 => &ring::digest::SHA256,
            BaseHashAlgo::SHA_384 => &ring::digest::SHA384,
            BaseHashAlgo::SHA_512 => &ring::digest::SHA512,
            _ => unimplemented!(),
        };
        RingDigest { digest: ring::digest::digest(algo, buf) }
    }
}

impl AsRef<[u8]> for RingDigest {
    fn as_ref(&self) -> &[u8] {
        self.digest.as_ref()
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

        let actual = RingDigest::hash(BaseHashAlgo::SHA_256, b"test\n");
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

        let actual = RingDigest::hash(BaseHashAlgo::SHA_384, b"test\n");
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

        let actual = RingDigest::hash(BaseHashAlgo::SHA_512, b"test\n");
        assert_eq!(&expected, actual.as_ref());
    }

    #[test]
    #[should_panic]
    fn ring_digest_unsupported() {
        RingDigest::hash(BaseHashAlgo::SHA3_256, b"test\n");
    }
}
