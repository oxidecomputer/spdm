// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::msgs::algorithms::BaseHashAlgo;
use crate::msgs::common::DigestBuf;
use core::convert::{AsRef, TryFrom};

/// Providers implement this trait to provide cryptographic hash support
pub trait Digest: AsRef<[u8]> {
    fn hash(algorithm: BaseHashAlgo, buf: &[u8]) -> Self;
}

/// A trait for enum wrappers around RustCrypto `Digest` variants
///
/// This trait implements a subset of the functionality of a RustCrypto Digest,
/// while allowing any implementor of `Digest` to be a variant of the wrapper
/// enum. We try to keep the implemented API as similar as possible to `Digest`,
/// but this is not always possible given the differences in ouptut size of
/// different algorithms.
///
/// We don't directly implement the `Digest` trait for a number of reasons:
///  * `new()` and `new_with_prefix()` don't semantically make sense for enums
///  * We can't uniformly return `Output<Self>` for the underlying variant types
///    since the lengths vary and `GenericArray` does not allow that.
pub trait Digests: TryFrom<BaseHashAlgo> {
    // Incrementally update a hash
    fn update(&mut self, data: impl AsRef<[u8]>);

    // Finish incrementally updating a hash and return the output
    //
    // Note that this makes a copy of the hash. Theortically we could create an
    // enum of `digest::Output` and then have that return a slice to prevent the
    // copy. However, practically speaking that doesn't make a lot of sense
    // since the message code operates in terms of `DigestBuf` and we'd end up
    // copying into one anyway. We just go ahead and do that here for simplicity.
    fn finalize(self) -> DigestBuf;

    // A convenience function to return a digest of `data` via `algorithm`.
    fn digest(algorithm: BaseHashAlgo, data: impl AsRef<[u8]>) -> DigestBuf;
}

/// Implement `Digests` for an enum where each variant implements
/// `crypto::digest::Digest`.
///
/// This assumes each variant of an enum is of tuple form with one element: e.g.
///  ```
///  # #[cfg(feature = "crypto-ring")] {
///  use ring_compat::digest::Sha256;
///  use ring_compat::digest::Sha512;
///  enum ProvidedDigests {
///      Sha256(Sha256),
///      Sha512(Sha512),
///  }
///  # }
///  ```
#[macro_export]
macro_rules! impl_digests {
    (
        $vis:vis enum $name:ident {
          $( $variant:ident($algo:ty) $(,)* )+
        }
    ) => {

        $vis enum $name {
            $( $variant($algo) ),+
        }

        impl Digests for $name {
            fn update(&mut self, data: impl AsRef<[u8]>) {
                match self {
                    $( $name::$variant(digest) => digest.update(data) ),+
                }
            }

            fn finalize(self) -> crate::msgs::common::DigestBuf {
                match self {
                    $(
                        $name::$variant(digest) => {
                            digest.finalize().as_slice().try_into().unwrap()
                        }
                    ),+
                }
            }

            fn digest(
                algorithm: crate::msgs::algorithms::BaseHashAlgo,
                data: impl AsRef<[u8]>
            ) -> crate::msgs::common::DigestBuf {
                let mut digests = $name::try_from(algorithm).unwrap();
                digests.update(data);
                digests.finalize()
            }
        }

    };
}
