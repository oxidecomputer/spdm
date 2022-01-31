// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use core::convert::AsRef;

use crate::msgs::algorithms::BaseHashAlgo;

/// Providers implement this trait to provide cryptographic hash support
pub trait Digest: AsRef<[u8]> {
    fn hash(algorithm: BaseHashAlgo, buf: &[u8]) -> Self;
}
