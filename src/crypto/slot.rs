// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Code for a wrapper around a SPDM certificate slot

use crate::crypto::signing::Signer;
use crate::msgs::algorithms::{BaseAsymAlgo, BaseHashAlgo};
use crate::msgs::CertificateChain;

/// A FilledSlot is a wrapper around a SPDM certificate slot that represents a given
/// asymmetric key pair and associated certificate chain.
///
/// A `Signer` is included because each platform using SPDM may have a different
/// mechanism for management of private keys and signing. These mechanisms may
/// include trusted hardware that never reveals the private key. We therefore
/// bundle a Signer, that is expected to be constructed by the user of this library
/// for a given slot..
///
/// TODO: Right now, the types of algorithms are encoded as SPDM specific base
/// algorithms. However, it's likely that we will support only a subset of base
/// algorithms, as well as potentially other algorithms. Maybe we should have a
/// global enum consisting of all supported algorithms for all platforms that
/// are then used throughout this library rather than the SPDM types. We would
/// then map this algorithm to the appropriate underlying base or extended SPDM
/// algorithm as necessary.
/// Tracked in https://github.com/oxidecomputer/spdm/issues/24
pub struct FilledSlot<'a, S: Signer> {
    pub signing_algorithm: BaseAsymAlgo,
    pub hash_algorithm: BaseHashAlgo,
    pub cert_chain: CertificateChain<'a>,
    pub signer: S,
}
