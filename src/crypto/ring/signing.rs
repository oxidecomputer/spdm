// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ring::signature::{
    EcdsaKeyPair, EcdsaSigningAlgorithm, ECDSA_P256_SHA256_FIXED_SIGNING,
    ECDSA_P384_SHA384_FIXED_SIGNING,
};

use ring::rand::SystemRandom;

use super::super::signing::{Error, Signature, Signer};
use crate::msgs::algorithms::BaseAsymAlgo;

// Convert a SPDM algorithmn to a Ring algorithm
//
// TODO: Put behind feature
fn spdm_to_ring(algorithm: BaseAsymAlgo) -> &'static EcdsaSigningAlgorithm {
    match algorithm {
        BaseAsymAlgo::ECDSA_ECC_NIST_P256 => &ECDSA_P256_SHA256_FIXED_SIGNING,
        BaseAsymAlgo::ECDSA_ECC_NIST_P384 => &ECDSA_P384_SHA384_FIXED_SIGNING,
        _ => unimplemented!(),
    }
}

/// Take a private key in PKCS#8 v1 format and create a new signer. The signer
/// key must correspond to the given algorithm.
///
/// This is explicitly not part of a trait, as a HW module would not take a
/// private key. The application level software should call this function.
///
/// TODO: Hide this behind a feature
pub fn new_signer(
    algorithm: BaseAsymAlgo,
    private_key: &[u8],
) -> Result<RingSigner, Error> {
    let algorithm = spdm_to_ring(algorithm);
    RingSigner::new(algorithm, private_key)
}

/// A Signer backed by ring
///
/// TODO: Put behind a feature
pub struct RingSigner {
    key_pair: EcdsaKeyPair,
    rng: SystemRandom,
}

impl RingSigner {
    pub fn new(
        algorithm: &'static EcdsaSigningAlgorithm,
        private_key: &[u8],
    ) -> Result<RingSigner, Error> {
        let key_pair = EcdsaKeyPair::from_pkcs8(algorithm, private_key)
            .map_err(|_| Error {})?;
        Ok(RingSigner { key_pair, rng: SystemRandom::new() })
    }
}

impl Signature for ring::signature::Signature {}

impl Signer for RingSigner {
    type Signature = ring::signature::Signature;

    fn sign(&self, msg: &[u8]) -> Result<Self::Signature, Error> {
        self.key_pair.sign(&self.rng, msg).map_err(|_| Error {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pki::EndEntityCert;
    use crate::crypto::ring::pki::new_end_entity_cert;
    use test_utils::certs::*;

    // Sign a message using a private key and verify it using a certificate
    #[test]
    fn sign_and_verify() {
        let algorithm = BaseAsymAlgo::ECDSA_ECC_NIST_P256;
        let leaf_params = cert_params_ecdsa_p256_sha256(false, "Leaf");
        let cert = rcgen::Certificate::from_params(leaf_params).unwrap();

        let private_key = cert.serialize_private_key_der();
        let signer = new_signer(algorithm, &private_key).unwrap();

        let leaf_der = cert.serialize_der().unwrap();
        let end_entity_cert = new_end_entity_cert(&leaf_der).unwrap();

        let msg = b"hello, hello";

        let signature = signer.sign(msg).unwrap();

        assert!(end_entity_cert.verify_signature(
            algorithm,
            msg,
            signature.as_ref()
        ));
    }
}
