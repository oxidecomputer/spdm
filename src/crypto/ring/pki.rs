// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use core::convert::TryFrom;

use crate::msgs::algorithms::BaseAsymAlgo;

use super::super::pki::{bin_to_der, max_encoded_size, EndEntityCert, Error};

pub fn new_end_entity_cert<'a>(
    leaf_cert: &'a [u8],
) -> Result<impl EndEntityCert<'a>, Error> {
    WebpkiEndEntityCert::new(leaf_cert)
}

// We don't support any RSA algorithms via webpki because they are based on
// Ring which requires using alloc;
//
// Note that we map a specific curve to a single hash function, which
// matches the spirit of TLS 1.3 and also fits the signature sizes expected
// in the `BaseAsymAlgo` description of the `NEGOTIATE_ALGORITHMS` message.
fn spdm_to_webpki(algo: BaseAsymAlgo) -> &'static webpki::SignatureAlgorithm {
    match algo {
        BaseAsymAlgo::ECDSA_ECC_NIST_P256 => &webpki::ECDSA_P256_SHA256,
        BaseAsymAlgo::ECDSA_ECC_NIST_P384 => &webpki::ECDSA_P384_SHA384,
        _ => unimplemented!(),
    }
}

/// webpki based implementaion of `EndEntityCert`
///
/// TODO: put behind a feature flag
pub struct WebpkiEndEntityCert<'a> {
    cert: webpki::EndEntityCert<'a>,
}

impl<'a> WebpkiEndEntityCert<'a> {
    pub fn new(cert: &'a [u8]) -> Result<WebpkiEndEntityCert<'a>, Error> {
        let cert = webpki::EndEntityCert::try_from(cert)
            .map_err(|_| Error::InvalidCert)?;
        Ok(WebpkiEndEntityCert { cert })
    }
}

impl<'a> EndEntityCert<'a> for WebpkiEndEntityCert<'a> {
    fn verify_signature(
        &self,
        algorithm: BaseAsymAlgo,
        msg: &[u8],
        signature: &[u8],
    ) -> bool {
        let algo = spdm_to_webpki(algorithm);
        let mut der = [0u8; max_encoded_size()];
        let size = bin_to_der(signature, &mut der[..]);
        self.cert.verify_signature(algo, msg, &der[..size]).is_ok()
    }

    fn verify_chain_of_trust(
        &self,
        algorithm: BaseAsymAlgo,
        intermediate_certs: &[&[u8]],
        root_cert: &[u8],
        seconds_since_unix_epoch: u64,
    ) -> Result<(), Error> {
        let trust_anchors = [webpki::TrustAnchor::try_from_cert_der(root_cert)
            .map_err(|_| Error::InvalidCert)?; 1];

        // TODO: Does it matter if we use server or client here?
        let server_trust_anchors =
            webpki::TlsServerTrustAnchors(&trust_anchors);

        let time = webpki::Time::from_seconds_since_unix_epoch(
            seconds_since_unix_epoch,
        );

        let algo = spdm_to_webpki(algorithm);

        // TODO: Map error types for more info?
        self.cert
            .verify_is_valid_tls_server_cert(
                &[algo],
                &server_trust_anchors,
                intermediate_certs,
                time,
            )
            .map_err(|_| Error::ValidationFailed)
    }
}
