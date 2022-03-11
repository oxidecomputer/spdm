// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use core::convert::TryFrom;
use heapless::Vec;

use crate::msgs::algorithms::BaseAsymAlgo;
use crate::msgs::certificates::CertificateChain;

use super::super::pki::{bin_to_der, max_encoded_size, EndEntityCert, Error};

// This is purposefully hardcoded as device certs mostly will not expire and we
// need *some* valid time. Furthermore, during early boot we will not have
// access to a trusted source of time.
//
// An alternative would be to disable the time check in a patched version of
// WebPKI.
//
// This may not work for all consumers of this library.
// Tracked in https://github.com/oxidecomputer/spdm/issues/31
//
// December 1, 2021 00:00:00 GMT
const UNIX_TIME: u64 = 1638316800;

// TODO: Make this configurable?
const MAX_ROOT_CERTS: u8 = 8;

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

/// A validator is a wrapper around a set of trust anchors
pub struct WebpkiValidator<'a> {
    trust_anchors: Vec<<webpki::TrustAnchor>, MAX_ROOT_CERTS>,
}

impl<'a> WebpkiValidator<'a> {
    /// Create a validator from a set of DER encoded X.509v3 root certs
    pub fn try_from_der_root_certs(
        root_certs: &[&[u8]],
    ) -> Result<WebpkiValidator, webpki::Error> {

        let trust_anchors = root_certs.iter().map(|cert| webpki::TrustAnchor::try_from_cert_der(cert)?).collect();

        Ok(WebpkiValidator { trust_anchors })
    }
}

impl<'a> Validator for WebpkiValidator<'a> {
    type Error = webpki::Error;
    type EndEntityCert = WebpkiEndEntityCert<'a>;

    fn validate(
        algo: BaseAsymAlgo,
        cert_chain: CertificateChain<'a>,
    ) -> Result<Self::EndEntityCert, Self::Error> {
        let cert = webpki::EndEntityCert::try_from(cert_chain.leaf_cert)?;

        let time = webpki::Time::from_seconds_since_unix_epoch(
            UNIX_TIME
        );

        let algo = spdm_to_webpki(algorithm);

        // TODO: Does it matter if we use server or client here?
        let server_trust_anchors =
            webpki::TlsServerTrustAnchors(&self.trust_anchors);

        cert.verify_is_valid_tls_server_cert(
            &[algo],
            &server_trust_anchors,
            cert_chain.intermediate_certs(),
            time,
        )?;

        Ok(WebpkiEndEntityCert { cert })
    }
}

/// webpki based implementaion of `EndEntityCert`
pub struct WebpkiEndEntityCert<'a> {
    cert: webpki::EndEntityCert<'a>,
}

impl<'a> EndEntityCert<'a> for WebpkiEndEntityCert<'a> {
    type Error = webpki::Error;

    fn verify(
        &self,
        algorithm: BaseAsymAlgo,
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), Self::Error> {
        let algo = spdm_to_webpki(algorithm);
        let mut der = [0u8; max_encoded_size()];
        let size = bin_to_der(signature, &mut der[..]);
        self.cert.verify_signature(algo, msg, &der[..size])
    }
}
