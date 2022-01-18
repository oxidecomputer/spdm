// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ring::io::der;

use crate::config::MAX_SIGNATURE_SIZE;
use core::convert::TryFrom;

use crate::msgs::algorithms::BaseAsymAlgo;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidCert,
    ValidationFailed,
}

// TODO: Put this behind a feature flag
pub fn new_end_entity_cert<'a>(
    leaf_cert: &'a [u8],
) -> Result<impl EndEntityCert<'a>, Error> {
    WebpkiEndEntityCert::new(leaf_cert)
}

/// An EndEntityCert represents the leaf certificate in a certificate chain.
///
/// It can be used to verify that a msg was signed by the certificate's
/// corresponding private key.
///
/// It can also be verfied that an EndEntityCert is valid for a certificate ///
/// chain given a root certifcate and chain of intermediate certificates where
/// the first intermediate certificate in the chain is signed by the root
/// certificate and the last intermediate certificate in the chain has signed
/// the EndEntity (leaf) certificate.
///
///
/// An EndEntityCert wraps an ASN.1 DER encoded x.509 v3 certificate.
pub trait EndEntityCert<'a> {
    fn verify_signature(
        &self,
        algorithm: BaseAsymAlgo,
        msg: &[u8],
        signature: &[u8],
    ) -> bool;

    fn verify_chain_of_trust(
        &self,
        algorithm: BaseAsymAlgo,
        intermediate_certs: &[&[u8]],
        root_cert: &[u8],
        seconds_since_unix_epoch: u64,
    ) -> Result<(), Error>;
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

// Convert `r` and `s` values from fixed size big-endian integers where each
// takes up 1/2 of the `signature` buffer into a ASN.1 DER encoded buffer
// as described in
// https://datatracker.ietf.org/doc/html/rfc3279#section-2.2.3.
//
// ASN.1 DER encoding for integers is signed, but `r` and `s` must be positive.
// Therfore, if the first bit of `r` or `s` contains a 1, we must pad it with a
// zero. Then we DER encode the padded value as an integer.
//
// The DER encoded value in ASN.1 types is:
//
// Ecdsa-Sig-Value ::= SEQUENCE {
//     r   INTEGER,
//     s   INTEGER
// }
//
// This ends up being serialized in Tag-length-value (TLV) form as:
//
// 0x30 <s1> 0x02 <s2> <vr> 0x02 <s3> <vs>
//
// where:
//      `0x30` is the tag for a `SEQUENCE`
//      `<s1>`, `<s2>`,`<s3>` are variably encoded lengths of the next value
//      `0x02` is the tag for an `INTEGER`
//      `vr` and `vs` are the DER encoded positive integers for `r` and `s`
//
fn bin_to_der(signature: &[u8], out: &mut [u8]) -> usize {
    let value_size = signature.len() / 2;
    let r = &signature[..value_size];
    let s = &signature[value_size..];

    let (r_start, r_len) = get_start_and_length(r);
    let (s_start, s_len) = get_start_and_length(s);

    // Compute the size of the encoded integer sequence
    let sig_len = 2 + r_len + s_len + der_length(r_len) + der_length(s_len);

    // Write out the sequence tag and length
    out[0] = der::Tag::Sequence as u8;
    let mut written = 1 + write_der_length(&mut out[1..], sig_len);

    // Write r and s
    written += integer_to_der(&mut out[written..], &r[r_start..]);
    written += integer_to_der(&mut out[written..], &s[s_start..]);

    written
}

// Take an integer (`r` or `s`) and return as a pair its start location and its
// size including any necessary pad bytes.
fn get_start_and_length(i: &[u8]) -> (usize, usize) {
    let start = i.iter().position(|b| *b != 0).unwrap();
    let pad = if i[start] & 0x80 != 0 { 1 } else { 0 };
    let length = i.len() - start + pad;
    (start, length)
}

// Write an integer into a buffer as DER encoded positive integer
//
// Return the number of bytes written
fn integer_to_der(out: &mut [u8], integer: &[u8]) -> usize {
    let pad = if integer[0] & 0x80 != 0 { 1 } else { 0 };
    let mut written = 1;
    out[0] = der::Tag::Integer as u8;
    written += write_der_length(&mut out[written..], integer.len() + pad);
    if pad == 1 {
        out[written] = 0;
        written += 1;
    }
    out[written..][..integer.len()].copy_from_slice(integer);
    written + integer.len()
}

// Write out a DER encoded variable length
//
// We assume values no larger than 2^16 bytes.
fn write_der_length(out: &mut [u8], length: usize) -> usize {
    if length < 128 {
        out[0] = length as u8;
        1
    } else if length < 256 {
        out[0] = 0x81;
        out[1] = length as u8;
        2
    } else {
        assert!(length < 65536);
        let buf = (length as u16).to_be_bytes();
        out[0] = 0x82;
        out[1] = buf[0];
        out[2] = buf[1];
        3
    }
}

// Compute the max DER encoded size of a signature.
//
// A signature is made up of two positive integers: `r` and `s`.
//
// We assume that all bytes of the signature are used and the high bit is a
// 1, which induces a padding of a zero byte so we end up with a positive
// integer.
//
// We also assume that the total size of `r` and `s` is less than 2^16 bytes,
// such that the total size of the variable length encoding needed is 3 bytes.
#[rustfmt::skip]
const fn max_encoded_size() -> usize {
    const TAG_SIZE: usize = 1;
    let hash_size = MAX_SIGNATURE_SIZE / 2;
    let size_bytes_needed_per_hash = der_length(hash_size);

    // Tag-length-value (TLV) for the integers
    let body_size =
         MAX_SIGNATURE_SIZE // Values of `r` and `s`
         + 2                // leading 0 pad bytes to make `r` and `s` positive
         + 2 * TAG_SIZE     // Integer tags
         + size_bytes_needed_per_hash * 2;

    // Tag-length-value form for the whole signature
    TAG_SIZE // Sequence tag
        + der_length(body_size)
        + body_size
}

// Return the number of bytes needed to DER encode the length a value.
// We assume values no larger than 2^16 bytes require encoding.
const fn der_length(size: usize) -> usize {
    if size < 128 {
        1
    } else if size < 256 {
        2
    } else {
        3
    }
}
