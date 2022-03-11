// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::config::MAX_SIGNATURE_SIZE;
use crate::msgs::algorithms::BaseAsymAlgo;
use crate::msgs::certificates::CertificateChain;

/// A Validator represents *all* trust anchors (root certificates) used to endorse
/// any end entity (leaf) certificates via a certificate chain.
///
/// The validator is used to ensure that any received certificate chain is
/// rooted to a trust anchor that the user of the SPDM library trusts. Basic
/// constraint validation should also be performed.
///
/// Validators can also be used to ensure extra, application specific properties
/// of an end entity cert, such as that they derive from a shared DeviceId
/// public key. or that they have certain information encoded in the cert.
pub trait Validator<'a> {
    type Error;
    type EndEntityCert: EndEntityCert<'a>;

    fn validate(
        algorithm: BaseAsymAlgo,
        cert_chain: CertificateChain<'a>,
    ) -> Result<Self::EndEntityCert, Self::Error>;
}

/// An EndEntityCert represents the leaf certificate in a certificate chain.
///
/// It can be used to verify that a msg was signed by the certificate's
/// corresponding private key.
///
/// EndEntityCerts are are created by a `Validator` and returned after they have
/// already been validated. Therefore the only thing they need to be used for is
/// verifying signatures.
pub trait EndEntityCert<'a> {
    type Error;

    fn verify(
        algorithm: BaseAsymAlgo,
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), Self::Error>;
}

// DER tags required for this module
pub const DER_TAG_SEQUENCE: u8 = 0x30;
pub const DER_TAG_INTEGER: u8 = 0x02;

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
pub fn bin_to_der(signature: &[u8], out: &mut [u8]) -> usize {
    let value_size = signature.len() / 2;
    let r = &signature[..value_size];
    let s = &signature[value_size..];

    let (r_start, r_len) = get_start_and_length(r);
    let (s_start, s_len) = get_start_and_length(s);

    // Compute the size of the encoded integer sequence
    let sig_len = 2 + r_len + s_len + der_length(r_len) + der_length(s_len);

    // Write out the sequence tag and length
    out[0] = DER_TAG_SEQUENCE;
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
    out[0] = DER_TAG_INTEGER;
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
pub const fn max_encoded_size() -> usize {
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
