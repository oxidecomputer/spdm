// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use core::cmp::PartialEq;

use crate::config::{MAX_CERT_CHAIN_DEPTH, MAX_CERT_CHAIN_SIZE};

use super::encoding::{
    ReadError, ReadErrorKind, Reader, WriteError, WriteErrorKind, Writer,
};
use super::Msg;

/// A request for a certificate portion in a given slot
///
/// The SPDM spec allows multiple messages to be used to transfer a certificate,
/// although this implementation does not yet support that. This is the reason
/// for the offset and length fields. This implementation always transfers an
/// entire certificate in one message, implying that offset is always `0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetCertificate {
    pub slot: u8,
    pub offset: u16,
    pub length: u16,
}

impl Msg for GetCertificate {
    const NAME: &'static str = "GET_CERTIFICATE";

    const SPDM_VERSION: u8 = 0x11;

    const SPDM_CODE: u8 = 0x82;

    fn write_body(&self, w: &mut Writer) -> Result<usize, WriteError> {
        w.put(self.slot)?;
        w.put_reserved(1)?;
        w.put_u16(self.offset)?;
        w.put_u16(self.length)
    }
}

impl GetCertificate {
    pub fn parse_body(buf: &[u8]) -> Result<GetCertificate, ReadError> {
        let mut r = Reader::new(Self::NAME, buf);
        let slot = r.get_byte()?;
        r.skip_reserved(1)?;
        let offset = r.get_u16()?;
        let length = r.get_u16()?;

        Ok(GetCertificate { slot, offset, length })
    }
}

/// A CERTIFICATE message sent by a responder
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub slot: u8,
    pub portion_length: u16,
    pub remainder_length: u16,
    pub cert_chain: [u8; MAX_CERT_CHAIN_SIZE],
}

impl Msg for Certificate {
    const NAME: &'static str = "CERTIFICATE";

    const SPDM_VERSION: u8 = 0x11;

    const SPDM_CODE: u8 = 0x02;

    fn write_body(&self, w: &mut Writer) -> Result<usize, WriteError> {
        w.put(self.slot)?;
        w.put_reserved(1)?;
        w.put_u16(self.portion_length)?;
        w.put_u16(self.remainder_length)?;
        w.extend(&self.cert_chain[..self.portion_length as usize])
    }
}

impl Certificate {
    pub fn parse_body(buf: &[u8]) -> Result<Certificate, ReadError> {
        let mut r = Reader::new(Self::NAME, buf);
        let slot = r.get_byte()?;
        r.skip_reserved(1)?;
        let portion_length = r.get_u16()?;
        if portion_length as usize > MAX_CERT_CHAIN_SIZE {
            return Err(ReadError::new(
                Self::NAME,
                ReadErrorKind::ImplementationLimitReached,
            ));
        }
        let remainder_length = r.get_u16()?;
        let mut cert_chain = [0u8; MAX_CERT_CHAIN_SIZE];
        cert_chain.as_mut()[..portion_length as usize]
            .copy_from_slice(r.get_slice(portion_length as usize)?);

        Ok(Certificate { slot, portion_length, remainder_length, cert_chain })
    }
}

/// Represents a complete certificate chain. This may result from the
/// concatenation of buffers from multiple `Certificate` messages. For now we
/// only support retreiving cert chains in a single message.
///
/// Certificates inside the cert chain are verified outside of this module.
///
/// This corresponds to the "Certificate chain format" table in section 10.6.1
/// of version 1.1.1 of the SPDM spec
#[derive(Debug, Clone, Copy)]
pub struct CertificateChain<'a> {
    pub root_hash: &'a [u8],
    pub leaf_cert: &'a [u8],

    // The certs are in order from closest to the root to the leaf.
    // In this implementation we assume that the root certificate is *not*
    // transmitted via the SPDM protocol, but instead is provisioned out of
    // band.
    num_intermediate_certs: u8,
    intermediate_certs: [&'a [u8]; MAX_CERT_CHAIN_DEPTH],
}

// We manually implement PartialEq because intermediate_certs is of variable
// size and may contain garbage from initialization.
impl<'a> PartialEq for CertificateChain<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.root_hash == other.root_hash
            && self.leaf_cert == other.leaf_cert
            && self.intermediate_certs() == other.intermediate_certs()
    }
}

impl<'a> Eq for CertificateChain<'a> {}

/// Indicates that there is no more room for intermediate certs in a
/// `CertificateChain`.
#[derive(Debug)]
pub struct Full {}

impl<'a> CertificateChain<'a> {
    /// Create a new certificate chain with no intermediate certificates
    ///
    /// `root_hash` is the hash of the DER encoded root certificate used to start
    /// the chain.
    ///
    /// `leaf_cert` is an ASN.1 DER encoded EndEntity certificate signed by
    /// either the root certificate or the last intermediate certificate in the chain.
    pub fn new(root_hash: &'a [u8], leaf_cert: &'a [u8]) -> Self {
        CertificateChain {
            root_hash,
            leaf_cert,

            // We initialize the array with "default" references, since we need
            // a slice of slices (`&[&[u8]]`) for use with webpki, and therefore
            // can't use an `option<&[u8]>`.
            //
            // We don't allow direct access to prevent misuse.
            intermediate_certs: [leaf_cert; MAX_CERT_CHAIN_DEPTH],
            num_intermediate_certs: 0,
        }
    }

    /// Return all ASN.1 DER encoded certificates
    pub fn intermediate_certs(&self) -> &[&[u8]] {
        &self.intermediate_certs[0..self.num_intermediate_certs as usize]
    }

    /// Append an ASN.1 DER encoded intermediate certificate to the chain
    ///
    /// This method is required to ensure that a cert chain can be returned as a
    /// a slice of slices, no matter the original format of the generated certs
    /// in the application code..
    pub fn append_intermediate_cert(
        &mut self,
        cert: &'a [u8],
    ) -> Result<(), Full> {
        if self.num_intermediate_certs as usize == MAX_CERT_CHAIN_DEPTH {
            return Err(Full {});
        }
        self.intermediate_certs[self.num_intermediate_certs as usize] = cert;
        self.num_intermediate_certs += 1;
        Ok(())
    }

    /// Serialize a certificate chain via a Writer
    pub fn write(&self, w: &mut Writer) -> Result<usize, WriteError> {
        let length = 4
            + self.root_hash.len()
            + (0..self.num_intermediate_certs as usize)
                .fold(0, |acc, i| acc + self.intermediate_certs[i].len())
            + self.leaf_cert.len();
        if length > 65535 {
            return Err(WriteError::new(
                "CERTFICATE",
                WriteErrorKind::InvalidRange("CertificateChain (length)"),
            ));
        }
        w.put_u16(length as u16)?;
        w.put_reserved(2)?;
        w.extend(self.root_hash)?;
        for i in 0..self.num_intermediate_certs as usize {
            w.extend(self.intermediate_certs[i])?;
        }
        w.extend(self.leaf_cert)
    }

    /// Deserialize a CertificateChain into `buf` given `digest_size`.
    ///
    /// `digest_size` must match the size of the digest used for the root hash.
    pub fn parse(
        buf: &'a [u8],
        digest_size: u8,
    ) -> Result<CertificateChain<'a>, ReadError> {
        let mut r = Reader::new("CERTFICATE", buf);
        let length = r.get_u16()?;
        if length as usize != buf.len() {
            return Err(Self::err_unexpected());
        }
        r.skip_reserved(2)?;
        let offset = r.byte_offset();
        r.skip_ignored(digest_size.into())?;
        let root_hash = &buf[offset..offset + digest_size as usize];

        let mut num_intermediate_certs = 0u8;
        let mut intermediate_certs = [buf; MAX_CERT_CHAIN_DEPTH];

        // parse DER headers of certs
        let leaf_offset = loop {
            let offset = r.byte_offset();
            let (length, header_size) = Self::read_cert_size(&mut r)?;
            if length > r.remaining() {
                return Err(Self::err_unexpected());
            }
            if length == r.remaining() {
                // we found the end entity cert
                break offset;
            }
            if num_intermediate_certs as usize == MAX_CERT_CHAIN_DEPTH {
                return Err(ReadError::new(
                    "CERTFICATE",
                    ReadErrorKind::ImplementationLimitReached,
                ));
            }
            let end = offset + length + header_size;
            intermediate_certs[num_intermediate_certs as usize] =
                &buf[offset..end];
            num_intermediate_certs += 1;

            r.skip_ignored(length)?;
        };

        let leaf_cert = &buf[leaf_offset..];

        Ok(CertificateChain {
            root_hash,
            num_intermediate_certs,
            intermediate_certs,
            leaf_cert,
        })
    }

    fn err_unexpected() -> ReadError {
        return ReadError::new("CERTFICATE", ReadErrorKind::UnexpectedValue);
    }

    // Read the size of the cert from the DER encoded header along with the
    // number of bytes read (2 - 4).
    //
    // If the high order bit of the first byte is set to zero then the length
    // is encoded in the seven remaining bits of that byte. Otherwise, those
    // seven bits represent the number of bytes used to encode the length in big
    // endian format.
    fn read_cert_size(r: &mut Reader) -> Result<(usize, usize), ReadError> {
        // Skip the sequence byte
        assert_eq!(r.get_byte()?, 0x30);

        let pair = match r.get_byte()? {
            n if (n & 0x80) == 0 => (n.into(), 2),
            0x81 => {
                let n = r.get_byte()?;
                if n < 128 {
                    return Err(Self::err_unexpected());
                }
                (n.into(), 3)
            }
            0x82 => {
                let high = r.get_byte()? as usize;
                let low = r.get_byte()? as usize;
                let n = (high << 8) | low;
                if n < 256 {
                    return Err(Self::err_unexpected());
                }
                (n.into(), 4)
            }
            _ => {
                return Err(Self::err_unexpected());
            }
        };
        Ok(pair)
    }
}

#[cfg(test)]
mod tests {
    use core::convert::TryFrom;
    use rcgen;
    use std::time::SystemTime;
    use webpki;

    use super::super::HEADER_SIZE;
    use super::*;
    use test_utils::certs::*;

    #[test]
    fn get_certificate_round_trip() {
        let msg = GetCertificate { slot: 0, offset: 0, length: 1000 };
        let mut buf = [0u8; 128];
        let _ = msg.write(&mut buf).unwrap();

        let msg2 = GetCertificate::parse_body(&buf[HEADER_SIZE..]).unwrap();
        assert_eq!(msg, msg2);
    }

    #[test]
    fn certificate_round_trip() {
        let mut msg = Certificate {
            slot: 0,
            portion_length: 800,
            remainder_length: 0,
            cert_chain: [0u8; MAX_CERT_CHAIN_SIZE],
        };
        // Ensure the remaining bytes are 0s, since they aren't part of the
        // simulated data.
        msg.cert_chain[800..]
            .copy_from_slice(&[0u8; MAX_CERT_CHAIN_SIZE - 800]);

        let mut buf = [0u8; 1200];
        let _ = msg.write(&mut buf).unwrap();

        let msg2 = Certificate::parse_body(&buf[HEADER_SIZE..]).unwrap();
        assert_eq!(msg, msg2);
    }

    #[test]
    fn roundtrip_cert_chain_no_intermediate() {
        let root_params = cert_params_ecdsa_p256_sha256(true, "Root");
        let root_cert = rcgen::Certificate::from_params(root_params).unwrap();
        let leaf_params = cert_params_ecdsa_p256_sha256(true, "Leaf");
        let leaf_cert = rcgen::Certificate::from_params(leaf_params).unwrap();
        let der = leaf_cert.serialize_der_with_signer(&root_cert).unwrap();

        let fake_hash = [0u8; 32];

        let cert_chain = CertificateChain::new(&fake_hash, &der);

        let mut buf = [0u8; 1024];
        let mut w = Writer::new("test", &mut buf);
        let size = cert_chain.write(&mut w).unwrap();

        let digest_size = 32;
        let cert_chain2 =
            CertificateChain::parse(&buf[..size], digest_size).unwrap();
        assert_eq!(cert_chain, cert_chain2);
    }

    #[test]
    fn roundtrip_cert_chain_2_intermediates() {
        let root_params = cert_params_ecdsa_p256_sha256(true, "Root");
        let root_cert = rcgen::Certificate::from_params(root_params).unwrap();
        let intermediate1_params =
            cert_params_ecdsa_p256_sha256(true, "intermediate1");
        let intermediate1_cert =
            rcgen::Certificate::from_params(intermediate1_params).unwrap();
        let intermediate2_params =
            cert_params_ecdsa_p256_sha256(true, "intermediate2");
        let intermediate2_cert =
            rcgen::Certificate::from_params(intermediate2_params).unwrap();
        let leaf_params = cert_params_ecdsa_p256_sha256(false, "Leaf");
        let leaf_cert = rcgen::Certificate::from_params(leaf_params).unwrap();

        let der_inter1 =
            intermediate1_cert.serialize_der_with_signer(&root_cert).unwrap();
        let der_inter2 = intermediate2_cert
            .serialize_der_with_signer(&intermediate1_cert)
            .unwrap();
        let der_leaf =
            leaf_cert.serialize_der_with_signer(&intermediate2_cert).unwrap();

        let fake_hash = [0u8; 32];

        let mut cert_chain = CertificateChain::new(&fake_hash, &der_leaf);
        cert_chain.append_intermediate_cert(&der_inter1).unwrap();
        cert_chain.append_intermediate_cert(&der_inter2).unwrap();

        let mut buf = [0u8; 2048];
        let mut w = Writer::new("test", &mut buf);
        let size = cert_chain.write(&mut w).unwrap();

        let digest_size = 32;
        let cert_chain2 =
            CertificateChain::parse(&buf[..size], digest_size).unwrap();
        assert_eq!(cert_chain, cert_chain2);
    }

    // This test is basically ensuring that `rcgen` generated cert chains can be parsed
    // and verified by `webpki`. This is a useful test for correctness, since
    // both crates are written by independent authors. It serves mostly as an
    // example of how to use webpki with DER encoded cert chains.
    #[test]
    fn example_webpki_verify_cert_chain() {
        let root_params = cert_params_ecdsa_p256_sha256(true, "Root");
        let root_cert = rcgen::Certificate::from_params(root_params).unwrap();
        let intermediate1_params =
            cert_params_ecdsa_p256_sha256(true, "intermediate1");
        let intermediate1_cert =
            rcgen::Certificate::from_params(intermediate1_params).unwrap();
        let intermediate2_params =
            cert_params_ecdsa_p256_sha256(true, "intermediate2");
        let intermediate2_cert =
            rcgen::Certificate::from_params(intermediate2_params).unwrap();
        let leaf_params = cert_params_ecdsa_p256_sha256(false, "Leaf");
        let leaf_cert = rcgen::Certificate::from_params(leaf_params).unwrap();

        let der_root = root_cert.serialize_der().unwrap();
        let der_inter1 =
            intermediate1_cert.serialize_der_with_signer(&root_cert).unwrap();
        let der_inter2 = intermediate2_cert
            .serialize_der_with_signer(&intermediate1_cert)
            .unwrap();
        let der_leaf =
            leaf_cert.serialize_der_with_signer(&intermediate2_cert).unwrap();

        let intermediate_certs = vec![&der_inter1[..], &der_inter2[..]];
        let trust_anchors =
            vec![webpki::TrustAnchor::try_from_cert_der(&der_root).unwrap()];
        let server_trust_anchors =
            webpki::TlsServerTrustAnchors(&trust_anchors);

        let end_entity_cert =
            webpki::EndEntityCert::try_from(&der_leaf[..]).unwrap();

        let seconds = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 10000;
        let time = webpki::Time::from_seconds_since_unix_epoch(seconds);

        end_entity_cert
            .verify_is_valid_tls_server_cert(
                &[&webpki::ECDSA_P256_SHA256],
                &server_trust_anchors,
                &intermediate_certs[..],
                time,
            )
            .unwrap();
    }
}
