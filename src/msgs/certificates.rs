// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use core::cmp::PartialEq;

use crate::config::{Slot, SlotState};

use super::common::DigestSize;
use super::encoding::{BufferFullError, ReadError, Reader, Writer};
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

    type WriteError = BufferFullError;

    fn write_body(&self, w: &mut Writer) -> Result<usize, BufferFullError> {
        w.put(self.slot)?;
        w.put_reserved(1)?;
        w.put_u16(self.offset)?;
        w.put_u16(self.length)
    }
}

impl GetCertificate {
    pub fn parse_body(buf: &[u8]) -> Result<GetCertificate, ReadError> {
        let mut r = Reader::new(buf);
        let slot = r.get_byte()?;
        r.skip_reserved(1)?;
        let offset = r.get_u16()?;
        let length = r.get_u16()?;

        Ok(GetCertificate { slot, offset, length })
    }
}

/// A CERTIFICATE message sent by a responder
#[derive(Debug, PartialEq, Eq)]
pub struct Certificate<'a> {
    pub slot_id: u8,
    pub portion_length: u16,
    pub remainder_length: u16,
    pub cert_chain: &'a Slot<'a>,
}

impl<'a> Msg for Certificate<'a> {
    const NAME: &'static str = "CERTIFICATE";

    const SPDM_VERSION: u8 = 0x11;

    const SPDM_CODE: u8 = 0x02;

    type WriteError = BufferFullError;

    fn write_body(&self, w: &mut Writer) -> Result<usize, BufferFullError> {
        w.put(self.slot_id)?;
        w.put_reserved(1)?;
        w.put_u16(self.portion_length)?;
        w.put_u16(self.remainder_length)?;
        w.extend(&self.cert_chain.as_slice()[..self.portion_length as usize])
    }
}

#[derive(Debug, PartialEq)]
pub enum ParseCertificateError {
    TooLarge,
    NoEmptyResponderSlot,

    // This is only temporary. Eventually we will support sending certificates
    // in chunks.
    PartialCertificatesNotSupported,
    Read(ReadError),
}

impl From<ReadError> for ParseCertificateError {
    fn from(e: ReadError) -> Self {
        ParseCertificateError::Read(e)
    }
}

impl<'a> Certificate<'a> {
    pub fn parse_body(
        buf: &[u8],
        responder_certs: &'a mut [Slot<'a>],
    ) -> Result<Certificate<'a>, ParseCertificateError> {
        let mut r = Reader::new(buf);
        let slot_id = r.get_byte()?;
        r.skip_reserved(1)?;

        // Find the proper empty slot.
        // In the future we may allow overwriting full slots, but not now.
        let slot = responder_certs.iter_mut().find(|slot| {
            slot.state == SlotState::Empty && slot_id == slot.id()
        });
        if slot.is_none() {
            return Err(ParseCertificateError::NoEmptyResponderSlot);
        }
        let mut slot = slot.unwrap();

        let portion_length = r.get_u16()?;
        if portion_length as usize > slot.capacity() {
            return Err(ParseCertificateError::TooLarge);
        }
        let remainder_length = r.get_u16()?;
        if remainder_length != 0 {
            return Err(ParseCertificateError::PartialCertificatesNotSupported);
        }
        slot.fill(&mut r, usize::from(portion_length))?;
        Ok(Certificate {
            slot_id,
            portion_length,
            remainder_length,
            cert_chain: slot,
        })
    }
}

const MAX_CERT_CHAIN_DEPTH: usize = 10;

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

#[derive(Debug)]
pub struct MaxCertChainDepthExceededError;

#[derive(Debug, PartialEq)]
pub enum WriteCertificateChainError {
    MaxSizeExceeded,
    BufferFull,
}

impl From<BufferFullError> for WriteCertificateChainError {
    fn from(_: BufferFullError) -> Self {
        WriteCertificateChainError::BufferFull
    }
}

#[derive(Debug, PartialEq)]
pub enum ParseCertificateChainError {
    BadDerEncoding,
    LengthMismatch,
    MaxDepthExceeded,
    Read(ReadError),
}

impl From<ReadError> for ParseCertificateChainError {
    fn from(e: ReadError) -> Self {
        ParseCertificateChainError::Read(e)
    }
}

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
    ) -> Result<(), MaxCertChainDepthExceededError> {
        if self.num_intermediate_certs as usize == MAX_CERT_CHAIN_DEPTH {
            return Err(MaxCertChainDepthExceededError);
        }
        self.intermediate_certs[self.num_intermediate_certs as usize] = cert;
        self.num_intermediate_certs += 1;
        Ok(())
    }

    /// Serialize a certificate chain via a Writer
    pub fn write(
        &self,
        w: &mut Writer,
    ) -> Result<usize, WriteCertificateChainError> {
        let length = 4
            + self.root_hash.len()
            + (0..self.num_intermediate_certs as usize)
                .fold(0, |acc, i| acc + self.intermediate_certs[i].len())
            + self.leaf_cert.len();
        if length > 65535 {
            return Err(WriteCertificateChainError::MaxSizeExceeded);
        }
        w.put_u16(length as u16)?;
        w.put_reserved(2)?;
        w.extend(self.root_hash)?;
        for i in 0..self.num_intermediate_certs as usize {
            w.extend(self.intermediate_certs[i])?;
        }
        w.extend(self.leaf_cert)?;
        Ok(w.offset())
    }

    /// Deserialize a CertificateChain into `buf` given `digest_size`.
    ///
    /// `digest_size` must match the size of the digest used for the root hash.
    pub fn parse(
        buf: &'a [u8],
        digest_size: DigestSize,
    ) -> Result<CertificateChain<'a>, ParseCertificateChainError> {
        let mut r = Reader::new(buf);
        let length = r.get_u16()?;
        if length as usize != buf.len() {
            return Err(ParseCertificateChainError::LengthMismatch);
        }
        r.skip_reserved(2)?;
        let offset = r.byte_offset();
        r.skip_ignored(digest_size.into())?;
        let root_hash = &buf[offset..offset + usize::from(digest_size)];

        let mut num_intermediate_certs = 0u8;
        let mut intermediate_certs = [buf; MAX_CERT_CHAIN_DEPTH];

        // parse DER headers of certs
        let leaf_offset = loop {
            let offset = r.byte_offset();
            let (length, header_size) = Self::read_cert_size(&mut r)?;
            if length > r.remaining() {
                return Err(ParseCertificateChainError::LengthMismatch);
            }
            if length == r.remaining() {
                // we found the end entity cert
                break offset;
            }
            if num_intermediate_certs as usize == MAX_CERT_CHAIN_DEPTH {
                return Err(ParseCertificateChainError::MaxDepthExceeded);
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

    // Read the size of the cert from the DER encoded header along with the
    // number of bytes read (2 - 4).
    //
    // If the high order bit of the first byte is set to zero then the length
    // is encoded in the seven remaining bits of that byte. Otherwise, those
    // seven bits represent the number of bytes used to encode the length in big
    // endian format.
    fn read_cert_size(
        r: &mut Reader,
    ) -> Result<(usize, usize), ParseCertificateChainError> {
        // Skip the sequence byte
        assert_eq!(r.get_byte()?, 0x30);

        let pair = match r.get_byte()? {
            n if (n & 0x80) == 0 => (n.into(), 2),
            0x81 => {
                let n = r.get_byte()?;
                if n < 128 {
                    return Err(ParseCertificateChainError::BadDerEncoding);
                }
                (n.into(), 3)
            }
            0x82 => {
                let high = r.get_byte()? as usize;
                let low = r.get_byte()? as usize;
                let n = (high << 8) | low;
                if n < 256 {
                    return Err(ParseCertificateChainError::BadDerEncoding);
                }
                (n.into(), 4)
            }
            _ => {
                return Err(ParseCertificateChainError::BadDerEncoding);
            }
        };
        Ok(pair)
    }
}

#[cfg(test)]
mod tests {
    use core::convert::TryFrom;
    use rcgen;
    use tinyvec::SliceVec;

    #[cfg(feature = "webpki")]
    use std::time::SystemTime;
    #[cfg(feature = "webpki")]
    use webpki;

    use super::super::HEADER_SIZE;
    use super::*;
    use crate::msgs::algorithms::BaseAsymAlgo;
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
        let full_cert_chain = [0xDEu8; 800];
        let empty_cert_chain = [0x0; 1000];

        let responder_filled_slot = Slot::new(
            SlotState::Full,
            0,
            BaseAsymAlgo::ECDSA_ECC_NIST_P256,
            SliceVec::from(full_cert_chain),
        );

        let responder_empty_slot = Slot::new(
            SlotState::Empty,
            0,
            BaseAsymAlgo::ECDSA_ECC_NIST_P256,
            SliceVec::from(empty_cert_chain),
        );
        responder_empty_slot.clear();
        let responder_certs = &mut [&responder_empty_slot];

        let mut msg = Certificate {
            slot_id: 0,
            portion_length: 800,
            remainder_length: 0,
            cert_chain: &responder_filled_slot,
        };

        let mut buf = [0u8; 1000];
        let _ = msg.write(&mut buf).unwrap();

        let msg2 =
            Certificate::parse_body(&buf[HEADER_SIZE..], responder_certs)
                .unwrap();
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
        let mut w = Writer::new(&mut buf);
        let size = cert_chain.write(&mut w).unwrap();

        let digest_size = DigestSize::try_from(32).unwrap();
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
        let mut w = Writer::new(&mut buf);
        let size = cert_chain.write(&mut w).unwrap();

        let digest_size = DigestSize::try_from(32).unwrap();
        let cert_chain2 =
            CertificateChain::parse(&buf[..size], digest_size).unwrap();
        assert_eq!(cert_chain, cert_chain2);
    }

    // This test is basically ensuring that `rcgen` generated cert chains can be parsed
    // and verified by `webpki`. This is a useful test for correctness, since
    // both crates are written by independent authors. It serves mostly as an
    // example of how to use webpki with DER encoded cert chains.
    #[cfg(feature = "webpki")]
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
