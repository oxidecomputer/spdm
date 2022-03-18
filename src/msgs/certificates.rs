// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use core::cmp::PartialEq;
use core::convert::TryFrom;

use crate::{Slot, SlotState};

use super::common::{DigestBuf, DigestSize};
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
#[derive(Debug, PartialEq)]
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

    type WriteError = WriteCertificateChainError;

    fn write_body(
        &self,
        w: &mut Writer,
    ) -> Result<usize, WriteCertificateChainError> {
        w.put(self.slot_id)?;
        w.put_reserved(1)?;
        w.put_u16(self.portion_length)?;
        w.put_u16(self.remainder_length)?;
        self.write_cert_chain(w)
    }
}

#[derive(Debug, PartialEq)]
pub enum ParseCertificateError {
    TooLarge,

    // The received certificate does not match the given slot id
    SlotIdMismatch,

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
        digest_size: DigestSize,
        slot: &'a mut Slot<'a>,
    ) -> Result<Certificate<'a>, ParseCertificateError> {
        let mut r = Reader::new(buf);
        let slot_id = r.get_byte()?;
        r.skip_reserved(1)?;

        if slot.id() != slot_id {
            return Err(ParseCertificateError::SlotIdMismatch);
        }

        let portion_length = r.get_u16()?;
        if portion_length as usize > slot.capacity() {
            return Err(ParseCertificateError::TooLarge);
        }
        let remainder_length = r.get_u16()?;
        if remainder_length != 0 {
            return Err(ParseCertificateError::PartialCertificatesNotSupported);
        }
        Self::read_cert_chain(&mut r, digest_size, slot)?;
        Ok(Certificate {
            slot_id,
            portion_length,
            remainder_length,
            cert_chain: slot,
        })
    }

    // Parse a cert chain off the wire as described in Table 28 of SPDM 1.2 spec
    //
    // A CertificateChain parses into a Slot<'a> with SlotState::Full(_)
    fn read_cert_chain(
        r: &mut Reader,
        digest_size: DigestSize,
        slot: &'a mut Slot<'a>,
    ) -> Result<(), ReadError> {
        let length = usize::from(r.get_u16()?);
        r.skip_reserved(2)?;
        let root_hash = DigestBuf::read(digest_size, r)?;
        let cert_chain_len = length - 4 - usize::from(digest_size);
        slot.fill(&mut r, cert_chain_len, root_hash)?;
        Ok(())
    }

    fn write_cert_chain(
        &self,
        w: &mut Writer,
    ) -> Result<usize, WriteCertificateChainError> {
        if let SlotState::Full(digest_buf) = &self.cert_chain.state {
            let length = 4 + digest_buf.len() + self.cert_chain.len();
            if length > 65536 {
                return Err(WriteCertificateChainError::MaxSizeExceeded);
            }
            w.put_u16(u16::try_from(length).unwrap())?;
            w.put_reserved(2)?;
            w.extend(digest_buf.as_ref())?;
            w.extend(self.cert_chain.as_slice())?;
            Ok(w.offset())
        } else {
            // RETURN an error
            Err(WriteCertificateChainError::SlotIsEmpty)
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum WriteCertificateChainError {
    SlotIsEmpty,
    MaxSizeExceeded,
    BufferFull,
}

impl From<BufferFullError> for WriteCertificateChainError {
    fn from(_: BufferFullError) -> Self {
        WriteCertificateChainError::BufferFull
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
