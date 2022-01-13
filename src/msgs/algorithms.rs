// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::encoding::{ReadError, ReadErrorKind, Reader, WriteError, Writer};
use super::Msg;

use bitflags::bitflags;
use core::str::FromStr;

bitflags! {
   /// The base asymetric signing algorithm defined in the SPDM spec
   #[derive(Default)]
   pub struct BaseAsymAlgo: u32 {
       const RSASSA_2048 = 0x1;
       const RSAPSS_2048 = 0x2;
       const RSASSA_3072 = 0x4;
       const RSAPSS_3072 = 0x8;
       const ECDSA_ECC_NIST_P256 = 0x10;
       const RSASSA_4096 = 0x20;
       const RSAPSS_4096 = 0x40;
       const ECDSA_ECC_NIST_P384 = 0x80;
       const ECDSA_ECC_NIST_P521 = 0x100;
   }
}

impl BaseAsymAlgo {
    // The signature size in bytes of the "Raw" or "Fixed" signature.
    pub fn get_signature_size(&self) -> u16 {
        use BaseAsymAlgo as A;
        match *self {
            A::RSASSA_2048 | A::RSAPSS_2048 => 256,
            A::RSASSA_3072 | A::RSAPSS_3072 => 384,
            A::ECDSA_ECC_NIST_P256 => 64,
            A::RSASSA_4096 | A::RSAPSS_4096 => 512,
            A::ECDSA_ECC_NIST_P384 => 96,
            A::ECDSA_ECC_NIST_P521 => 132,
            _ => unreachable!(),
        }
    }
}

impl FromStr for BaseAsymAlgo {
    type Err = ReadError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let algo = match s {
            "RSASSA_2048" => BaseAsymAlgo::RSASSA_2048,
            "RSAPSS_2048" => BaseAsymAlgo::RSAPSS_2048,
            "RSASSA_3072" => BaseAsymAlgo::RSASSA_3072,
            "RSAPSS_3072" => BaseAsymAlgo::RSAPSS_3072,
            "ECDSA_ECC_NIST_P256" => BaseAsymAlgo::ECDSA_ECC_NIST_P256,
            "RSASSA_4096" => BaseAsymAlgo::RSASSA_4096,
            "RSAPSS_4096" => BaseAsymAlgo::RSAPSS_4096,
            "ECDSA_ECC_NIST_P384" => BaseAsymAlgo::ECDSA_ECC_NIST_P384,
            "ECDSA_ECC_NIST_P521" => BaseAsymAlgo::ECDSA_ECC_NIST_P521,
            _ => {
                return Err(ReadError::new(
                    "BaseAsymAlgo",
                    ReadErrorKind::UnexpectedValue,
                ))
            }
        };
        Ok(algo)
    }
}

bitflags! {
    /// The base hash algorithm defined in the SPDM spec.
    #[derive(Default)]
    pub struct BaseHashAlgo: u32 {
        const SHA_256 = 0x1;
        const SHA_384 = 0x2;
        const SHA_512  = 0x4;
        const SHA3_256 = 0x8;
        const SHA3_384 = 0x10;
        const SHA3_512 = 0x20;
    }
}

impl BaseHashAlgo {
    /// The size of a digest in bytes
    pub fn get_digest_size(&self) -> u8 {
        use BaseHashAlgo as H;
        match *self {
            H::SHA_256 | H::SHA3_256 => 32,
            H::SHA_384 | H::SHA3_384 => 48,
            H::SHA_512 | H::SHA3_512 => 64,
            _ => unreachable!(),
        }
    }
}

impl FromStr for BaseHashAlgo {
    type Err = ReadError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let algo = match s {
            "SHA_256" => BaseHashAlgo::SHA_256,
            "SHA_384" => BaseHashAlgo::SHA_384,
            "SHA_512" => BaseHashAlgo::SHA_512,
            "SHA3_256" => BaseHashAlgo::SHA3_256,
            "SHA3_384" => BaseHashAlgo::SHA3_384,
            "SHA3_512" => BaseHashAlgo::SHA3_512,
            _ => {
                return Err(ReadError::new(
                    "BaseHashAlgo",
                    ReadErrorKind::UnexpectedValue,
                ))
            }
        };
        Ok(algo)
    }
}

bitflags! {
    /// This is the `MeasurementSpecification` field from the Measurement block
    /// format in seciton 10.11.1 of the SPDM 1.1 spec. Only 1 bit is valid at
    /// a time. Currently DMTF is the only valid value.
    #[derive(Default)]
    pub struct MeasurementSpec: u8 {
        const DMTF = 0x1;
    }
}

// SPDM Parameters in AlgorithmRequests
pub trait AlgorithmConstants {
    const TYPE: u8;
    const FIXED_ALG_COUNT: u8;
}

bitflags! {
    /// The base key-exchange algorithms in the SPDM spec.
    #[derive(Default)]
    pub struct DheFixedAlgorithms: u16 {
       const FFDHE_2048 = 0x1;
       const FFDHE_3072 = 0x2;
       const FFDHE_4096 = 0x4;
       const SECP_256_R1 = 0x8;
       const SECP_384_R1 = 0x10;
       const SECP_521_R1 = 0x20;
    }
}

/// All defined key-exchange algorithms
///
/// We don't currently support any external algorithms.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct DheAlgorithm {
    pub supported: DheFixedAlgorithms,
}

impl AlgorithmConstants for DheAlgorithm {
    const TYPE: u8 = 0x2;
    const FIXED_ALG_COUNT: u8 = 2;
}

bitflags! {
    /// Base AEAD algorithms defined for use in the SPDM spec
    #[derive(Default)]
    pub struct AeadFixedAlgorithms: u16 {
        const AES_128_GCM = 0x1;
        const AES_256_GCM = 0x2;
        const CHACHA20_POLY1305 = 0x4;
    }
}

/// All defined AEAD algorithms.
///
/// We don't currently support any external algorithms
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct AeadAlgorithm {
    pub supported: AeadFixedAlgorithms,
}

impl AlgorithmConstants for AeadAlgorithm {
    const TYPE: u8 = 0x3;
    const FIXED_ALG_COUNT: u8 = 2;
}

bitflags! {
    /// Base asymmetric signing algorithms for use by the requester
    #[derive(Default)]
    pub struct ReqBaseAsymFixedAlgorithms: u16 {
       const RSASSA_2048 = 0x1;
       const RSAPSS_2048 = 0x2;
       const RSASSA_3072 = 0x4;
       const RSAPSS_3072 = 0x8;
       const ECDSA_ECC_NIST_P256 = 0x10;
       const RSASSA_4096 = 0x20;
       const RSAPSS_4096 = 0x40;
       const ECDSA_ECC_NIST_P384 = 0x80;
       const ECDSA_ECC_NIST_P521 = 0x100;
    }
}

/// All defined base digital signature algorithms
///
/// We don't currently support any external algorithms
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReqBaseAsymAlgorithm {
    pub supported: ReqBaseAsymFixedAlgorithms,
}

impl AlgorithmConstants for ReqBaseAsymAlgorithm {
    const TYPE: u8 = 0x4;
    const FIXED_ALG_COUNT: u8 = 2;
}

bitflags! {
    #[derive(Default)]
    pub struct KeyScheduleFixedAlgorithms: u16 {
        const SPDM = 0x1;
    }
}

// We don't currently support any external algorithms
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyScheduleAlgorithm {
    pub supported: KeyScheduleFixedAlgorithms,
}

impl AlgorithmConstants for KeyScheduleAlgorithm {
    const TYPE: u8 = 0x5;
    const FIXED_ALG_COUNT: u8 = 2;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// An AlgorithmRequest structure that is part of the NEGOTIATE_ALGORITHMS msg
pub enum AlgorithmRequest {
    Dhe(DheAlgorithm),
    Aead(AeadAlgorithm),
    ReqBaseAsym(ReqBaseAsymAlgorithm),
    KeySchedule(KeyScheduleAlgorithm),
}

// This is only to be able to fill in arrays
impl Default for AlgorithmRequest {
    fn default() -> Self {
        AlgorithmRequest::Dhe(DheAlgorithm { supported: Default::default() })
    }
}

impl AlgorithmRequest {
    /// Return the number of bytes required to fit fixed spdm algorithm options
    /// for the given algorithm type.
    pub fn fixed_algo_count(&self) -> u8 {
        match self {
            AlgorithmRequest::Dhe(_) => DheAlgorithm::FIXED_ALG_COUNT,
            AlgorithmRequest::Aead(_) => AeadAlgorithm::FIXED_ALG_COUNT,
            AlgorithmRequest::ReqBaseAsym(_) => {
                ReqBaseAsymAlgorithm::FIXED_ALG_COUNT
            }
            AlgorithmRequest::KeySchedule(_) => {
                KeyScheduleAlgorithm::FIXED_ALG_COUNT
            }
        }
    }

    /// Serialize an AlgorithmRequest structure
    pub fn write(&self, w: &mut Writer) -> Result<usize, WriteError> {
        match &self {
            AlgorithmRequest::Dhe(algo) => {
                w.put(DheAlgorithm::TYPE)?;
                w.put(DheAlgorithm::FIXED_ALG_COUNT << 4)?;
                w.put_u16(algo.supported.bits())?;
            }
            AlgorithmRequest::Aead(algo) => {
                w.put(AeadAlgorithm::TYPE)?;
                w.put(AeadAlgorithm::FIXED_ALG_COUNT << 4)?;
                w.put_u16(algo.supported.bits())?;
            }
            AlgorithmRequest::ReqBaseAsym(algo) => {
                w.put(ReqBaseAsymAlgorithm::TYPE)?;
                w.put(ReqBaseAsymAlgorithm::FIXED_ALG_COUNT << 4)?;
                w.put_u16(algo.supported.bits())?;
            }
            AlgorithmRequest::KeySchedule(algo) => {
                w.put(KeyScheduleAlgorithm::TYPE)?;
                w.put(KeyScheduleAlgorithm::FIXED_ALG_COUNT << 4)?;
                w.put_u16(algo.supported.bits())?;
            }
        }
        Ok(w.offset())
    }

    // Deserialize an AlgorithmRequest structure
    pub fn read(
        msg_name: &'static str,
        r: &mut Reader,
    ) -> Result<AlgorithmRequest, ReadError> {
        match r.get_byte()? {
            DheAlgorithm::TYPE => {
                let ext_count = r.get_bits(4)? as usize;
                let fixed_count = r.get_bits(4)?;
                if fixed_count != DheAlgorithm::FIXED_ALG_COUNT {
                    return Err(ReadError::new(
                        msg_name,
                        ReadErrorKind::UnexpectedValue,
                    ));
                }
                let supported = r.get_u16()?;
                let supported = DheFixedAlgorithms::from_bits(supported)
                    .ok_or_else(|| {
                        ReadError::new(msg_name, ReadErrorKind::InvalidBitsSet)
                    })?;
                r.skip_ignored(4 * ext_count)?;
                Ok(AlgorithmRequest::Dhe(DheAlgorithm { supported }))
            }

            AeadAlgorithm::TYPE => {
                let ext_count = r.get_bits(4)? as usize;
                let fixed_count = r.get_bits(4)?;
                if fixed_count != AeadAlgorithm::FIXED_ALG_COUNT {
                    return Err(ReadError::new(
                        msg_name,
                        ReadErrorKind::UnexpectedValue,
                    ));
                }
                let supported = r.get_u16()?;
                let supported = AeadFixedAlgorithms::from_bits(supported)
                    .ok_or_else(|| {
                        ReadError::new(msg_name, ReadErrorKind::InvalidBitsSet)
                    })?;
                r.skip_ignored(4 * ext_count)?;
                Ok(AlgorithmRequest::Aead(AeadAlgorithm { supported }))
            }

            ReqBaseAsymAlgorithm::TYPE => {
                let ext_count = r.get_bits(4)? as usize;
                let fixed_count = r.get_bits(4)?;
                if fixed_count != ReqBaseAsymAlgorithm::FIXED_ALG_COUNT {
                    return Err(ReadError::new(
                        msg_name,
                        ReadErrorKind::UnexpectedValue,
                    ));
                }
                let supported = r.get_u16()?;
                let supported =
                    ReqBaseAsymFixedAlgorithms::from_bits(supported)
                        .ok_or_else(|| {
                            ReadError::new(
                                msg_name,
                                ReadErrorKind::InvalidBitsSet,
                            )
                        })?;
                r.skip_ignored(4 * ext_count)?;
                Ok(AlgorithmRequest::ReqBaseAsym(ReqBaseAsymAlgorithm {
                    supported,
                }))
            }

            KeyScheduleAlgorithm::TYPE => {
                let ext_count = r.get_bits(4)? as usize;
                let fixed_count = r.get_bits(4)?;
                if fixed_count != KeyScheduleAlgorithm::FIXED_ALG_COUNT {
                    return Err(ReadError::new(
                        msg_name,
                        ReadErrorKind::UnexpectedValue,
                    ));
                }
                let supported = r.get_u16()?;
                let supported =
                    KeyScheduleFixedAlgorithms::from_bits(supported)
                        .ok_or_else(|| {
                            ReadError::new(
                                msg_name,
                                ReadErrorKind::InvalidBitsSet,
                            )
                        })?;
                r.skip_ignored(4 * ext_count)?;
                Ok(AlgorithmRequest::KeySchedule(KeyScheduleAlgorithm {
                    supported,
                }))
            }

            _ => Err(ReadError::new(msg_name, ReadErrorKind::UnexpectedValue)),
        }
    }
}

/// This corresponds to the number of `RequestAlgorithm` variants
pub const MAX_ALGORITHM_REQUESTS: usize = 4;

/// The NEGOTIATE_ALGORITHMS SPDM request
///
/// For simplicity and expediency we don't support any extended algorithms yet
/// in this implementation. This corresponds to the ExtAsym and ExtHash fields
/// in the spec, as well as the fields related to their sizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiateAlgorithms {
    pub measurement_spec: MeasurementSpec,
    pub base_asym_algo: BaseAsymAlgo,
    pub base_hash_algo: BaseHashAlgo,
    pub num_algorithm_requests: u8, //Param1 in spec
    pub algorithm_requests: [AlgorithmRequest; MAX_ALGORITHM_REQUESTS],
}

impl Msg for NegotiateAlgorithms {
    const NAME: &'static str = "NEGOTIATE_ALGORITHMS";

    const SPDM_VERSION: u8 = 0x11;

    const SPDM_CODE: u8 = 0xE3;

    fn write_body(&self, w: &mut Writer) -> Result<usize, WriteError> {
        w.put(self.num_algorithm_requests)?;
        w.put_reserved(1)?;
        w.put_u16(self.msg_length())?;
        w.put(self.measurement_spec.bits())?;
        w.put_reserved(1)?;
        w.put_u32(self.base_asym_algo.bits())?;
        w.put_u32(self.base_hash_algo.bits())?;
        w.put_reserved(12)?;
        w.put(0)?; // ExtAsymCount
        w.put(0)?; // ExtHashCount
        w.put_reserved(2)?;
        self.write_algorithm_requests(w)
    }
}

impl NegotiateAlgorithms {
    pub fn parse_body(buf: &[u8]) -> Result<NegotiateAlgorithms, ReadError> {
        let mut r = Reader::new(Self::NAME, buf);
        let num_requests = r.get_byte()?;
        if num_requests as usize > MAX_ALGORITHM_REQUESTS {
            return Err(ReadError::new(
                Self::NAME,
                ReadErrorKind::ImplementationLimitReached,
            ));
        }

        r.skip_reserved(1)?;

        // TODO: Use this for validation?
        let length = r.get_u16()?;
        if length > 128 {
            return Err(ReadError::new(
                Self::NAME,
                ReadErrorKind::SpdmLimitReached,
            ));
        }
        let spec = r.get_byte()?;
        let measurement_spec =
            MeasurementSpec::from_bits(spec).ok_or_else(|| {
                ReadError::new(Self::NAME, ReadErrorKind::InvalidBitsSet)
            })?;

        r.skip_reserved(1)?;

        let algo = r.get_u32()?;
        let base_asym_algo =
            BaseAsymAlgo::from_bits(algo).ok_or_else(|| {
                ReadError::new(Self::NAME, ReadErrorKind::InvalidBitsSet)
            })?;

        let algo = r.get_u32()?;
        let base_hash_algo =
            BaseHashAlgo::from_bits(algo).ok_or_else(|| {
                ReadError::new(Self::NAME, ReadErrorKind::InvalidBitsSet)
            })?;

        r.skip_reserved(12)?;

        // A responder will never select these algorithms, as they are not
        // currently supported. However, the data must still be properly skipped
        // over.
        let ext_asym_count = r.get_byte()? as usize;
        let ext_hash_count = r.get_byte()? as usize;

        r.skip_reserved(2)?;

        // Skip over the extended algorithms, as they are not supported.
        r.skip_ignored(ext_asym_count * 4)?;
        r.skip_ignored(ext_hash_count * 4)?;

        let mut requests =
            [AlgorithmRequest::default(); MAX_ALGORITHM_REQUESTS];
        Self::read_algorithm_requests(&mut r, num_requests, &mut requests)?;

        Ok(NegotiateAlgorithms {
            measurement_spec,
            base_asym_algo,
            base_hash_algo,
            num_algorithm_requests: num_requests,
            algorithm_requests: requests,
        })
    }

    fn read_algorithm_requests(
        r: &mut Reader,
        num_requests: u8,
        requests: &mut [AlgorithmRequest; MAX_ALGORITHM_REQUESTS],
    ) -> Result<(), ReadError> {
        for i in 0..num_requests as usize {
            requests[i] = AlgorithmRequest::read(Self::NAME, r)?;
        }
        Ok(())
    }

    fn msg_length(&self) -> u16 {
        self.algorithm_requests[0..self.num_algorithm_requests as usize]
            .iter()
            .fold(32, |acc, algo_req| {
                acc + 2 + algo_req.fixed_algo_count() as u16
            })
    }

    fn write_algorithm_requests(
        &self,
        w: &mut Writer,
    ) -> Result<usize, WriteError> {
        for i in 0..self.num_algorithm_requests as usize {
            self.algorithm_requests[i].write(w)?;
        }
        Ok(w.offset())
    }
}

// The format is the same for both messages
pub type AlgorithmResponse = AlgorithmRequest;

/// The algorithms selected by the responder as part of negotiation
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Algorithms {
    pub measurement_spec_selected: MeasurementSpec,
    pub measurement_hash_algo_selected: BaseHashAlgo,
    pub base_asym_algo_selected: BaseAsymAlgo,
    pub base_hash_algo_selected: BaseHashAlgo,
    pub num_algorithm_responses: u8, // Param1 in spec
    pub algorithm_responses: [AlgorithmResponse; MAX_ALGORITHM_REQUESTS],
}

impl Msg for Algorithms {
    const NAME: &'static str = "ALGORITHMS";

    const SPDM_VERSION: u8 = 0x11;

    const SPDM_CODE: u8 = 0x63;

    fn write_body(&self, w: &mut Writer) -> Result<usize, WriteError> {
        w.put(self.num_algorithm_responses)?;
        w.put_reserved(1)?;
        w.put_u16(self.msg_length())?;
        w.put(self.measurement_spec_selected.bits())?;
        w.put_reserved(1)?;
        w.put_u32(self.measurement_hash_algo_selected.bits())?;
        w.put_u32(self.base_asym_algo_selected.bits())?;
        w.put_u32(self.base_hash_algo_selected.bits())?;
        w.put_reserved(12)?;

        // External Algorithms not supported
        w.put(0)?; // ExtAsymSelCount
        w.put(0)?; // ExtHashSelCount

        w.put_reserved(2)?;

        self.write_algorithm_responses(w)
    }
}

impl Algorithms {
    pub fn parse_body(buf: &[u8]) -> Result<Algorithms, ReadError> {
        let mut r = Reader::new(Self::NAME, buf);
        let num_responses = r.get_byte()?;
        if num_responses as usize > MAX_ALGORITHM_REQUESTS {
            return Err(ReadError::new(
                Self::NAME,
                ReadErrorKind::ImplementationLimitReached,
            ));
        }

        r.skip_reserved(1)?;

        // TODO: Use this for validation?
        let _length = r.get_u16()?;

        let selection = r.get_byte()?;
        let measurement_spec_selected = MeasurementSpec::from_bits(selection)
            .ok_or_else(|| {
            ReadError::new(Self::NAME, ReadErrorKind::InvalidBitsSet)
        })?;
        if measurement_spec_selected.bits().count_ones() != 1 {
            return Self::too_many_bits();
        }

        r.skip_reserved(1)?;

        let selection = r.get_u32()?;
        let measurement_hash_algo_selected = BaseHashAlgo::from_bits(selection)
            .ok_or_else(|| {
                ReadError::new(Self::NAME, ReadErrorKind::InvalidBitsSet)
            })?;
        if measurement_hash_algo_selected.bits().count_ones() != 1 {
            return Self::too_many_bits();
        }

        let selection = r.get_u32()?;
        let base_asym_algo_selected = BaseAsymAlgo::from_bits(selection)
            .ok_or_else(|| {
                ReadError::new(Self::NAME, ReadErrorKind::InvalidBitsSet)
            })?;
        if base_asym_algo_selected.bits().count_ones() != 1 {
            return Self::too_many_bits();
        }

        let selection = r.get_u32()?;
        let base_hash_algo_selected = BaseHashAlgo::from_bits(selection)
            .ok_or_else(|| {
                ReadError::new(Self::NAME, ReadErrorKind::InvalidBitsSet)
            })?;
        if base_hash_algo_selected.bits().count_ones() != 1 {
            return Self::too_many_bits();
        }

        r.skip_reserved(12)?;

        // Exxternal algorithms are not currently supported
        r.skip_reserved(1)?; // ExtAsymCount must be 0
        r.skip_reserved(1)?; // ExtHashCount must be 0

        r.skip_reserved(2)?;

        let mut responses =
            [AlgorithmResponse::default(); MAX_ALGORITHM_REQUESTS];
        Self::read_algorithm_responses(&mut r, num_responses, &mut responses)?;

        Ok(Algorithms {
            measurement_spec_selected,
            measurement_hash_algo_selected,
            base_asym_algo_selected,
            base_hash_algo_selected,
            num_algorithm_responses: num_responses,
            algorithm_responses: responses,
        })
    }

    fn msg_length(&self) -> u16 {
        self.algorithm_responses[0..self.num_algorithm_responses as usize]
            .iter()
            .fold(36, |acc, algo_req| {
                acc + 2 + algo_req.fixed_algo_count() as u16
            })
    }

    fn write_algorithm_responses(
        &self,
        w: &mut Writer,
    ) -> Result<usize, WriteError> {
        for i in 0..self.num_algorithm_responses as usize {
            self.algorithm_responses[i].write(w)?;
        }
        Ok(w.offset())
    }

    fn read_algorithm_responses(
        r: &mut Reader,
        num_responses: u8,
        responses: &mut [AlgorithmResponse; MAX_ALGORITHM_REQUESTS],
    ) -> Result<(), ReadError> {
        for i in 0..num_responses as usize {
            responses[i] = AlgorithmResponse::read(Self::NAME, r)?;
            Self::ensure_only_one_bit_set(&responses[i])?;
        }
        Ok(())
    }

    fn ensure_only_one_bit_set(
        response: &AlgorithmResponse,
    ) -> Result<(), ReadError> {
        match response {
            AlgorithmResponse::Dhe(algo) => {
                if algo.supported.bits().count_ones() != 1 {
                    Self::too_many_bits()?;
                }
            }
            AlgorithmResponse::Aead(algo) => {
                if algo.supported.bits().count_ones() != 1 {
                    Self::too_many_bits()?;
                }
            }
            AlgorithmResponse::ReqBaseAsym(algo) => {
                if algo.supported.bits().count_ones() != 1 {
                    Self::too_many_bits()?;
                }
            }
            AlgorithmResponse::KeySchedule(algo) => {
                if algo.supported.bits().count_ones() != 1 {
                    Self::too_many_bits()?;
                }
            }
        }
        Ok(())
    }

    fn too_many_bits() -> Result<Algorithms, ReadError> {
        Err(ReadError::new(Self::NAME, ReadErrorKind::TooManyBitsSet))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn algo_requests(
        requests: &mut [AlgorithmRequest; MAX_ALGORITHM_REQUESTS],
    ) {
        requests[0] = AlgorithmRequest::Dhe(DheAlgorithm {
            supported: DheFixedAlgorithms::FFDHE_3072
                | DheFixedAlgorithms::SECP_384_R1,
        });
        requests[1] = AlgorithmRequest::Aead(AeadAlgorithm {
            supported: AeadFixedAlgorithms::AES_256_GCM
                | AeadFixedAlgorithms::CHACHA20_POLY1305,
        });
        requests[2] = AlgorithmRequest::ReqBaseAsym(ReqBaseAsymAlgorithm {
            supported: ReqBaseAsymFixedAlgorithms::ECDSA_ECC_NIST_P384
                | ReqBaseAsymFixedAlgorithms::ECDSA_ECC_NIST_P256,
        });
        requests[3] = AlgorithmRequest::KeySchedule(KeyScheduleAlgorithm {
            supported: KeyScheduleFixedAlgorithms::SPDM,
        });
    }

    // The difference between a request and response is that a response always
    // only has one bit set. The responder makes a choice!
    pub fn algo_responses(
        responses: &mut [AlgorithmResponse; MAX_ALGORITHM_REQUESTS],
    ) {
        responses[0] = AlgorithmResponse::Dhe(DheAlgorithm {
            supported: DheFixedAlgorithms::FFDHE_3072,
        });
        responses[1] = AlgorithmResponse::Aead(AeadAlgorithm {
            supported: AeadFixedAlgorithms::AES_256_GCM,
        });
        responses[2] = AlgorithmResponse::ReqBaseAsym(ReqBaseAsymAlgorithm {
            supported: ReqBaseAsymFixedAlgorithms::ECDSA_ECC_NIST_P384,
        });
        responses[3] = AlgorithmResponse::KeySchedule(KeyScheduleAlgorithm {
            supported: KeyScheduleFixedAlgorithms::SPDM,
        });
    }

    pub fn negotiate_algo(
        requests: [AlgorithmRequest; MAX_ALGORITHM_REQUESTS],
    ) -> NegotiateAlgorithms {
        NegotiateAlgorithms {
            measurement_spec: MeasurementSpec::DMTF,
            base_asym_algo: BaseAsymAlgo::ECDSA_ECC_NIST_P256
                | BaseAsymAlgo::ECDSA_ECC_NIST_P521,
            base_hash_algo: BaseHashAlgo::SHA_384 | BaseHashAlgo::SHA3_384,
            num_algorithm_requests: 4,
            algorithm_requests: requests,
        }
    }

    pub fn algo(
        responses: [AlgorithmResponse; MAX_ALGORITHM_REQUESTS],
    ) -> Algorithms {
        Algorithms {
            measurement_spec_selected: MeasurementSpec::DMTF,
            measurement_hash_algo_selected: BaseHashAlgo::SHA_384,
            base_asym_algo_selected: BaseAsymAlgo::ECDSA_ECC_NIST_P256,
            base_hash_algo_selected: BaseHashAlgo::SHA_384,
            num_algorithm_responses: 4,
            algorithm_responses: responses,
        }
    }

    #[test]
    fn negotiate_algorithms_parses_correctly() {
        let mut buf = [0u8; 128];
        let mut requests =
            [AlgorithmRequest::default(); MAX_ALGORITHM_REQUESTS];
        algo_requests(&mut requests);
        let msg = negotiate_algo(requests);

        assert_eq!(48, msg.write(&mut buf).unwrap());
        assert_eq!(Ok(true), NegotiateAlgorithms::parse_header(&buf));

        let msg2 = NegotiateAlgorithms::parse_body(&buf[2..]).unwrap();
        assert_eq!(msg, msg2);
    }

    // We can't actually create this NegotiateAlgorithms message from our code,
    // so we must do it manually in the test as if we are interroperating with
    // a client written by an external party.
    //
    // In this case we skip any external algorithms as they are not suppported
    // and only negotiate based on the fixed algorithms.
    #[test]
    fn negotiate_algorithms_with_external_algorithms_skipped_parses_correctly()
    {
        let mut buf = [0u8; 128];
        let mut requests =
            [AlgorithmRequest::default(); MAX_ALGORITHM_REQUESTS];
        algo_requests(&mut requests);
        let msg = negotiate_algo(requests);
        assert_eq!(48, msg.write(&mut buf).unwrap());

        // patch counts to pretend there are external algorithms
        const EXT_ASYM_COUNT_POS: usize = 28;
        const EXT_HASH_COUNT_POS: usize = 29;
        const EXT_ASYM_COUNT: usize = 2;
        const EXT_HASH_COUNT: usize = 2;
        buf[EXT_ASYM_COUNT_POS] = 2;
        buf[EXT_HASH_COUNT_POS] = 2;

        // Reading will fail here because we didn't incorporate ExtAsym and
        // ExtHash fields.
        assert!(NegotiateAlgorithms::parse_body(&buf[2..]).is_err());

        // Now move the ReqAlgStruct past the skipped external algos. This
        // will allow proper parsing.
        const ALG_STRUCT_SIZE: usize = 16;
        const ORIG_OFFSET: usize = 32;
        let mut alg_struct = [0u8; ALG_STRUCT_SIZE];
        alg_struct
            .copy_from_slice(&buf[ORIG_OFFSET..ORIG_OFFSET + ALG_STRUCT_SIZE]);
        let new_offset = ORIG_OFFSET + EXT_ASYM_COUNT * 4 + EXT_HASH_COUNT * 4;
        buf[new_offset..new_offset + ALG_STRUCT_SIZE]
            .copy_from_slice(&alg_struct);

        let msg2 = NegotiateAlgorithms::parse_body(&buf[2..]).unwrap();
        assert_eq!(msg, msg2);
    }

    #[test]
    fn algorithms_parses_correctly() {
        let mut buf = [0u8; 128];
        let mut responses =
            [AlgorithmResponse::default(); MAX_ALGORITHM_REQUESTS];
        algo_responses(&mut responses);
        let msg = algo(responses);

        assert_eq!(52, msg.write(&mut buf).unwrap());
        assert_eq!(Ok(true), Algorithms::parse_header(&buf));

        let msg2 = Algorithms::parse_body(&buf[2..]).unwrap();
        assert_eq!(msg, msg2);
    }

    #[test]
    fn algorithms_with_more_than_one_selection_fails_to_parse() {
        let mut buf = [0u8; 128];
        let mut responses =
            [AlgorithmResponse::default(); MAX_ALGORITHM_REQUESTS];
        algo_responses(&mut responses);
        let mut msg = algo(responses);

        // Patch the responses to have more than 1 bit set
        algo_requests(&mut msg.algorithm_responses);

        assert_eq!(52, msg.write(&mut buf).unwrap());
        assert_eq!(Ok(true), Algorithms::parse_header(&buf));
        assert!(Algorithms::parse_body(&buf[2..]).is_err());
    }
}
