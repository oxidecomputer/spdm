use super::encoding::{ReadError, ReadErrorKind, Reader, WriteError, Writer};
use super::Msg;

use bitflags::bitflags;

bitflags! {
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

bitflags! {
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

bitflags! {

    /// This is the `MeasurementSpecification` field from the Measurement block
    /// format in seciton 10.11.1 of the SPDM 1.1 spec. Only 1 bit is valid at
    /// a time. Currently DMTF is the only valid value.
    #[derive(Default)]
    pub struct MeasurementSpec: u8 {
        const DMTF = 0x1;
    }
}

// We use associated constants for AlgorithmRequests
//
pub trait AlgorithmConstants {
    const TYPE: u8;
    const FIXED_ALG_COUNT: u8;
}

bitflags! {
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

// We don't currently support any external algorithms
#[derive(Default, Clone, Copy)]
pub struct DheAlgorithm {
    pub supported: DheFixedAlgorithms,
}

impl AlgorithmConstants for DheAlgorithm {
    const TYPE: u8 = 0x2;
    const FIXED_ALG_COUNT: u8 = 2;
}

bitflags! {
    #[derive(Default)]
    pub struct AeadFixedAlgorithms: u16 {
        const AES_128_GCM = 0x1;
        const AES_256_GCM = 0x2;
        const CHACHA20_POLY1305 = 0x4;
    }
}

// We don't currently support any external algorithms
#[derive(Default, Clone, Copy)]
pub struct AeadAlgorithm {
    pub supported: AeadFixedAlgorithms,
}

impl AlgorithmConstants for AeadAlgorithm {
    const TYPE: u8 = 0x3;
    const FIXED_ALG_COUNT: u8 = 2;
}

bitflags! {
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

// We don't currently support any external algorithms
#[derive(Default, Clone, Copy)]
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
#[derive(Default, Clone, Copy)]
pub struct KeyScheduleAlgorithm {
    pub supported: KeyScheduleFixedAlgorithms,
}

impl AlgorithmConstants for KeyScheduleAlgorithm {
    const TYPE: u8 = 0x5;
    const FIXED_ALG_COUNT: u8 = 2;
}

#[derive(Clone, Copy)]
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

    pub fn read(
        msg_name: &'static str,
        r: &mut Reader,
    ) -> Result<AlgorithmRequest, ReadError> {
        match r.get_byte()? {
            DheAlgorithm::TYPE => {
                let ext_count = r.get_bits(4)?;
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
                let ext_count = r.get_bits(4)?;
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
                let ext_count = r.get_bits(4)?;
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
                let ext_count = r.get_bits(4)?;
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
const MAX_ALGORITHM_REQUESTS: usize = 4;

/// For simplicity and expediency we don't support any extended algorithms yet
/// in this implementation. This corresponds to the ExtAsym and ExtHash fields
/// in the spec, as well as the fields related to their sizes.
pub struct NegotiateAlgorithms {
    pub measurement_spec: MeasurementSpec,
    pub base_asym_algo: BaseAsymAlgo,
    pub base_hash_algo: BaseHashAlgo,
    pub num_algorithm_requests: u8, //Param1 in spec
    pub algorithm_requests: [AlgorithmRequest; MAX_ALGORITHM_REQUESTS],
}

impl Msg for NegotiateAlgorithms {
    fn name() -> &'static str {
        "NEGOTIATE_ALGORITHMS"
    }

    fn spdm_version() -> u8 {
        0x11
    }

    fn spdm_code() -> u8 {
        0xE3
    }

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
        let mut r = Reader::new(Self::name(), buf);
        let num_requests = r.get_byte()?;
        if num_requests as usize > MAX_ALGORITHM_REQUESTS {
            return Err(ReadError::new(
                Self::name(),
                ReadErrorKind::ImplementationLimitReached,
            ));
        }

        r.skip_reserved(1)?;

        // TODO: Use this for validation?
        let length = r.get_u16()?;
        if length > 128 {
            return Err(ReadError::new(
                Self::name(),
                ReadErrorKind::SpdmLimitReached,
            ));
        }
        let spec = r.get_byte()?;
        let measurement_spec =
            MeasurementSpec::from_bits(spec).ok_or_else(|| {
                ReadError::new(Self::name(), ReadErrorKind::InvalidBitsSet)
            })?;

        r.skip_reserved(1)?;

        let algo = r.get_u32()?;
        let base_asym_algo =
            BaseAsymAlgo::from_bits(algo).ok_or_else(|| {
                ReadError::new(Self::name(), ReadErrorKind::InvalidBitsSet)
            })?;

        let algo = r.get_u32()?;
        let base_hash_algo =
            BaseHashAlgo::from_bits(algo).ok_or_else(|| {
                ReadError::new(Self::name(), ReadErrorKind::InvalidBitsSet)
            })?;

        r.skip_reserved(12)?;

        // A responder will never select these algorithms, as they are not
        // currently supported. However, the data must still be properly skipped
        // over.
        let ext_asym_count = r.get_byte()?;
        let ext_hash_count = r.get_byte()?;

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
            requests[i] = AlgorithmRequest::read(Self::name(), r)?;
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
type AlgorithmResponse = AlgorithmRequest;

pub struct Algorithms {
    pub measurement_spec_selected: MeasurementSpec,
    pub measurement_hash_algo_selected: BaseHashAlgo,
    pub base_asym_algo_selected: BaseAsymAlgo,
    pub base_hash_algo_selected: BaseHashAlgo,
    pub num_algorithm_responses: u8, // Param1 in spec
    pub algorithm_responses: [AlgorithmResponse; MAX_ALGORITHM_REQUESTS],
}

impl Msg for Algorithms {
    fn name() -> &'static str {
        "ALGORITHMS"
    }

    fn spdm_version() -> u8 {
        0x11
    }

    fn spdm_code() -> u8 {
        0x63
    }

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
        let mut r = Reader::new(Self::name(), buf);
        let num_responses = r.get_byte()?;
        if num_responses as usize > MAX_ALGORITHM_REQUESTS {
            return Err(ReadError::new(
                Self::name(),
                ReadErrorKind::ImplementationLimitReached,
            ));
        }

        r.skip_reserved(1)?;

        // TODO: Use this for validation?
        let _length = r.get_u16()?;

        let selection = r.get_byte()?;
        let measurement_spec_selected = MeasurementSpec::from_bits(selection)
            .ok_or_else(|| {
            ReadError::new(Self::name(), ReadErrorKind::InvalidBitsSet)
        })?;
        if measurement_spec_selected.bits().count_ones() != 1 {
            return Self::too_many_bits();
        }

        r.skip_reserved(1)?;

        let selection = r.get_u32()?;
        let measurement_hash_algo_selected = BaseHashAlgo::from_bits(selection)
            .ok_or_else(|| {
                ReadError::new(Self::name(), ReadErrorKind::InvalidBitsSet)
            })?;
        if measurement_hash_algo_selected.bits().count_ones() != 1 {
            return Self::too_many_bits();
        }

        let selection = r.get_u32()?;
        let base_asym_algo_selected = BaseAsymAlgo::from_bits(selection)
            .ok_or_else(|| {
                ReadError::new(Self::name(), ReadErrorKind::InvalidBitsSet)
            })?;
        if base_asym_algo_selected.bits().count_ones() != 1 {
            return Self::too_many_bits();
        }

        let selection = r.get_u32()?;
        let base_hash_algo_selected = BaseHashAlgo::from_bits(selection)
            .ok_or_else(|| {
                ReadError::new(Self::name(), ReadErrorKind::InvalidBitsSet)
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
            responses[i] = AlgorithmResponse::read(Self::name(), r)?;
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
        Err(ReadError::new(Self::name(), ReadErrorKind::TooManyBitsSet))
    }
}
