// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Generate a `spdm::Config` from a TOML file

use anyhow::Result;
use serde_derive::Deserialize;
use std::convert::AsRef;
use std::env;
use std::fs;
use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SpdmConfigError {
    #[error(
        "Invalid number of cert chains: Must be at least 1,\
            and no more than 8"
    )]
    InvalidNumCertChains,

    #[error("Your cert chain almost certainly does not need to be this long")]
    CertChainDepthTooLarge,

    #[error("Cert chain buffers cannot exceed 64 KiB")]
    CertChainBufferTooLarge,

    #[error("Invalid asymmetric_signing algorithm: {0}")]
    InvalidAsymmetricSigningAlgorithm(String),

    #[error("Invalid capability: {0}")]
    InvalidCapability(String),

    #[error(
        "Capabilities: {0:?} not supported because a crypto provider \
            (e.g.'crypto-ring') is not enabled"
    )]
    CryptoCapNotSupported(Vec<String>),
}

#[derive(Debug, Deserialize)]
pub struct SpdmConfig {
    pub cert_chains: CertChainConfig,
    pub transcript: TranscriptConfig,
    pub capabilities: Vec<String>,
    pub algorithms: AlgorithmsConfig,
    pub measurement: MeasurementConfig,
    pub opaque_data: OpaqueDataConfig,
}

#[derive(Debug, Deserialize)]
pub struct CertChainConfig {
    pub num_slots: usize,
    pub buf_size: usize,
    pub max_depth: usize,
}

impl CertChainConfig {
    fn validate(&self) -> Result<(), SpdmConfigError> {
        if self.num_slots < 1 || self.num_slots > 8 {
            return Err(SpdmConfigError::InvalidNumCertChains);
        }
        if self.buf_size > 65536 {
            return Err(SpdmConfigError::CertChainBufferTooLarge);
        }
        if self.max_depth > 24 {
            return Err(SpdmConfigError::CertChainDepthTooLarge);
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct TranscriptConfig {
    pub buf_size: usize,
}

#[derive(Debug, Deserialize)]
pub struct AlgorithmsConfig {
    pub max_digest_size: usize,
    pub asymmetric_signing: Vec<String>,
}

// TODO: Validation
#[derive(Debug, Deserialize)]
pub struct MeasurementConfig {
    pub max_blocks: usize,
    pub max_size: usize,
}

// TODO: Validation
#[derive(Debug, Deserialize)]
pub struct OpaqueDataConfig {
    pub max_elements: usize,
    pub max_element_data_size: usize,
}

// Return the maximum signature size if all algorithms are supported, otherwise
// return an error.
//
// We only are listing algorithms that are implemented here. This is a subset of
// all algorithms supported by SPDM.
fn max_signature_size(algos: &Vec<String>) -> Result<usize, SpdmConfigError> {
    let max_size = 64;
    for algo in algos {
        match algo.as_str() {
            "ECDSA_ECC_NIST_P256" => (),
            x => {
                return Err(
                    SpdmConfigError::InvalidAsymmetricSigningAlgorithm(
                        x.into(),
                    ),
                );
            }
        }
    }
    Ok(max_size)
}

// Return Ok(()) if all capabilities are suppported.
fn validate_capabilities(caps: &Vec<String>) -> Result<(), SpdmConfigError> {
    if std::env::var("CARGO_FEATURE_CRYPTO_RING").is_err() {
        // Crypto not enabled. We cannot allow any crypto related capabilities
        // to be set.
        // TODO: For now, just assume this is all capabilities
        if !caps.is_empty() {
            return Err(SpdmConfigError::CryptoCapNotSupported(caps.clone()));
        }
    }
    for cap in caps {
        match cap.as_str() {
            "CERT_CAP" | "CHAL_CAP" | "ENCRYPT_CAP" | "MAC_CAP"
            | "MUT_AUTH_CAP" | "KEY_EX_CAP" | "KEY_UPD_CAP" => (),
            x => {
                return Err(SpdmConfigError::InvalidCapability(x.into()));
            }
        }
    }
    Ok(())
}

pub fn load<P: AsRef<Path>>(path: P) -> Result<SpdmConfig> {
    let toml = read_to_string(path)?;
    let config: SpdmConfig = toml::from_str(&toml)?;
    Ok(config)
}

/// Take SpdmConfig and generate a configuration file consisting of many
/// constants.
pub fn gen_config(input: SpdmConfig) -> Result<String> {
    let template = read_to_string("./config.rs.template")?;
    let max_digest_size = input.algorithms.max_digest_size;
    let max_signature_size =
        max_signature_size(&input.algorithms.asymmetric_signing)?;
    input.cert_chains.validate()?;
    validate_capabilities(&input.capabilities)?;
    let params = [
        input.cert_chains.num_slots.to_string(),
        input.cert_chains.buf_size.to_string(),
        input.cert_chains.max_depth.to_string(),
        input.transcript.buf_size.to_string(),
        max_digest_size.to_string(),
        max_signature_size.to_string(),
        input.opaque_data.max_element_data_size.to_string(),
        input.opaque_data.max_elements.to_string(),
        input.measurement.max_blocks.to_string(),
        input.measurement.max_size.to_string(),
        format!("{:?}", input.capabilities),
        format!("{:?}", input.algorithms.asymmetric_signing),
        // We use an empty string to zip the last `;` from the template.
        String::from(""),
    ];
    Ok(template
        .split("{}")
        .zip(params)
        .map(|(s, arg)| format!("{}{}", s, arg))
        .collect())
}

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("config.rs");
    let src_path = match env::var("SPDM_CONFIG") {
        Ok(path) => PathBuf::from(path),
        _ => PathBuf::from("./spdm-config.toml"),
    };
    let config_input = load(src_path).unwrap();
    let config_output = gen_config(config_input).unwrap();
    fs::write(&dest_path, &config_output).unwrap();

    // We may need to make this more fine-grained in the future, but this
    // follows the "single-provider enables all crypto functionality" model.
    // When different providers are possible, if at least one is possible this
    // will be set to true.
    if std::env::var("CARGO_FEATURE_CRYPTO_RING").is_ok() {
        println!("cargo:rustc-cfg=feature=\"crypto\"")
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=spdm-config.toml");
    println!("cargo:rerun-if-changed=config.rs.template");
    println!("cargo:rerun-if-env-changed=SPDM_CONFIG");
}
