//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//

use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, KeyIdMethod, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};

pub fn distinguished_name(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "Oxide");
    dn.push(DnType::CommonName, cn);
    dn.push(DnType::OrganizationalUnitName, "Test");
    dn
}

pub fn ca_key_usages() -> Vec<KeyUsagePurpose> {
    use rcgen::KeyUsagePurpose as P;
    vec![
        P::DigitalSignature,
        P::ContentCommitment,
        P::KeyEncipherment,
        P::DataEncipherment,
        P::KeyAgreement,
        P::KeyCertSign,
        P::CrlSign,
    ]
}

pub fn leaf_key_usages() -> Vec<KeyUsagePurpose> {
    use rcgen::KeyUsagePurpose as P;
    vec![P::DigitalSignature, P::ContentCommitment, P::KeyEncipherment]
}

pub fn ca_extended_key_usages() -> Vec<ExtendedKeyUsagePurpose> {
    use rcgen::ExtendedKeyUsagePurpose as P;
    vec![P::ServerAuth, P::ClientAuth]
}

pub fn leaf_extended_key_usages() -> Vec<ExtendedKeyUsagePurpose> {
    use rcgen::ExtendedKeyUsagePurpose as P;
    vec![P::ServerAuth, P::ClientAuth, P::OcspSigning]
}

pub fn cert_params_ecdsa_p256_sha256(
    is_ca: bool,
    cn: &str,
) -> CertificateParams {
    let key_usages = if is_ca { ca_key_usages() } else { leaf_key_usages() };

    let extended_key_usages = if is_ca {
        ca_extended_key_usages()
    } else {
        leaf_extended_key_usages()
    };

    let is_ca = if is_ca {
        IsCa::Ca(BasicConstraints::Unconstrained)
    } else {
        IsCa::SelfSignedOnly
    };

    // Slightly modified from the example in the DMTF spec
    let subject_alt_name =
        "otherName:1.3.6.1.4.1.412.274.1;UTF8STRING:OXIDE:COMPUTER:1";

    let mut params = CertificateParams::new(vec![subject_alt_name.to_string()]);

    params.alg = &PKCS_ECDSA_P256_SHA256;
    params.not_before = date_time_ymd(2021, 10, 27);
    params.not_after = date_time_ymd(3000, 1, 1);
    params.serial_number = Some(1);
    params.subject_alt_names = vec![];
    params.distinguished_name = distinguished_name(cn);
    params.is_ca = is_ca;
    params.key_usages = key_usages;
    params.extended_key_usages = extended_key_usages;
    params.name_constraints = None;
    params.custom_extensions = vec![];
    params.key_pair = None;
    params.use_authority_key_identifier_extension = false;
    params.key_identifier_method = KeyIdMethod::Sha256;

    params
}
