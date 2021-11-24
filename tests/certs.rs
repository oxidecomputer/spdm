//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//

extern crate test_utils;

use rcgen::Certificate;


use test_utils::certs::*;

#[test]
fn gen_certs() {
    let root_params = cert_params_ecdsa_p256_sha256(true, "Root");
    let root_cert = Certificate::from_params(root_params).unwrap();
    println!("{}", root_cert.serialize_pem().unwrap());

    let leaf_params = cert_params_ecdsa_p256_sha256(true, "Leaf");
    let leaf_cert = Certificate::from_params(leaf_params).unwrap();
    println!("{}", leaf_cert.serialize_pem_with_signer(&root_cert).unwrap());
    
}

