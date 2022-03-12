// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

include!(concat!(env!("OUT_DIR"), "/config.rs"));

use crate::crypto::{pki::Validator, Digests};
use crate::msgs::algorithms::BaseAsymAlgo;
use crate::msgs::encoding::{ReadError, Reader};

// A slot that does not yet contain a certificate chain
//
// All requesters are configured with a set of empty slots.
//
// If `CERT_CAP` is enabled, then the slots will be filled when the
// `CERTIFICATE` messages are received. Upon filling the slot will automatically
// be converted to a FilledSlot.
pub struct EmptySlot<'a> {
    id: u8,
    algo: BaseAsymAlgo,
    buf: &'a [u8],
}

impl<'a> EmptySlot<'a> {
    // Copy `size` bytes from
    pub(crate) fn fill<'b>(
        self,
        r: Reader<'b>,
    ) -> Result<FilledSlot<'a>, ReadError> {
        unimplemented!();
    }
}

// A slot that holds a certificate chain
pub struct FilledSlot<'a> {
    id: u8,
    algo: BaseAsymAlgo,
    len: usize,
    buf: &'a [u8],
}

impl<'a> FilledSlot<'a> {
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    pub fn id(&self) -> u8 {
        self.id
    }

    pub fn algo(&self) -> BaseAsymAlgo {
        self.algo
    }

    pub fn clear(self) -> EmptySlot<'a> {
        // Don't bother zeroing the data. It can't be read from EmptySlot<'a>
        // and it's public information anyway.
        EmptySlot { id: self.id, algo: self.algo, buf: self.buf }
    }
}

#[derive(Debug, Clone)]
pub struct Config<'b, D, V>
where
    D: Digests,
    V: for<'a> Validator<'a>,
{
    digests: Option<D>,
    validator: Option<V>,
    my_certs: &'b [FilledSlot<'b>],
    remote_certs: &'b [EmptySlot<'b>],
}
