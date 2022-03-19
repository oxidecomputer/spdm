// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use tinyvec::SliceVec;

use crate::msgs::algorithms::BaseAsymAlgo;
use crate::msgs::common::DigestBuf;
use crate::msgs::encoding::{ReadError, Reader};

type RootHash = DigestBuf;

/// The state of a slot holding a certificate chain.
///
/// A local slot is always full. A slot that is retrieved from requester or
/// responder may not yet be full.
#[derive(Debug, PartialEq)]
pub enum SlotState {
    /// There is a full cert chain in the slot.
    Full(RootHash),
    /// There is no cert chain in the slot
    Empty,
    /// The cert chain has been partially retrieved in a CERTIFICATE msg
    /// This isn't yet in use.
    Partial,
}

/// Slots contain certificate chains or are placeholders for certificate
/// chains. There are 8 slot ids ranging from 0 to 7. Each slot's algorithm is
/// known a-priori whether it is for a requester or responder.
#[derive(Debug, PartialEq)]
pub struct Slot<'a> {
    pub state: SlotState,
    pub id: u8,
    pub algo: BaseAsymAlgo,
    pub buf: SliceVec<'a, u8>,
}

impl<'a> AsRef<Slot<'a>> for Slot<'a> {
    fn as_ref(&self) -> &Slot<'a> {
        &self
    }
}

impl<'a> Slot<'a> {
    pub fn new(
        state: SlotState,
        id: u8,
        algo: BaseAsymAlgo,
        buf: SliceVec<'a, u8>,
    ) -> Slot<'a> {
        Slot { state, id, algo, buf }
    }
    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn id(&self) -> u8 {
        self.id
    }

    pub fn algo(&self) -> BaseAsymAlgo {
        self.algo
    }

    pub fn fill<'b>(
        &mut self,
        reader: &mut Reader<'b>,
        len: usize,
        root_hash: DigestBuf,
    ) -> Result<(), ReadError> {
        // We don't currently allow partial fills
        assert!(self.state == SlotState::Empty);
        self.buf.set_len(len);
        if let Err(e) = reader.get_slice(len, self.buf.as_mut_slice()) {
            // Maintain invariant that len = 0 when state = SliceState::Empty
            self.buf.set_len(0);
            return Err(e);
        }
        self.state = SlotState::Full(root_hash);
        Ok(())
    }
}
