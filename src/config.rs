// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::msgs::algorithms::BaseAsymAlgo;
use crate::Slot;

/// This is the size in bytes of the largest buffer required for a signature
/// using the base asymmetric signing algorithms in the SPDM 1.2 spec,
/// not-including RSA.
///
/// See Table 15, Byte offset: 8, Field: BaseAsymAlgo in the SPDM 1.2 spec
pub const MAX_SIGNATURE_SIZE: usize = 132;

/// This is the size in bytes of the largest buffer required for a digest
/// See Table 15, Byte offset: 12, Field: BaseHashAlgo in the SPDM 1.2 spec
pub const MAX_DIGEST_SIZE: usize = 64;

/// The number of possible slots in the SPDM
pub const NUM_SLOTS: usize = 8;

/// TODO: Eventually we will get rid of the need for this by maintaining a rolling
/// hash.
pub const TRANSCRIPT_SIZE: usize = 512;

#[derive(Debug, PartialEq)]
pub enum SlotConfigError {
    /// The provided algorithm is not supported.
    AlgorithmNotSupported(BaseAsymAlgo),

    /// Each slot must use a unique algorithm
    /// This is necessary so the implementation can choose which slot to use
    /// based on the selected algorithm.
    ///
    /// It's anticipated that different requesters can chose different slots
    /// depending upon the given responder, so this should not be problematic.
    AlgorithmUsedInMoreThanOneSlot(BaseAsymAlgo),

    /// Slots must have exactly one bit set for `algo`
    SlotsMustHaveExactlyOneAlgoSelected { slot_id: u8 },
}

// Ensure that exactly one bit of BaseAsymAlgo is set for each algorithm in
// `my_certs` and `responder_certs`.
//
// Also ensure that no more than one slot has the same algorithm.
pub fn validate_slots<'a, T: AsRef<Slot<'a>>>(
    slots: &[T],
) -> Result<(), SlotConfigError> {
    // We don't support RSA, and need to add Ed25519 once we upgrade the
    // algorithms message to 1.2.
    let mut counts = heapless::LinearMap::<BaseAsymAlgo, usize, 3>::new();
    counts.insert(BaseAsymAlgo::ECDSA_ECC_NIST_P256, 0).unwrap();
    counts.insert(BaseAsymAlgo::ECDSA_ECC_NIST_P384, 0).unwrap();
    counts.insert(BaseAsymAlgo::ECDSA_ECC_NIST_P521, 0).unwrap();

    for slot in slots {
        let slot = slot.as_ref();
        if slot.algo().bits().count_ones() != 1 {
            return Err(SlotConfigError::SlotsMustHaveExactlyOneAlgoSelected {
                slot_id: slot.id,
            });
        }
        match counts.get_mut(&slot.algo()) {
            Some(count) => {
                *count += 1;
                if *count > 1 {
                    return Err(
                        SlotConfigError::AlgorithmUsedInMoreThanOneSlot(
                            slot.algo,
                        ),
                    );
                }
            }
            None => {
                return Err(SlotConfigError::AlgorithmNotSupported(slot.algo));
            }
        }
    }

    Ok(())
}
