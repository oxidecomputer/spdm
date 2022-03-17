// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), no_std)]

pub mod config;
pub mod crypto;
pub mod requester;
pub mod responder;
mod slot;

pub mod msgs;
pub(crate) mod transcript;

pub use requester::{Requester, RequesterError};
pub use responder::{Responder, ResponderError};
pub use slot::{Slot, SlotState};
pub use transcript::Transcript;
