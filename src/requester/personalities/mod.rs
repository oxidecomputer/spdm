// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Personalities define the message exchanges that a requester takes.
//! By separating Requesters into different personalities we can make the flow
//! of messages easier to understand and specialize each Requester for the use case.
//!
//! The set of personalities are not limited to ones defined here. Users can
//! create their own personalities directly by using the requester states directly.

pub mod vca;
