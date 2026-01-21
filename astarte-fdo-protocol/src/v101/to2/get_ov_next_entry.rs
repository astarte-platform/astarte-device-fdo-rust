// This file is part of Astarte.
//
// Copyright 2025, 2026 SECO Mind Srl
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! Get Ownership Voucher Next Entry, Type 62
//!
//! From Device to Owner Onboarding Service:
//!
//! ```cddl
//! TO2.GetOVNextEntry = [
//!     OVEntryNum
//! ]
//! OVEntryNum = uint8
//! ```
//!
//! Acknowledges the previous message and requests the next Ownership Voucher Entry. The integer
//! argument, OVEntryNum, is the number of the entry, where the first entry is zero (0).

use std::io::Write;

use serde::{Deserialize, Serialize};

use crate::Error;
use crate::error::ErrorKind;
use crate::v101::{ClientMessage, Message, Msgtype};

use super::ov_next_entry::OvNextEntry;

/// ```cddl
/// TO2.GetOVNextEntry = [
///     OVEntryNum
/// ]
/// OVEntryNum = uint8
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetOvNextEntry {
    pub(crate) ov_entry_num: u8,
}

impl GetOvNextEntry {
    /// Crete the message.
    pub fn new(ov_entry_num: u8) -> Self {
        Self { ov_entry_num }
    }
}

impl Serialize for GetOvNextEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self { ov_entry_num } = self;

        (ov_entry_num,).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for GetOvNextEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (ov_entry_num,) = Deserialize::deserialize(deserializer)?;

        Ok(Self { ov_entry_num })
    }
}

impl Message for GetOvNextEntry {
    const MSG_TYPE: Msgtype = 62;

    fn decode(buf: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(buf).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't decode TO2.GetOvNextEntry");

            Error::new(ErrorKind::Decode, "the TO2.GetOvNextEntry")
        })
    }

    fn encode<W>(&self, write: &mut W) -> Result<(), Error>
    where
        W: Write,
    {
        ciborium::into_writer(self, write).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't encode TO2.GetOvNextEntry");

            Error::new(ErrorKind::Encode, "the TO2.GetOvNextEntry")
        })
    }
}

impl ClientMessage for GetOvNextEntry {
    type Response<'a> = OvNextEntry;
}

#[cfg(test)]
mod tests {
    use crate::tests::insta_settings;

    use super::*;

    #[test]
    fn get_ov_next_entry_roundtrip() {
        let nxt = GetOvNextEntry::new(42);

        let mut buf = Vec::new();

        nxt.encode(&mut buf).unwrap();

        let res = GetOvNextEntry::decode(&buf).unwrap();

        assert_eq!(res, nxt);

        insta_settings!({
            insta::assert_binary_snapshot!(".cbor", buf);
        });
    }
}
