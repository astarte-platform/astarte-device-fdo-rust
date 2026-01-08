// This file is part of Astarte.
//
// Copyright 2025 SECO Mind Srl
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

//! Ownership Voucher Next Entry, Type 63
//!
//! From Device to Owner Onboarding Service
//!
//! Message Format:
//!
//! ```cddl
//! TO2.OVNextEntry = [
//!     OVEntryNum
//!     OVEntry
//! ]
//! ```
//!
//! Acknowledges the previous message and requests the next Ownership Voucher Entry. The integer
//! argument, OVEntryNum, is the number of the entry, where the first entry is zero (0).

use std::io::Write;

use serde::{Deserialize, Serialize};

use crate::error::ErrorKind;
use crate::v101::ownership_voucher::OvEntry;
use crate::v101::{Message, Msgtype};
use crate::Error;

/// ```cddl
/// TO2.OVNextEntry = [
///     OVEntryNum
///     OVEntry
/// ]
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct OvNextEntry {
    pub(crate) ov_entry_num: u8,
    pub(crate) ov_entry: OvEntry,
}

impl OvNextEntry {
    /// Returns the entry num
    pub fn num(&self) -> u8 {
        self.ov_entry_num
    }

    /// Returns the ov entry
    pub fn ov_entry(&self) -> &OvEntry {
        &self.ov_entry
    }

    /// Returns the ov entry
    pub fn take_ov_entry(self) -> OvEntry {
        self.ov_entry
    }
}

impl Serialize for OvNextEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            ov_entry_num,
            ov_entry,
        } = self;

        (ov_entry_num, ov_entry).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OvNextEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (ov_entry_num, ov_entry) = Deserialize::deserialize(deserializer)?;

        Ok(Self {
            ov_entry_num,
            ov_entry,
        })
    }
}

impl Message for OvNextEntry {
    const MSG_TYPE: Msgtype = 63;

    fn decode(buf: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(buf).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't decode TO2.OvNextEntry");

            Error::new(ErrorKind::Decode, "the TO2.OvNextEntry")
        })
    }

    fn encode<W>(&self, write: &mut W) -> Result<(), Error>
    where
        W: Write,
    {
        ciborium::into_writer(self, write).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't encode TO2.OvNextEntry");

            Error::new(ErrorKind::Encode, "the TO2.OvNextEntry")
        })
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use crate::v101::ownership_voucher::tests::{create_ov_entry, create_ov_entry_payload};

    use super::*;

    #[test]
    fn ov_next_entry_roundtrip() {
        let entry = create_ov_entry(&create_ov_entry_payload());

        let ov_entry = OvNextEntry {
            ov_entry_num: 42,
            ov_entry: entry,
        };

        let mut buf = Vec::new();

        ov_entry.encode(&mut buf).unwrap();

        let mut res = OvNextEntry::decode(&buf).unwrap();

        res.ov_entry.entry.protected.original_data.take();

        assert_eq!(res, ov_entry);

        insta::assert_binary_snapshot!(".cbor", buf);
    }

    #[test]
    fn ov_next_entry_methods() {
        let entry = create_ov_entry(&create_ov_entry_payload());

        let ov_entry = OvNextEntry {
            ov_entry_num: 42,
            ov_entry: entry.clone(),
        };

        assert_eq!(ov_entry.num(), 42);
        assert_eq!(*ov_entry.ov_entry(), entry);
        assert_eq!(ov_entry.take_ov_entry(), entry);
    }
}
