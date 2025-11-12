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

use serde::{Deserialize, Serialize};

use crate::v101::ownership_voucher::OvEntry;
use crate::v101::{Message, Msgtype};

/// ```cddl
/// TO2.GetOVNextEntry = [
///     OVEntryNum
/// ]
/// OVEntryNum = uint8
/// ```
#[derive(Debug)]
pub(crate) struct OvNextEntry {
    pub(crate) ov_entry_num: u8,
    pub(crate) ov_entry: OvEntry,
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

    fn decode(buf: &[u8]) -> eyre::Result<Self> {
        let this = ciborium::from_reader(buf)?;

        Ok(this)
    }

    fn encode(&self) -> eyre::Result<Vec<u8>> {
        let mut buf = Vec::new();

        ciborium::into_writer(self, &mut buf)?;

        Ok(buf)
    }
}
