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

use crate::v101::{ClientMessage, Message, Msgtype};

use super::ov_next_entry::OvNextEntry;

/// ```cddl
/// TO2.GetOVNextEntry = [
///     OVEntryNum
/// ]
/// OVEntryNum = uint8
/// ```
#[derive(Debug)]
pub(crate) struct GetOvNextEntry {
    pub(crate) ov_entry_num: u8,
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

impl ClientMessage for GetOvNextEntry {
    type Response<'a> = OvNextEntry;
}
