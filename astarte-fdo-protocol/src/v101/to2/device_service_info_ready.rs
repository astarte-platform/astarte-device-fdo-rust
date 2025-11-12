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

use eyre::Context;
use serde::{Deserialize, Serialize};

use crate::v101::hash_hmac::HMac;
use crate::v101::{ClientMessage, Message, Msgtype};

use super::owner_service_info_ready::OwnerServiceInfoReady;

/// ```cddl
/// TO2.DeviceServiceInfoReady = [
///     ReplacementHMac, ;; Replacement for DI.SetHMac.HMac or equivalent
///     maxOwnerServiceInfoSz    ;; maximum size service info that Device can receive
/// ]
/// ;; A null HMAC indicates acceptance of credential reuse protocol
/// ReplacementHMac = HMac / null
/// maxOwnerServiceInfoSz = uint16 / null
/// ```
#[derive(Debug)]
pub(crate) struct DeviceServiceInfoReady<'a> {
    pub(crate) replacement_hmac: Option<HMac<'a>>,
    pub(crate) max_owner_service_info_sz: Option<u16>,
}

impl Serialize for DeviceServiceInfoReady<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            replacement_hmac,
            max_owner_service_info_sz,
        } = self;

        (replacement_hmac, max_owner_service_info_sz).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DeviceServiceInfoReady<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (replacement_hmac, max_owner_service_info_sz) = Deserialize::deserialize(deserializer)?;

        Ok(Self {
            replacement_hmac,
            max_owner_service_info_sz,
        })
    }
}

impl Message for DeviceServiceInfoReady<'_> {
    const MSG_TYPE: Msgtype = 66;

    fn decode(buf: &[u8]) -> eyre::Result<Self> {
        ciborium::from_reader(buf).wrap_err("couldn't decode TO2.DeviceServiceInfoReady")
    }

    fn encode(&self) -> eyre::Result<Vec<u8>> {
        let mut buf = Vec::new();

        ciborium::into_writer(self, &mut buf)?;

        Ok(buf)
    }
}

impl ClientMessage for DeviceServiceInfoReady<'_> {
    type Response<'a> = OwnerServiceInfoReady;
}
