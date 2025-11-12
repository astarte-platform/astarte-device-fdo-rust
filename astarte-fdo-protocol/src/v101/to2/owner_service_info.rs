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

use crate::v101::service_info::ServiceInfo;
use crate::v101::{Message, Msgtype};

/// ```cddl
/// TO2.OwnerServiceInfo = [
///     IsMoreServiceInfo,
///     IsDone,
///     ServiceInfo
/// ]
/// IsDone = bool
/// ```
#[derive(Debug)]
pub(crate) struct OwnerServiceInfo<'a> {
    pub(crate) is_more_service_info: bool,
    pub(crate) is_done: bool,
    pub(crate) service_info: ServiceInfo<'a>,
}

impl Serialize for OwnerServiceInfo<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            is_more_service_info,
            is_done,
            service_info,
        } = self;

        (is_more_service_info, is_done, service_info).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OwnerServiceInfo<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (is_more_service_info, is_done, service_info) = Deserialize::deserialize(deserializer)?;

        Ok(Self {
            is_more_service_info,
            is_done,
            service_info,
        })
    }
}

impl Message for OwnerServiceInfo<'_> {
    const MSG_TYPE: Msgtype = 69;

    fn decode(buf: &[u8]) -> eyre::Result<Self> {
        ciborium::from_reader(buf).wrap_err("couldn't decode TO2.OwnerServiceInfo")
    }

    fn encode(&self) -> eyre::Result<Vec<u8>> {
        let mut buf = Vec::new();

        ciborium::into_writer(self, &mut buf)?;

        Ok(buf)
    }
}
