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

use std::io::Write;

use serde::{Deserialize, Serialize};

use crate::error::ErrorKind;
use crate::v101::{Message, Msgtype};
use crate::Error;

/// ```cddl
/// TO2.OwnerServiceInfoReady  = [
///     maxDeviceServiceInfoSz    ;; maximum size service info that Owner can receive
/// ]
/// maxDeviceServiceInfoSz = uint16 / null
/// ```
pub struct OwnerServiceInfoReady {
    pub(crate) max_device_service_info_sz: Option<u16>,
}

impl OwnerServiceInfoReady {
    /// Return the owner max size
    pub fn max_size(&self) -> Option<u16> {
        self.max_device_service_info_sz
    }
}

impl Serialize for OwnerServiceInfoReady {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            max_device_service_info_sz,
        } = self;

        (max_device_service_info_sz,).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OwnerServiceInfoReady {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (max_device_service_info_sz,) = Deserialize::deserialize(deserializer)?;

        Ok(Self {
            max_device_service_info_sz,
        })
    }
}

impl Message for OwnerServiceInfoReady {
    const MSG_TYPE: Msgtype = 67;

    fn decode(buf: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(buf).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't decode TO2.OwnerServiceInfoReady");

            Error::new(ErrorKind::Decode, "the TO2.OwnerServiceInfoReady")
        })
    }

    fn encode<W>(&self, write: &mut W) -> Result<(), Error>
    where
        W: Write,
    {
        ciborium::into_writer(self, write).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't encode TO2.OwnerServiceInfoReady");

            Error::new(ErrorKind::Encode, "the TO2.OwnerServiceInfoReady")
        })
    }
}
