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

//! Device Service Info Ready, Type 66
//!
//! From Device to Owner Onboarding Service
//!
//! Message Format - after decryption and verification:
//!
//! ```cddl
//! TO2.DeviceServiceInfoReady = [
//!     ReplacementHMac, ;; Replacement for DI.SetHMac.HMac or equivalent
//!     maxOwnerServiceInfoSz    ;; maximum size service info that Device can receive
//! ]
//! ;; A null HMAC indicates acceptance of credential reuse protocol
//! ReplacementHMac = HMac / null
//! maxOwnerServiceInfoSz = uint16 / null
//! ```
//!
//! This message signals a state change between the authentication phase of the protocol and the
//! provisioning phase (ServiceInfo) negotiation.

use std::io::Write;

use serde::{Deserialize, Serialize};

use crate::Error;
use crate::error::ErrorKind;
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceServiceInfoReady<'a> {
    pub(crate) replacement_hmac: Option<HMac<'a>>,
    pub(crate) max_owner_service_info_sz: Option<u16>,
}

impl<'a> DeviceServiceInfoReady<'a> {
    /// Creates the message
    pub fn new(replacement_hmac: Option<HMac<'a>>, max_owner_service_info_sz: Option<u16>) -> Self {
        Self {
            replacement_hmac,
            max_owner_service_info_sz,
        }
    }
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

    fn decode(buf: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(buf).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't decode TO2.DeviceServiceInfoReady");

            Error::new(ErrorKind::Decode, "the TO2.DeviceServiceInfoReady")
        })
    }

    fn encode<W>(&self, write: &mut W) -> Result<(), Error>
    where
        W: Write,
    {
        ciborium::into_writer(self, write).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't encode TO2.DeviceServiceInfoReady");

            Error::new(ErrorKind::Encode, "the TO2.DeviceServiceInfoReady")
        })?;

        Ok(())
    }
}

impl ClientMessage for DeviceServiceInfoReady<'_> {
    type Response<'a> = OwnerServiceInfoReady;
}

#[cfg(test)]
mod tests {
    use crate::tests::insta_settings;
    use crate::v101::hash_hmac::tests::create_hmac;

    use super::*;

    #[test]
    fn device_service_info_roundtrip() {
        let replacement_hmac = create_hmac();
        let dv_ready = DeviceServiceInfoReady::new(Some(replacement_hmac), Some(1400));

        let mut buf = Vec::new();

        dv_ready.encode(&mut buf).unwrap();

        let res = DeviceServiceInfoReady::decode(&buf).unwrap();

        assert_eq!(res, dv_ready);

        insta_settings!({
            insta::assert_binary_snapshot!(".cbor", buf);
        });
    }
}
