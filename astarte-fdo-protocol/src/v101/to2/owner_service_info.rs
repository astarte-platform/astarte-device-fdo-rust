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

//! Owner Service Info, Type 69
//!
//! From Owner Onboarding Service to Device
//!
//! Message Format - after decryption and verification:
//!
//! ```cddl
//! TO2.OwnerServiceInfo = [
//!     IsMoreServiceInfo,
//!     IsDone,
//!     ServiceInfo
//! ]
//! IsDone = bool
//! ```
//!
//! Sends as many Owner to Device ServiceInfo entries as will conveniently fit into a message, based
//! on protocol and implementation constraints. This message is part of a loop with
//! TO2.DeviceServiceInfo.

use std::io::Write;

use serde::{Deserialize, Serialize};

use crate::error::ErrorKind;
use crate::v101::service_info::ServiceInfo;
use crate::v101::{Message, Msgtype};
use crate::Error;

/// ```cddl
/// TO2.OwnerServiceInfo = [
///     IsMoreServiceInfo,
///     IsDone,
///     ServiceInfo
/// ]
/// IsDone = bool
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct OwnerServiceInfo<'a> {
    /// Check if owner has more info
    pub is_more_service_info: bool,
    /// Check if owner is done.
    pub is_done: bool,
    /// The service info
    pub service_info: ServiceInfo<'a>,
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

    fn decode(buf: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(buf).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err,"couldn't decode TO2.OwnerServiceInfo");

            Error::new(ErrorKind::Decode, "couldn't decode TO2.OwnerServiceInfo")
        })
    }

    fn encode<W>(&self, write: &mut W) -> Result<(), Error>
    where
        W: Write,
    {
        ciborium::into_writer(self, write).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err,"couldn't encode TO2.OwnerServiceInfo");

            Error::new(ErrorKind::Encode, "the TO2.OwnerServiceInfo")
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use pretty_assertions::assert_eq;

    use crate::v101::service_info::ServiceInfoKv;

    use super::*;

    #[test]
    fn owner_service_info_roundtrip() {
        let info = OwnerServiceInfo {
            is_more_service_info: true,
            is_done: false,
            service_info: vec![ServiceInfoKv {
                service_info_key: "key".into(),
                service_info_val: Cow::Owned(serde_bytes::ByteBuf::from(b"value")),
            }],
        };

        let mut buf = Vec::new();

        info.encode(&mut buf).unwrap();

        let res = OwnerServiceInfo::decode(&buf).unwrap();

        assert_eq!(res, info);

        insta::assert_binary_snapshot!(".cbor", buf);
    }
}
