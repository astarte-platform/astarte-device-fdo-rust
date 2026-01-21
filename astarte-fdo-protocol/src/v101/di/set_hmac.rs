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

//! Device signed and owned secret in the Ownership Voucher.
//!
//! The device returns the HMAC of the internal secret and the DI.SetCredentials.OVHeader tag. The
//! manufacturer combines this HMAC with its own transmitted information to create an Ownership
//! Voucher with zero entries.

use std::io::Write;

use serde::{Deserialize, Serialize};

use crate::Error;
use crate::error::ErrorKind;
use crate::v101::hash_hmac::HMac;
use crate::v101::{ClientMessage, Message, Msgtype};

use super::done::Done;

/// ```cddl
/// DI.SetHMAC = [
///     Hmac
/// ]
#[derive(Debug, Clone, PartialEq)]
pub struct SetHmac<'a> {
    /// HMac signed by the device
    pub hmac: HMac<'a>,
}

impl Serialize for SetHmac<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self { hmac } = self;

        (hmac,).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SetHmac<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (hmac,) = Deserialize::deserialize(deserializer)?;

        Ok(Self { hmac })
    }
}

impl Message for SetHmac<'_> {
    const MSG_TYPE: Msgtype = 12;

    fn decode(buf: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(buf).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't decode DI.SetHmac");

            Error::new(ErrorKind::Decode, "the DI.SetHmac")
        })
    }

    fn encode<W>(&self, write: &mut W) -> Result<(), Error>
    where
        W: Write,
    {
        ciborium::into_writer(self, write).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't encode DI.SetHmac");

            Error::new(ErrorKind::Encode, "the DI.SetHmac")
        })
    }
}

impl ClientMessage for SetHmac<'_> {
    type Response<'a> = Done;
}

#[cfg(test)]
mod tests {
    use crate::tests::insta_settings;
    use crate::v101::hash_hmac::tests::create_hmac;

    use super::*;

    #[test]
    fn set_hmac_roundtrip() {
        let hmac = create_hmac();
        let set_hmac = SetHmac { hmac };

        let mut buf = Vec::new();

        set_hmac.encode(&mut buf).unwrap();

        let res = SetHmac::decode(&buf).unwrap();

        assert_eq!(res, set_hmac);

        insta_settings!({
            insta::assert_binary_snapshot!(".cbor", buf);
        });
    }
}
