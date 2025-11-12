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

//! The manufacturing station sends credentials to the Device.
//!
//! The credentials in OVHeader are identical to the OVHeader field of the Ownership Voucher. Note
//! that OVHeader is wrapped in a byte string, as it is in the Ownership Voucher.
//!
//! Some additional credentials allow the original manufacturer of the device to be determined
//! across future ownership transfers.

use std::io::Write;

use serde::{Deserialize, Serialize};

use crate::error::ErrorKind;
use crate::utils::CborBstr;
use crate::v101::ownership_voucher::OvHeader;
use crate::v101::{Message, Msgtype};
use crate::Error;

/// ```cddl
/// DI.SetCredentials = [
///     bstr .cbor OVHeader
/// ]
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct SetCredentials<'a> {
    /// Ownership voucher header
    pub ov_header: CborBstr<'a, OvHeader<'a>>,
}

impl Serialize for SetCredentials<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self { ov_header } = self;

        (ov_header,).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SetCredentials<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (ov_header,) = Deserialize::deserialize(deserializer)?;

        Ok(Self { ov_header })
    }
}

impl Message for SetCredentials<'_> {
    const MSG_TYPE: Msgtype = 11;

    fn decode(buf: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(buf).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't decode DI.SetCredentials");

            Error::new(ErrorKind::Decode, "the DI.SetCredentials")
        })
    }

    fn encode<W>(&self, write: &mut W) -> Result<(), Error>
    where
        W: Write,
    {
        ciborium::into_writer(self, write).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't decode DI.SetCredentials");

            Error::new(ErrorKind::Decode, "the DI.SetCredentials")
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::v101::ownership_voucher::tests::create_ov_header;

    use super::*;

    #[test]
    fn set_credentials_roundtrip() {
        let ov_header = create_ov_header();
        let set_credentials = SetCredentials {
            ov_header: CborBstr::new(ov_header),
        };

        let mut buf = Vec::new();

        set_credentials.encode(&mut buf).unwrap();

        let res = SetCredentials::decode(&buf).unwrap();

        assert_eq!(res, set_credentials);

        insta::assert_binary_snapshot!(".cbor", buf);
    }
}
