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

//! DI.AppStart DeviceMfgInfo sent to the Device to the Manufacturing server.
//!
//! This part is non normative, but we follow the other reference implementations.

use std::borrow::Cow;
use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use serde_bytes::Bytes;

use crate::utils::Hex;
use crate::v101::public_key::{PkEnc, PkType};

/// DeviceMfgInfo is a structure for use in DI.AppStart. The structure is not part of the spec, but
/// matches the [C client] and [Java client] implementations.
///
/// Type definition from C:
///
///    MfgInfo.cbor = [
///      pkType,                 // as per FDO spec
///      pkEnc,                  // as per FDO spec
///      serialNo,               // tstr
///      modelNo,                // tstr
///      CSR,                    // bstr
///      OnDie ECDSA cert chain, // bstr OR OMITTED
///      test signature,         // bstr OR OMITTED
///      MAROE prefix,           // bstr OR OMITTED
///    ]
///
///    DeviceMfgInfo = bstr, MfgInfo.cbor (bstr-wrap MfgInfo CBOR bytes)
///
/// [C client]: https://github.com/fido-device-onboard/client-sdk-fidoiot/
/// [Java client]: https://github.com/fido-device-onboard/pri-fidoiot
#[derive(Clone, PartialEq, Eq)]
pub struct MfgInfo<'a> {
    pk_type: PkType,
    pk_enc: PkEnc,
    serial_no: Cow<'a, str>,
    model_no: Cow<'a, str>,
    cert_info: Cow<'a, Bytes>,
}

impl<'a> MfgInfo<'a> {
    /// Returns a new MfgInfo
    pub fn new(
        pk_type: PkType,
        pk_enc: PkEnc,
        cert_info: Cow<'a, Bytes>,
        serial_no: Cow<'a, str>,
        model_no: Cow<'a, str>,
    ) -> Self {
        Self {
            pk_type,
            pk_enc,
            serial_no,
            model_no,
            cert_info,
        }
    }
}

impl Debug for MfgInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            pk_type,
            pk_enc,
            serial_no,
            model_no,
            cert_info,
        } = self;
        f.debug_struct("MfgInfo")
            .field("pk_type", &pk_type)
            .field("pk_enc", &pk_enc)
            .field("serial_no", &serial_no)
            .field("model_no", &model_no)
            .field("cert_info", &Hex::new(cert_info))
            .finish()
    }
}

impl Serialize for MfgInfo<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            pk_type,
            pk_enc,
            serial_no,
            model_no,
            cert_info,
        } = self;

        (pk_type, pk_enc, serial_no, model_no, cert_info).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MfgInfo<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (pk_type, pk_enc, serial_no, model_no, cert_info) =
            Deserialize::deserialize(deserializer)?;

        Ok(Self {
            pk_type,
            pk_enc,
            serial_no,
            model_no,
            cert_info,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use serde_bytes::ByteBuf;

    use super::*;

    pub(crate) fn custom_mfginfo() -> MfgInfo<'static> {
        MfgInfo::new(
            PkType::Secp256R1,
            PkEnc::X509,
            Cow::Owned(ByteBuf::from(b"deadbeef")),
            "fdo-serial-no".into(),
            "fdo-model-no".into(),
        )
    }

    #[test]
    fn mfg_info_roundtrip() {
        let mfg_info = custom_mfginfo();

        let mut buf = Vec::new();
        ciborium::into_writer(&mfg_info, &mut buf).unwrap();

        let res: MfgInfo = ciborium::from_reader(buf.as_slice()).unwrap();

        assert_eq!(res, mfg_info);

        insta::assert_binary_snapshot!(".cbor", buf);
    }

    #[test]
    fn mfg_info_debug() {
        let mfg_info = custom_mfginfo();

        insta::assert_debug_snapshot!(mfg_info);
    }
}
