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

//! Type to manage [`ServiceInfo`].
//!
//! The ServiceInfo type is a collection of key-value pairs which allows an interaction between the
//! Management Service (on the cloud side) and Management Agent functions (on the Device side),
//! using the FIDO Device Onboard encrypted channel as a transport.
//!
//! See <https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-PS-v1.1-20220419/FIDO-Device-Onboard-PS-v1.1-20220419.html#ServiceInfo>.

use std::borrow::Cow;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_bytes::Bytes;

use crate::error::ErrorKind;
use crate::Error;

/// ```cddl
/// ServiceInfo = [
///     * ServiceInfoKV
/// ]
/// ```
pub type ServiceInfo<'a> = Vec<ServiceInfoKv<'a>>;

/// ```cddl
/// ServiceInfoKV = [
///     ServiceInfoKey: tstr,
///     ServiceInfoVal: bstr .cbor any
/// ]
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceInfoKv<'a> {
    pub(crate) service_info_key: Cow<'a, str>,
    // TODO: make generic
    pub(crate) service_info_val: Cow<'a, Bytes>,
}

impl<'a> ServiceInfoKv<'a> {
    /// Return the service info key
    pub fn key(&self) -> &str {
        &self.service_info_key
    }

    /// Return the service info value
    pub fn value_as_bytes(&self) -> &Bytes {
        self.service_info_val.as_ref()
    }

    /// Return the service info value
    pub fn value<T>(&self) -> Result<T, Error>
    where
        T: DeserializeOwned,
    {
        ciborium::from_reader::<T, &[u8]>(self.service_info_val.as_ref()).map_err(|error| {
            #[cfg(feature = "tracing")]
            tracing::error!(%error, "couldn't decode service info value");

            Error::new(ErrorKind::Decode, "service info value")
        })
    }
}

impl Serialize for ServiceInfoKv<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            service_info_key,
            service_info_val,
        } = self;

        (service_info_key, service_info_val).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ServiceInfoKv<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (service_info_key, service_info_val) = Deserialize::deserialize(deserializer)?;

        Ok(Self {
            service_info_key,
            service_info_val,
        })
    }
}

/// Device [`ServiceInfo`] devmod Module.
///
/// The “devmod” module implements a set of messages to the FIDO Device Onboard Owner that identify
/// the capabilities of the device.
///
/// All FIDO Device Onboard Owners must implement this module, and FIDO Device Onboard Owner
/// implementations must provide these messages to any module that asks for them. In addition all
/// “devmod” messages are sent by the Device in the first Device ServiceInfo.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Devmod<'a> {
    /// Indicates the module is active. Devmod is required on all devices
    ///
    /// - **Required**
    /// - **CBOR type**: `bool` with value `True`
    Active,
    /// OS name (e.g., Linux)
    ///
    /// - **Required**
    /// - **CBOR type**: `tstr`
    Os(Cow<'a, str>),
    /// Architecture name / instruction set (e.g., X86_64)
    ///
    /// - **Required**
    /// - **CBOR type**: `tstr`
    Arch(Cow<'a, str>),
    /// Version of OS (e.g., “Ubuntu* 16.0.4LTS”)
    ///
    /// - **Required**
    /// - **CBOR type**: `tstr`
    Version(Cow<'a, str>),
    /// Model specifier for this FIDO Device Onboard Device, manufacturer specific
    ///
    /// - **Required**
    /// - **CBOR type**: `tstr`
    Device(Cow<'a, str>),
    /// Serial number for this FIDO Device Onboard Device, manufacturer specific
    ///
    /// - **Optional**
    /// - **CBOR type**: `tstr` or `bstr`
    Sn(Option<StrOrBstr<'a>>),
    /// Filename path separator, between the directory and sub-directory (e.g., ‘/’ or ‘\’)
    ///
    /// - **Optional**
    /// - **CBOR type**: tstr
    Pathsep(Option<Cow<'a, str>>),
    /// Filename separator, that works to make lists of file names (e.g., ‘:’ or ‘;’)
    ///
    /// - **Required**
    /// - **CBOR type**: tstr
    Sep(Cow<'a, str>),
    /// Newline sequence (e.g., a tstr of length 1 containing U+000A; a tstr of length 2 containing
    /// U+000D followed by U+000A)
    ///
    /// - **Optional**
    /// - **CBOR type**: tstr
    Nl(Option<Cow<'a, str>>),
    /// Location of temporary directory, including terminating file separator (e.g., “/tmp”)
    ///
    /// - **Optional**
    /// - **CBOR type**: tstr
    Tmp(Option<Cow<'a, str>>),
    /// Location of suggested installation directory, including terminating file separator (e.g.,
    /// “.” or “/home/fdo” or “c:\Program Files\fdo”)
    ///
    /// - **Optional**
    /// - **CBOR type**: tstr
    Dir(Option<Cow<'a, str>>),
    /// Programming environment. See Table ‎3‑22 (e.g., “bin:java:py3:py2”)
    ///
    /// - **Optional**
    /// - **CBOR type**: tstr
    Progenv(Option<Cow<'a, str>>),
    /// Either the same value as “arch”, or a list of machine formats that can be interpreted by
    /// this device, in preference order, separated by the “sep” value (e.g., “x86:X86_64”)
    ///
    /// - **Required**
    /// - **CBOR type**: tstr
    Bin(Cow<'a, str>),
    /// URL for the Manufacturer Usage Description file that relates to this device
    ///
    /// - **Optional**
    /// - **CBOR type**: tstr
    Mudurl(Option<Cow<'a, str>>),
    /// Number of modules supported by this FIDO Device Onboard Device
    ///
    /// - **Required**
    /// - **CBOR type**: uint
    Nummodules(usize),
    /// Enumerates the modules supported by this FIDO Device Onboard Device.
    ///
    /// The first element is an integer from zero to [`devmod:nummodules`](Devmod::Nummodules). The second element is the
    /// number of module names to return The subsequent elements are module names. During the
    /// initial Device ServiceInfo, the device sends the complete list of modules to the Owner. If
    /// the list is long, it might require more than one ServiceInfo message.
    ///
    /// - **Required**
    /// - **CBOR type**: [uint, uint, tstr1, tstr2, ...]
    Modules,
}

impl<'a> Devmod<'a> {
    /// Returns the ServiceInfoKey for the Devmod
    pub fn key(&self) -> &'static str {
        match self {
            Devmod::Active => "devmod:active",
            Devmod::Os(_) => "devmod:os",
            Devmod::Arch(_) => "devmod:arch",
            Devmod::Version(_) => "devmod:version",
            Devmod::Device(_) => "devmod:device",
            Devmod::Sn(_) => "devmod:sn",
            Devmod::Pathsep(_) => "devmod:pathsep",
            Devmod::Sep(_) => "devmod:sep",
            Devmod::Nl(_) => "devmod:nl",
            Devmod::Tmp(_) => "devmod:tmp",
            Devmod::Dir(_) => "devmod:dir",
            Devmod::Progenv(_) => "devmod:progenv",
            Devmod::Bin(_) => "devmod:bin",
            Devmod::Mudurl(_) => "devmod:mudurl",
            Devmod::Nummodules(_) => "devmod:nummodules",
            Devmod::Modules => "devmod:modules",
        }
    }
}

/// Either `tstr` or `bstr`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StrOrBstr<'a> {
    /// A `tstr`
    Str(Cow<'a, str>),
    /// A `bstr`
    Bstr(Cow<'a, Bytes>),
}

#[cfg(test)]
mod tests {

    use coset::CborSerializable;
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn service_info_roundtrip() {
        let cases = [
            ServiceInfo::new(),
            vec![ServiceInfoKv {
                service_info_key: "devmod:os".into(),
                service_info_val: Cow::Owned(
                    ciborium::Value::Text("Linux".to_string())
                        .to_vec()
                        .unwrap()
                        .into(),
                ),
            }],
        ];

        for case in cases {
            let mut buf = Vec::new();
            ciborium::into_writer(&case, &mut buf).unwrap();

            let res: ServiceInfo = ciborium::from_reader(buf.as_slice()).unwrap();

            assert_eq!(res, case);

            insta::assert_binary_snapshot!(".cbor", buf);
        }
    }

    #[test]
    fn devmod_key() {
        let cases = [
            (Devmod::Active, "devmod:active"),
            (Devmod::Os("Linux".into()), "devmod:os"),
            (Devmod::Arch("x86_64".into()), "devmod:arch"),
            (
                Devmod::Version("Ubuntu* 16.0.4LTS".into()),
                "devmod:version",
            ),
            (Devmod::Device("fdo-astarte".into()), "devmod:device"),
            (Devmod::Sn(None), "devmod:sn"),
            (Devmod::Pathsep(None), "devmod:pathsep"),
            (Devmod::Sep("/".into()), "devmod:sep"),
            (Devmod::Nl(None), "devmod:nl"),
            (Devmod::Tmp(None), "devmod:tmp"),
            (Devmod::Dir(None), "devmod:dir"),
            (Devmod::Progenv(None), "devmod:progenv"),
            (Devmod::Bin("x86:x86_64".into()), "devmod:bin"),
            (Devmod::Mudurl(None), "devmod:mudurl"),
            (Devmod::Nummodules(8), "devmod:nummodules"),
            (Devmod::Modules, "devmod:modules"),
        ];

        for (case, exp) in cases {
            assert_eq!(case.key(), exp);
        }
    }
}
