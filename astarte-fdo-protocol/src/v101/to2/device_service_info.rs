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

//! Device Service info, Type 68
//!
//! From Device ROE to Owner Onboarding Service.
//!
//! Message Format - after decryption and verification:
//!
//! ```cddl
//! TO2.DeviceServiceInfo = [
//!     IsMoreServiceInfo,   ;; more ServiceInfo to come
//!     ServiceInfo          ;; service info entries
//! ]
//! IsMoreServiceInfo = bool
//! ```
//! Sends as many Device to Owner ServiceInfo entries as will conveniently fit into a message, based
//! on protocol and Device constraints. This message is part of a loop with TO2.OwnerServiceInfo.

use std::borrow::Cow;
use std::io::Write;

use coset::CborSerializable;
use serde::{Deserialize, Serialize};

use crate::error::ErrorKind;
use crate::v101::service_info::{ServiceInfo, ServiceInfoKv};
use crate::v101::{ClientMessage, Message, Msgtype};
use crate::Error;

use super::owner_service_info::OwnerServiceInfo;

/// ```cddl
/// TO2.DeviceServiceInfo = [
///     IsMoreServiceInfo,   ;; more ServiceInfo to come
///     ServiceInfo          ;; service info entries
/// ]
/// IsMoreServiceInfo = bool
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceServiceInfo<'a> {
    pub(crate) is_more_service_info: bool,
    pub(crate) service_info: ServiceInfo<'a>,
}

impl DeviceServiceInfo<'_> {
    // TODO: this is not neither by us nor Astarte, but we still send it to be spec complient
    //       We should change this to measure the correct values to send.
    /// Example bogus info
    pub fn example(sn: &str) -> Self {
        // devmod:active 	Required 	bool (True) 	Indicates the module is active. Devmod is required on all devices
        // devmod:os 	Required 	tstr 	OS name (e.g., Linux)
        // devmod:arch 	Required 	tstr 	Architecture name / instruction set (e.g., X86_64)
        // devmod:version 	Required 	tstr 	Version of OS (e.g., “Ubuntu* 16.0.4LTS”)
        // devmod:device 	Required 	tstr 	Model specifier for this FIDO Device Onboard Device, manufacturer specific
        // devmod:sn 	Optional 	tstr or bstr 	Serial number for this FIDO Device Onboard Device, manufacturer specific
        // devmod:pathsep 	Optional 	tstr 	Filename path separator, between the directory and sub-directory (e.g., ‘/’ or ‘\’)
        // devmod:sep 	Required 	tstr 	Filename separator, that works to make lists of file names (e.g., ‘:’ or ‘;’)
        // devmod:nl 	Optional 	tstr 	Newline sequence (e.g., a tstr of length 1 containing U+000A; a tstr of length 2 containing U+000D followed by U+000A)
        // devmod:tmp 	Optional 	tstr 	Location of temporary directory, including terminating file separator (e.g., “/tmp”)
        // devmod:dir 	Optional 	tstr 	Location of suggested installation directory, including terminating file separator (e.g., “.” or “/home/fdo” or “c:\Program Files\fdo”)
        // devmod:progenv 	Optional 	tstr 	Programming environment. See Table ‎3‑22 (e.g., “bin:java:py3:py2”)
        // devmod:bin 	Required 	tstr 	Either the same value as “arch”, or a list of machine formats that can be interpreted by this device, in preference order, separated by the “sep” value (e.g., “x86:X86_64”)
        // devmod:mudurl 	Optional 	tstr 	URL for the Manufacturer Usage Description file that relates to this device
        // devmod:nummodules 	Required 	uint 	Number of modules supported by this FIDO Device Onboard Device
        // devmod:modules 	Required 	[uint, uint, tstr1, tstr2, ...] 	Enumerates the modules supported by this FIDO Device Onboard Device. The first element is an integer from zero to devmod:nummodules. The second element is the number of module names to return The subsequent elements are module names. During the initial Device ServiceInfo, the device sends the complete list of modules to the Owner. If the list is long, it might require more than one ServiceInfo message.
        DeviceServiceInfo {
            is_more_service_info: false,
            service_info: vec![
                ServiceInfoKv {
                    service_info_key: "devmod:active".into(),
                    service_info_val: Cow::Owned(
                        ciborium::Value::Bool(true).to_vec().unwrap().into(),
                    ),
                },
                ServiceInfoKv {
                    service_info_key: "devmod:os".into(),
                    service_info_val: Cow::Owned(
                        ciborium::Value::Text("Linux".to_string())
                            .to_vec()
                            .unwrap()
                            .into(),
                    ),
                },
                ServiceInfoKv {
                    service_info_key: "devmod:arch".into(),
                    service_info_val: Cow::Owned(
                        ciborium::Value::Text(std::env::consts::ARCH.to_string())
                            .to_vec()
                            .unwrap()
                            .into(),
                    ),
                },
                ServiceInfoKv {
                    service_info_key: "devmod:version".into(),
                    service_info_val: Cow::Owned(
                        ciborium::Value::Text("Ubuntu* 16.0.4LTS".to_string())
                            .to_vec()
                            .unwrap()
                            .into(),
                    ),
                },
                ServiceInfoKv {
                    service_info_key: "devmod:device".into(),
                    service_info_val: Cow::Owned(
                        ciborium::Value::Text("fdo-astarte".to_string())
                            .to_vec()
                            .unwrap()
                            .into(),
                    ),
                },
                ServiceInfoKv {
                    service_info_key: "devmod:sn".into(),
                    service_info_val: Cow::Owned(
                        ciborium::Value::Text(sn.to_string())
                            .to_vec()
                            .unwrap()
                            .into(),
                    ),
                },
                ServiceInfoKv {
                    service_info_key: "devmod:sep".into(),
                    service_info_val: Cow::Owned(
                        ciborium::Value::Text(":".to_string())
                            .to_vec()
                            .unwrap()
                            .into(),
                    ),
                },
                ServiceInfoKv {
                    service_info_key: "devmod:bin".into(),
                    service_info_val: Cow::Owned(
                        ciborium::Value::Text(std::env::consts::ARCH.to_string())
                            .to_vec()
                            .unwrap()
                            .into(),
                    ),
                },
                ServiceInfoKv {
                    service_info_key: "devmod:nummodules".into(),
                    service_info_val: Cow::Owned(
                        ciborium::Value::Integer(6.into()).to_vec().unwrap().into(),
                    ),
                },
                ServiceInfoKv {
                    service_info_key: "devmod:modules".into(),
                    service_info_val: Cow::Owned(
                        ciborium::Value::Array(vec![
                            ciborium::Value::Integer(0.into()),
                            ciborium::Value::Integer(6.into()),
                            ciborium::Value::Text("devmod:os".to_string()),
                            ciborium::Value::Text("devmod:arch".to_string()),
                            ciborium::Value::Text("devmod:version".to_string()),
                            ciborium::Value::Text("devmod:device".to_string()),
                            ciborium::Value::Text("devmod:sep".to_string()),
                            ciborium::Value::Text("devmod:bin".to_string()),
                        ])
                        .to_vec()
                        .unwrap()
                        .into(),
                    ),
                },
            ],
        }
    }
}

impl Serialize for DeviceServiceInfo<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            is_more_service_info,
            service_info,
        } = self;

        (is_more_service_info, service_info).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DeviceServiceInfo<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (is_more_service_info, service_info) = Deserialize::deserialize(deserializer)?;

        Ok(Self {
            is_more_service_info,
            service_info,
        })
    }
}

impl Message for DeviceServiceInfo<'_> {
    const MSG_TYPE: Msgtype = 68;

    fn decode(buf: &[u8]) -> Result<Self, crate::Error> {
        ciborium::from_reader(buf).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't decode TO2.DeviceServiceInfo");

            Error::new(ErrorKind::Decode, "the TO2.DeviceServiceInfo")
        })
    }

    fn encode<W>(&self, write: &mut W) -> Result<(), Error>
    where
        W: Write,
    {
        ciborium::into_writer(self, write).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't encode TO2.DeviceServiceInfo");

            Error::new(ErrorKind::Encode, "the TO2.DeviceServiceInfo")
        })
    }
}

impl ClientMessage for DeviceServiceInfo<'_> {
    type Response<'a> = OwnerServiceInfo<'a>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_service_info_roundtrip() {
        let dv = DeviceServiceInfo::example("device-sn");

        let mut buf = Vec::new();

        dv.encode(&mut buf).unwrap();

        let res = DeviceServiceInfo::decode(&buf).unwrap();

        assert_eq!(res, dv);

        insta::assert_binary_snapshot!(".cbor", buf);
    }
}
