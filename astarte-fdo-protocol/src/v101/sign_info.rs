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

use std::borrow::Cow;

use eyre::bail;
use serde::{Deserialize, Serialize};
use serde_bytes::Bytes;

/// ```cddl
/// SigInfo = [
///     sgType: DeviceSgType,
///     Info: bstr
/// ]
/// ```
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SigInfo<'a> {
    pub(crate) sg_type: DeviceSgType,
    pub(crate) info: Cow<'a, Bytes>,
}
impl<'a> SigInfo<'a> {
    pub(crate) fn into_owned(self) -> SigInfo<'static> {
        SigInfo {
            sg_type: self.sg_type,
            info: Cow::Owned(self.info.into_owned()),
        }
    }
}

impl Serialize for SigInfo<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self { sg_type, info } = self;

        (sg_type, info).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SigInfo<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (sg_type, info) = Deserialize::deserialize(deserializer)?;

        Ok(Self { sg_type, info })
    }
}

/// ```cddl
/// eASigInfo = SigInfo  ;; from Device to Rendezvous/Owner
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[repr(transparent)]
pub(crate) struct EASigInfo<'a>(pub(crate) SigInfo<'a>);

/// ```cddl
/// eBSigInfo = SigInfo  ;; from Owner/Rendezvous to Device
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[repr(transparent)]
pub(crate) struct EBSigInfo<'a>(pub(crate) SigInfo<'a>);

/// DeviceSgType //= (
///     StSECP256R1: ES256,  ;; ECDSA secp256r1 = NIST-P-256 = prime256v1
///     StSECP384R1: ES384,  ;; ECDSA secp384r1 = NIST-P-384
///     StRSA2048:   RS256,  ;; RSA 2048 bit
///     StRSA3072:   RS384,  ;; RSA 3072 bit
///     StEPID10:    90,     ;; Intel® EPID 1.0 signature
///     StEPID11:    91      ;; Intel® EPID 1.1 signature
/// )
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "i64", into = "i64")]
#[repr(i64)]
pub(crate) enum DeviceSgType {
    /// ECDSA secp256r1 = NIST-P-256 = prime256v1
    StSecP256R1 = coset::iana::Algorithm::ES256 as i64,
    /// ECDSA secp384r1 = NIST-P-384
    StSecP384R1 = coset::iana::Algorithm::ES384 as i64,
    /// RSA 2048 bit
    StRsa2048 = coset::iana::Algorithm::RS256 as i64,
    /// RSA 3072 bit
    StRSA3072 = coset::iana::Algorithm::RS384 as i64,
    /// Intel® EPID 1.0 signature
    StEpid10 = 90,
    /// Intel® EPID 1.1 signature
    StEpid11 = 91,
}

impl TryFrom<i64> for DeviceSgType {
    type Error = eyre::Report;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        let value = match value {
            -7 => DeviceSgType::StSecP256R1,
            -35 => DeviceSgType::StSecP384R1,
            -257 => DeviceSgType::StRsa2048,
            -258 => DeviceSgType::StRSA3072,
            90 => DeviceSgType::StEpid10,
            91 => DeviceSgType::StEpid11,
            _ => bail!("value out of range: {value}"),
        };

        Ok(value)
    }
}

impl From<DeviceSgType> for i64 {
    fn from(value: DeviceSgType) -> Self {
        value as i64
    }
}
