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
use std::io::Write;

use serde::{Deserialize, Serialize};

use crate::error::ErrorKind;
use crate::v101::key_exchange::KexSuitNames;
use crate::v101::sign_info::EASigInfo;
use crate::v101::{ClientMessage, Guid, InitialMessage, Message, Msgtype, NonceTo2ProveOv};
use crate::Error;

use super::prove_ov_hdr::ProveOvHdr;

/// ```cddl
/// TO2.HelloDevice = [
///     maxDeviceMessageSize,
///     Guid,
///     NonceTO2ProveOV,
///     kexSuiteName,
///     cipherSuiteName,
///     eASigInfo  ;; Device attestation signature info
/// ]
/// maxDeviceMessageSize = uint16
/// kexSuiteName = tstr
/// cipherSuiteName = CipherSuites
/// ```
#[derive(Debug)]
pub struct HelloDevice<'a> {
    pub(crate) max_device_message_size: u16,
    pub(crate) guid: Guid,
    pub(crate) nonce: NonceTo2ProveOv,
    pub(crate) kex_suite_name: Cow<'a, str>,
    pub(crate) cipher_suite_name: i64,
    pub(crate) ea_sign_info: EASigInfo<'a>,
}

impl<'a> HelloDevice<'a> {
    /// Creates the HelloDevice message.
    pub fn new(
        max_device_message_size: u16,
        guid: Guid,
        nonce: NonceTo2ProveOv,
        kex_suite_name: KexSuitNames,
        cipher_suite_name: i64,
        ea_sign_info: EASigInfo<'a>,
    ) -> Self {
        Self {
            max_device_message_size,
            guid,
            nonce,
            kex_suite_name: kex_suite_name.as_str().into(),
            cipher_suite_name,
            ea_sign_info,
        }
    }
}

impl Serialize for HelloDevice<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            max_device_message_size,
            guid,
            nonce,
            kex_suite_name,
            cipher_suite_name,
            ea_sign_info,
        } = self;

        (
            max_device_message_size,
            guid,
            nonce,
            kex_suite_name,
            cipher_suite_name,
            ea_sign_info,
        )
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for HelloDevice<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (max_device_message_size, guid, nonce, kex_suite_name, cipher_suite_name, ea_sign_info) =
            Deserialize::deserialize(deserializer)?;

        Ok(Self {
            max_device_message_size,
            guid,
            nonce,
            kex_suite_name,
            cipher_suite_name,
            ea_sign_info,
        })
    }
}

impl Message for HelloDevice<'_> {
    const MSG_TYPE: Msgtype = 60;

    fn decode(buf: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(buf).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't decode TO2.HelloDevice");

            Error::new(ErrorKind::Decode, "the TO2.HelloDevice")
        })
    }

    fn encode<W>(&self, write: &mut W) -> Result<(), Error>
    where
        W: Write,
    {
        ciborium::into_writer(self, write).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't encode TO2.HelloDevice");

            Error::new(ErrorKind::Decode, "the TO2.HelloDevice")
        })
    }
}

impl ClientMessage for HelloDevice<'_> {
    type Response<'a> = ProveOvHdr;
}

impl InitialMessage for HelloDevice<'_> {}
