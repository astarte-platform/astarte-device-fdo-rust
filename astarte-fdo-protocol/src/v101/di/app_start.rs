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

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::ErrorKind;
use crate::utils::CborBstr;
use crate::v101::{ClientMessage, InitialMessage, Message, Msgtype};
use crate::Error;

use super::set_credentials::SetCredentials;

#[derive(Debug)]
pub(crate) struct AppStart<'a, T> {
    device_mfg_info: CborBstr<'a, T>,
}

impl<'a, T> AppStart<'a, T> {
    pub(crate) fn new(device_mfg_info: T) -> Self {
        Self {
            device_mfg_info: CborBstr::new(device_mfg_info),
        }
    }
}

impl<'a, T> Serialize for AppStart<'a, T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self { device_mfg_info } = self;

        (device_mfg_info,).serialize(serializer)
    }
}

impl<'a, 'de, T> Deserialize<'de> for AppStart<'a, T>
where
    T: DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (device_mfg_info,) = Deserialize::deserialize(deserializer)?;

        Ok(Self { device_mfg_info })
    }
}

impl<'a, T> Message for AppStart<'a, T>
where
    T: Serialize,
    T: DeserializeOwned,
{
    const MSG_TYPE: Msgtype = 10;

    fn decode(buf: &[u8]) -> Result<Self, Error> {
        let this = ciborium::from_reader(buf).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error=%err, "couldn't decode AppStart");

            Error::new(ErrorKind::Decode, "the AppStart")
        })?;

        Ok(this)
    }

    fn encode<W>(&self, write: &mut W) -> Result<(), Error>
    where
        W: Write,
    {
        ciborium::into_writer(self, write).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error=%err, "couldn't encode AppStart");

            Error::new(ErrorKind::Encode, "the AppStart")
        })
    }
}

impl<'a, T> ClientMessage for AppStart<'a, T>
where
    T: Serialize,
    T: DeserializeOwned,
{
    type Response<'b> = SetCredentials<'b>;
}

impl<'a, T> InitialMessage for AppStart<'a, T>
where
    T: Serialize,
    T: DeserializeOwned,
{
}
