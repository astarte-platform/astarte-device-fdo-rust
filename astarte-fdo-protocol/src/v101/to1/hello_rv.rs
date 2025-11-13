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

use serde::{Deserialize, Serialize};

use crate::error::ErrorKind;
use crate::v101::sign_info::EASigInfo;
use crate::v101::{ClientMessage, Guid, InitialMessage, Message, Msgtype};
use crate::Error;

use super::hello_rv_ack::HelloRvAck;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct HelloRv<'a> {
    pub(crate) guid: Guid,
    pub(crate) e_a_sig_info: EASigInfo<'a>,
}

impl Serialize for HelloRv<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self { guid, e_a_sig_info } = self;

        (guid, e_a_sig_info).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for HelloRv<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (guid, e_a_sig_info) = Deserialize::deserialize(deserializer)?;

        Ok(Self { guid, e_a_sig_info })
    }
}

impl Message for HelloRv<'_> {
    const MSG_TYPE: Msgtype = 30;

    fn decode(buf: &[u8]) -> Result<Self, Error> {
        let this = ciborium::from_reader(buf).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't decode TO1.HelloRv");

            Error::new(ErrorKind::Decode, "the TO1.HelloRv")
        })?;

        Ok(this)
    }

    fn encode<W>(&self, write: &mut W) -> Result<(), Error>
    where
        W: Write,
    {
        ciborium::into_writer(self, write).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't encode TO1.HelloRv");

            Error::new(ErrorKind::Encode, "the TO1.HelloRv")
        })
    }
}

impl ClientMessage for HelloRv<'_> {
    type Response<'a> = HelloRvAck<'a>;
}

impl InitialMessage for HelloRv<'_> {}
