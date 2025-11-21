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
use crate::v101::sign_info::EBSigInfo;
use crate::v101::{Message, Msgtype, NonceTo1Proof};
use crate::Error;

/// ```cddl
/// TO1.HelloRVAck = [
///     NonceTO1Proof,
///     eBSigInfo
/// ]
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct HelloRvAck<'a> {
    pub(crate) nonce_to1_proof: NonceTo1Proof,
    pub(crate) e_a_sig_info: EBSigInfo<'a>,
}

impl<'a> HelloRvAck<'a> {
    /// Returns the rendezvous nonce.
    ///
    /// This is used to prove the device.
    pub fn nonce_to1_proof(&self) -> NonceTo1Proof {
        self.nonce_to1_proof
    }
}

impl Serialize for HelloRvAck<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            nonce_to1_proof,
            e_a_sig_info,
        } = self;

        (nonce_to1_proof, e_a_sig_info).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for HelloRvAck<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (nonce_to1_proof, e_a_sig_info) = Deserialize::deserialize(deserializer)?;

        Ok(Self {
            nonce_to1_proof,
            e_a_sig_info,
        })
    }
}

impl Message for HelloRvAck<'_> {
    const MSG_TYPE: Msgtype = 31;

    fn decode(buf: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(buf).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't decode TO1.HelloRvAck");

            Error::new(ErrorKind::Decode, "the TO1.HelloRvAck")
        })
    }

    fn encode<W>(&self, write: &mut W) -> Result<(), Error>
    where
        W: Write,
    {
        ciborium::into_writer(self, write).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't encode TO1.HelloRvAck");

            Error::new(ErrorKind::Encode, "the TO1.HelloRvAck")
        })
    }
}
