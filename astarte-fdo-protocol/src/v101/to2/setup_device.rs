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

use coset::{CoseSign1, TaggedCborSerializable};
use eyre::{Context, OptionExt};
use serde::{Deserialize, Serialize};

use crate::v101::public_key::PublicKey;
use crate::v101::randezvous_info::RendezvousInfo;
use crate::v101::{Guid, Message, Msgtype, NonceTo2SetupDv};

/// ```cddl
/// ;; This message replaces previous FIDO Device Onboard credentials with new ones
/// ;; Note that this signature is signed with a new (Owner2) key
/// ;; which is transmitted in this same message.
/// ;; The entire message is also verified by the integrity of the
/// ;; transmission medium.
/// TO2.SetupDevice = CoseSignature
/// TO2SetupDevicePayload = [
///     RendezvousInfo, ;; RendezvousInfo replacement
///     Guid,           ;; GUID replacement
///     NonceTO2SetupDv,         ;; proves freshness of signature
///     Owner2Key       ;; Replacement for Owner key
/// ]
/// Owner2Key = PublicKey
///
/// $COSEPayloads /= (
///     TO2SetupDevicePayload
/// )
/// ```
#[derive(Debug)]
pub(crate) struct SetupDevice {
    pub(crate) sign: CoseSign1,
}

impl SetupDevice {
    pub(crate) fn payload(&self) -> eyre::Result<SetupDevicePayload<'static>> {
        let payload = self.sign.payload.as_deref().ok_or_eyre("missing payload")?;

        ciborium::from_reader(payload).wrap_err("couldn't decode payload")
    }
}

impl Message for SetupDevice {
    const MSG_TYPE: Msgtype = 65;

    fn decode(buf: &[u8]) -> eyre::Result<Self> {
        let sign = CoseSign1::from_tagged_slice(buf)?;

        Ok(SetupDevice { sign })
    }

    fn encode(&self) -> eyre::Result<Vec<u8>> {
        let buf = self.sign.clone().to_tagged_vec()?;

        Ok(buf)
    }
}

#[derive(Debug)]
pub(crate) struct SetupDevicePayload<'a> {
    pub(crate) rendezvous_info: RendezvousInfo<'a>,
    pub(crate) guid: Guid,
    pub(crate) nonce_to2_setup_dv: NonceTo2SetupDv,
    pub(crate) owner_2_key: PublicKey<'a>,
}

impl Serialize for SetupDevicePayload<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            rendezvous_info,
            guid,
            nonce_to2_setup_dv,
            owner_2_key,
        } = self;

        (rendezvous_info, guid, nonce_to2_setup_dv, owner_2_key).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SetupDevicePayload<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (rendezvous_info, guid, nonce_to2_setup_dv, owner_2_key) =
            Deserialize::deserialize(deserializer)?;

        Ok(Self {
            rendezvous_info,
            guid,
            nonce_to2_setup_dv,
            owner_2_key,
        })
    }
}
