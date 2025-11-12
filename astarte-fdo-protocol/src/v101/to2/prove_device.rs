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

use coset::TaggedCborSerializable;
use eyre::Context;

use crate::v101::eat_signature::EaToken;
use crate::v101::{ClientMessage, Message, Msgtype};

use super::setup_device::SetupDevice;

/// ```cddl
/// TO2.ProveDevice = EAToken
/// $$EATPayloadBase //= (
///     EAT-NONCE: NonceTO2ProveDv
/// )
/// TO2ProveDevicePayload = [
///     xBKeyExchange
/// ]
/// $EATUnprotectedHeaders /= (
///     EUPHNonce: NonceTO2SetupDv ;; NonceTO2SetupDv is used in TO2.SetupDevice and TO2.Done2
/// )
/// $EATPayloads /= (
///     TO2ProveDevicePayload
/// )
/// ```
#[derive(Debug)]
pub(crate) struct ProveDevice {
    pub(crate) sign: EaToken,
}

impl Message for ProveDevice {
    const MSG_TYPE: Msgtype = 64;

    fn decode(buf: &[u8]) -> eyre::Result<Self> {
        EaToken::from_tagged_slice(buf)
            .map(|sign| ProveDevice { sign })
            .wrap_err("couldn't decode prove device EAToken")
    }

    fn encode(&self) -> eyre::Result<Vec<u8>> {
        self.sign
            .clone()
            .to_tagged_vec()
            .wrap_err("couldn't encode prove device EAToken")
    }
}

impl ClientMessage for ProveDevice {
    type Response<'a> = SetupDevice;
}
