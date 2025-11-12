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
use eyre::{ensure, OptionExt};
use serde::{Deserialize, Serialize};

use crate::v101::hash_hmac::Hash;
use crate::v101::rv_to2_addr::RvTo2Addr;
use crate::v101::{Message, Msgtype};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RvRedirect {
    pub(crate) to1d: CoseSign1,
}

impl RvRedirect {
    pub(crate) fn rv_to2_addr(&self) -> eyre::Result<To1dBlob<'_>> {
        let payload = self.to1d.payload.as_ref().ok_or_eyre("payload missing")?;

        let rv_addr = ciborium::from_reader(payload.as_slice())?;

        Ok(rv_addr)
    }
}

impl Message for RvRedirect {
    const MSG_TYPE: Msgtype = 33;

    fn decode(buf: &[u8]) -> eyre::Result<Self> {
        let to1d = CoseSign1::from_tagged_slice(buf)?;

        ensure!(to1d.payload.is_some(), "to1d payload missing");

        Ok(Self { to1d })
    }

    fn encode(&self) -> eyre::Result<Vec<u8>> {
        let buf = self.to1d.clone().to_tagged_vec()?;

        Ok(buf)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct To1dBlob<'a> {
    pub(crate) to1d_rv: RvTo2Addr<'a>,
    pub(crate) to1d_to0d_hash: Hash<'a>,
}

impl Serialize for To1dBlob<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            to1d_rv,
            to1d_to0d_hash,
        } = self;

        (to1d_rv, to1d_to0d_hash).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for To1dBlob<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (to1d_rv, to1d_to0d_hash) = Deserialize::deserialize(deserializer)?;

        Ok(Self {
            to1d_rv,
            to1d_to0d_hash,
        })
    }
}
