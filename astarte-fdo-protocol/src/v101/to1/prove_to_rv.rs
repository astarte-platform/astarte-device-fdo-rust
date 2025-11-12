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

use crate::v101::{ClientMessage, Message, Msgtype};

use super::rv_redirect::RvRedirect;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ProveToRv {
    pub(crate) ea_token: CoseSign1,
}

impl Message for ProveToRv {
    const MSG_TYPE: Msgtype = 32;

    fn decode(buf: &[u8]) -> eyre::Result<Self> {
        let ea_token = CoseSign1::from_tagged_slice(buf)?;

        // TODO: probably some validation is required here
        Ok(Self { ea_token })
    }

    fn encode(&self) -> eyre::Result<Vec<u8>> {
        // coset requires allocations
        let buf = self.ea_token.clone().to_tagged_vec()?;

        Ok(buf)
    }
}

impl ClientMessage for ProveToRv {
    type Response<'a> = RvRedirect;
}
