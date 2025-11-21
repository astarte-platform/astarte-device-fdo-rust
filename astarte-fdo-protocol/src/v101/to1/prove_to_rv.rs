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

use coset::{CoseSign1, TaggedCborSerializable};

use crate::error::ErrorKind;
use crate::v101::{ClientMessage, Message, Msgtype};
use crate::Error;

use super::rv_redirect::RvRedirect;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ProveToRv {
    pub(crate) ea_token: CoseSign1,
}

impl Message for ProveToRv {
    const MSG_TYPE: Msgtype = 32;

    fn decode(buf: &[u8]) -> Result<Self, Error> {
        // TODO: probably some validation is required here
        CoseSign1::from_tagged_slice(buf)
            .map(|ea_token| Self { ea_token })
            .map_err(|err| {
                #[cfg(feature = "tracing")]
                tracing::error!(error = %err, "couldn't decode TO1.ProveToRv");

                Error::new(ErrorKind::Decode, "the TO1.ProveToRv")
            })
    }

    fn encode<W>(&self, write: &mut W) -> Result<(), Error>
    where
        W: Write,
    {
        // TODO: coset requires allocations
        self.ea_token
            .clone()
            .to_tagged_vec()
            .map_err(|err| {
                #[cfg(feature = "tracing")]
                tracing::error!(error = %err, "couldn't encode TO1.ProveToRv");

                Error::new(ErrorKind::Encode, "the TO1.ProveToRv")
            })
            .and_then(|buf| {
                write.write_all(&buf).map_err(|err| {
                    #[cfg(feature = "tracing")]
                    tracing::error!(error = %err, "couldn't write TO1.ProveToRv");

                    Error::new(ErrorKind::Write, "the TO1.ProveToRv")
                })
            })
    }
}

impl ClientMessage for ProveToRv {
    type Response<'a> = RvRedirect;
}
