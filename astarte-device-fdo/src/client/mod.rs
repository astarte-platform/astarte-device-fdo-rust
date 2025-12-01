// This file is part of Astarte.
//
// Copyright 2025, 2026 SECO Mind Srl
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

//! Client for the FDO protocol.

use std::io::Write;
use std::marker::PhantomData;

use astarte_fdo_protocol::error::ErrorKind;
use astarte_fdo_protocol::latest::Msgtype;
use astarte_fdo_protocol::v101::{ClientMessage, Message};
use astarte_fdo_protocol::Error;
use coset::{CoseEncrypt0, TaggedCborSerializable};
use tracing::error;

use crate::crypto::{Crypto, DefaultKeyExchange};

pub mod http;

struct EncMessage<T> {
    inner: CoseEncrypt0,
    _marker: PhantomData<T>,
}

impl<T> EncMessage<T> {
    fn create<C>(
        buf: &mut Vec<u8>,
        ctx: &mut C,
        key: &DefaultKeyExchange,
        msg: &T,
    ) -> Result<Self, Error>
    where
        T: Message,
        C: Crypto,
    {
        buf.clear();
        msg.encode(buf)?;

        ctx.cose_encrypt(key, buf).map(|inner| Self {
            inner,
            _marker: PhantomData,
        })
    }
}

impl<T> Message for EncMessage<T>
where
    T: Message,
{
    const MSG_TYPE: Msgtype = T::MSG_TYPE;

    fn decode(buf: &[u8]) -> Result<Self, Error> {
        CoseEncrypt0::from_tagged_slice(buf)
            .map(|inner| EncMessage {
                inner,
                _marker: PhantomData,
            })
            .map_err(|err| {
                error!(error = %err, "couldn't decode encrypted cose");

                Error::new(ErrorKind::Decode, "encrypted cose")
            })
    }

    fn encode<W>(&self, writer: &mut W) -> Result<(), Error>
    where
        W: Write,
    {
        self.inner
            .clone()
            .to_tagged_vec()
            .map_err(|err| {
                error!(error = %err, "couldn't encode encrypted cose");

                Error::new(ErrorKind::Encode, "encrypted cose")
            })
            .and_then(|buf| {
                writer.write_all(&buf).map_err(|err| {
                    error!(error = %err, "couldn't write encrypted cose");

                    Error::new(ErrorKind::Write, "encrypted cose")
                })
            })
    }
}

impl<T> ClientMessage for EncMessage<T>
where
    T: ClientMessage,
{
    type Response<'a> = T::Response<'a>;
}
