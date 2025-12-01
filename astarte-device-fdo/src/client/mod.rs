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

#[derive(Debug)]
struct EncMessage<M> {
    inner: CoseEncrypt0,
    _message: PhantomData<M>,
}

impl<M> EncMessage<M> {
    fn new(inner: CoseEncrypt0) -> Self {
        Self {
            inner,
            _message: PhantomData,
        }
    }

    fn create<C>(
        buf: &mut Vec<u8>,
        crypto: &mut C,
        key: &DefaultKeyExchange,
        msg: &M,
    ) -> Result<Self, Error>
    where
        M: Message,
        C: Crypto,
    {
        buf.clear();
        msg.encode(buf)?;

        crypto.cose_encrypt(key, buf).map(Self::new)
    }

    fn message<C>(&self, key: &DefaultKeyExchange) -> Result<M, Error>
    where
        M: Message,
        C: Crypto,
    {
        let msg = C::cose_decrypt(&self.inner, key)?;

        M::decode(&msg)
    }
}

impl<M> Message for EncMessage<M>
where
    M: Message,
{
    const MSG_TYPE: Msgtype = M::MSG_TYPE;

    fn decode(buf: &[u8]) -> Result<Self, Error> {
        CoseEncrypt0::from_tagged_slice(buf)
            .map_err(|err| {
                error!(error = %err, "couldn't decode encrypted cose");

                Error::new(ErrorKind::Decode, "encrypted cose")
            })
            .map(Self::new)
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

impl<M> ClientMessage for EncMessage<M>
where
    M: ClientMessage,
{
    type Response<'a> = EncMessage<M::Response<'a>>;
}
