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
use astarte_fdo_protocol::latest::error::ErrorMessage;
use astarte_fdo_protocol::latest::Msgtype;
use astarte_fdo_protocol::v101::{
    ClientMessage, InitialMessage, Message, Protver, PROTOCOL_VERSION,
};
use astarte_fdo_protocol::Error;
use coset::{CoseEncrypt0, TaggedCborSerializable};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::StatusCode;
use tracing::{debug, error, trace};
use url::Url;

use crate::crypto::{Crypto, DefaultKeyExchange};

const MIME: HeaderValue = HeaderValue::from_static("application/cbor");
const MESSAGE_TYPE: HeaderName = HeaderName::from_static("message-type");

/// The client needs authentication
#[derive(Debug)]
pub struct NeedsAuth {}

/// The client needs encryption
#[derive(Debug)]
pub struct NeedsEncryption {}

/// Http FDO client
#[derive(Debug)]
pub struct Client<A = HeaderValue, E = NeedsEncryption> {
    auth: A,
    base_url: Url,
    protocol_version: Protver,
    client: reqwest::Client,
    buf: Vec<u8>,
    key: E,
}

impl<A, E> Client<A, E> {
    async fn send<T>(
        &mut self,
        msg: &T,
        auth: Option<HeaderValue>,
    ) -> Result<reqwest::Response, Error>
    where
        T: Message,
    {
        let url = self
            .base_url
            .join(&format!(
                "/fdo/{}/msg/{}",
                self.protocol_version,
                T::MSG_TYPE
            ))
            .map_err(|err| {
                error!(error = %err, "couldn't parse URL");

                Error::new(ErrorKind::Invalid, "url")
            })?;

        debug!(%url, "sending message");

        self.buf.clear();
        msg.encode(&mut self.buf)?;

        let mut req = self.client.post(url).header(MESSAGE_TYPE, T::MSG_TYPE);

        if let Some(token) = auth {
            req = req.header(AUTHORIZATION, token);
        }

        let response = req
            // TODO: improve
            .body(self.buf.clone())
            .send()
            .await
            .map_err(|err| {
                error!(error = %err, "couldn't send HTTP request");

                Error::new(ErrorKind::Io, "send HTTP request")
            })?;

        Ok(response)
    }

    async fn send_with_resp<T>(
        &mut self,
        msg: &T,
        auth: Option<HeaderValue>,
    ) -> Result<reqwest::Response, Error>
    where
        T: ClientMessage,
    {
        let response = self.send(msg, auth).await?;

        // TODO: consider 302 and 307 for redirect in TO1.HelloRV
        match response.status() {
            StatusCode::OK => {
                trace!("HTTP response status OK")
            }
            StatusCode::INTERNAL_SERVER_ERROR => {
                trace!("HTTP response status INTERNAL_SERVER_ERROR");

                if !response.headers().contains_key(AUTHORIZATION) {
                    error!("couldn't handle response, missing authorization token");

                    return Err(Error::new(ErrorKind::Invalid, "authorization token"));
                }

                return Err(Self::parse_error_msg(response).await);
            }
            status => {
                error!(%status, "responce has invalid status code");

                return Err(Error::new(
                    ErrorKind::Io,
                    "invalid HTTP status code in response",
                ));
            }
        }

        let msg_type = response
            .headers()
            .get(MESSAGE_TYPE)
            .ok_or(Error::new(
                ErrorKind::Invalid,
                "message type header in response",
            ))
            .and_then(|msg_type| {
                let msg_type = msg_type.to_str().map_err(|err| {
                    error!(error = %err, "couldn't convert header value to string");

                    Error::new(ErrorKind::Invalid, "UTF-8 string")
                })?;

                let msg_type: Msgtype = msg_type.parse().map_err(|err| {
                    error!(error = %err,msg_type, "couldn't parse message-type");

                    Error::new(ErrorKind::Invalid, "message-type")
                })?;

                Ok(msg_type)
            })?;

        // TODO: should check the error code
        if msg_type == ErrorMessage::MSG_TYPE {
            return Err(Self::parse_error_msg(response).await);
        }

        if msg_type != T::Response::MSG_TYPE {
            error!(
                recv = msg_type,
                exp = T::Response::MSG_TYPE,
                "response message-type mismatch"
            );

            return Err(Error::new(ErrorKind::Invalid, ""));
        }

        Ok(response)
    }

    async fn parse_error_msg(response: reqwest::Response) -> Error {
        let error: ErrorMessage = match Self::parse_msg(response).await {
            Ok(err) => err,
            Err(error) => {
                error!("couldn't decode error message");

                return error;
            }
        };

        error!(%error, "protocol errro, error messagage received");

        Error::new(ErrorKind::Message, "error messasge received")
    }

    async fn parse_msg<T>(resp: reqwest::Response) -> Result<T, Error>
    where
        T: Message,
    {
        let bytes = resp.bytes().await.map_err(|err| {
            error!(error = %err, "couldn't read request body");

            Error::new(ErrorKind::Io, "read request body")
        })?;

        trace!(msg = %astarte_fdo_protocol::utils::Hex::new(&bytes));

        let value = T::decode(&bytes)?;

        Ok(value)
    }

    async fn parse_enc_msg<T, C>(
        key: &DefaultKeyExchange,
        resp: reqwest::Response,
    ) -> Result<T, Error>
    where
        C: Crypto,
        T: Message,
    {
        let bytes = resp.bytes().await.map_err(|err| {
            error!(error = %err, "request errord");

            Error::new(ErrorKind::Io, "request")
        })?;

        let enc = CoseEncrypt0::from_tagged_slice(&bytes).map_err(|err| {
            error!(error = %err, "couldn't decode encrypt message");

            Error::new(ErrorKind::Decode, "cose encrypted message")
        })?;

        let plain = C::cose_decrypt(&enc, key)?;

        T::decode(&plain)
    }
}

impl Client<NeedsAuth, NeedsEncryption> {
    /// Create the HTTP client from a base_url
    pub fn create(base_url: Url, tls: rustls::ClientConfig) -> Result<Self, Error> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, MIME);

        let client = reqwest::ClientBuilder::new()
            .use_preconfigured_tls(tls)
            .default_headers(headers)
            // TODO: consider 302 and 307 for redirect in TO1.HelloRV
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| {
                error!(error = %err, "couldn't build the client");

                Error::new(ErrorKind::Invalid, "client")
            })?;

        Ok(Self {
            base_url,
            protocol_version: PROTOCOL_VERSION,
            client,
            buf: Vec::with_capacity(512),
            auth: NeedsAuth {},
            key: NeedsEncryption {},
        })
    }

    pub(crate) async fn init<T>(
        &mut self,
        msg: &T,
    ) -> Result<(T::Response<'static>, HeaderValue), Error>
    where
        T: InitialMessage,
    {
        let resp = self.send_with_resp(msg, None).await?;

        let mut auth = resp
            .headers()
            .get(AUTHORIZATION)
            .ok_or(Error::new(
                ErrorKind::Invalid,
                "missing authorization header",
            ))?
            .clone();

        auth.set_sensitive(true);

        let msg = Self::parse_msg(resp).await?;

        Ok((msg, auth))
    }

    pub(crate) fn set_auth(self, auth: HeaderValue) -> Client<HeaderValue, NeedsEncryption> {
        Client {
            auth,
            base_url: self.base_url,
            protocol_version: self.protocol_version,
            buf: self.buf,
            client: self.client,
            key: self.key,
        }
    }
}

impl Client<HeaderValue, NeedsEncryption> {
    pub(crate) async fn send_msg<T>(&mut self, msg: &T) -> Result<T::Response<'static>, Error>
    where
        T: ClientMessage,
    {
        let resp = self.send_with_resp(msg, Some(self.auth.clone())).await?;

        Self::parse_msg(resp).await
    }

    pub(crate) async fn send_err(&mut self, msg: &ErrorMessage<'_>) -> bool {
        if let Err(err) = self.send(msg, Some(self.auth.clone())).await {
            error!(error = format!("{err:#}"), "couldn't send error message");

            return false;
        }

        true
    }

    pub(crate) fn set_enckey<E>(self, key: E) -> Client<HeaderValue, E> {
        Client {
            auth: self.auth,
            base_url: self.base_url,
            protocol_version: self.protocol_version,
            buf: self.buf,
            client: self.client,
            key,
        }
    }

    pub(crate) async fn init_enc<T, C>(
        &mut self,
        key: &DefaultKeyExchange,
        msg: &T,
    ) -> Result<T::Response<'static>, Error>
    where
        C: Crypto,
        T: ClientMessage,
    {
        let resp = self.send_with_resp(msg, Some(self.auth.clone())).await?;

        Self::parse_enc_msg::<_, C>(key, resp).await
    }
}

impl Client<HeaderValue, DefaultKeyExchange> {
    pub(crate) async fn send_enc<T, C>(
        &mut self,
        ctx: &mut C,
        msg: &T,
    ) -> Result<T::Response<'static>, Error>
    where
        C: Crypto,
        T: ClientMessage,
    {
        let msg = EncMessage::create(&mut self.buf, ctx, &self.key, msg)?;

        let resp = self.send_with_resp(&msg, Some(self.auth.clone())).await?;

        Self::parse_enc_msg::<_, C>(&self.key, resp).await
    }
}

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
