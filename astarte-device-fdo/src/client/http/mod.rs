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

//! FDO client for the HTTP protocol

use std::time::Duration;

use astarte_fdo_protocol::Error;
use astarte_fdo_protocol::error::ErrorKind;
use astarte_fdo_protocol::v101::error::ErrorMessage;
use astarte_fdo_protocol::v101::{
    ClientMessage, InitialMessage, Message, Msgtype, PROTOCOL_VERSION, Protver,
};
use http::header::AUTHORIZATION;
use http::{HeaderMap, StatusCode, header};
use reqwest::Method;
use reqwest::header::{HeaderName, HeaderValue};
use rustls::ClientConfig;
use tracing::{error, trace, warn};
use url::Url;

use crate::crypto::DefaultKeyExchange;
use crate::{Crypto, Ctx};

use self::retry::HttpRetry;

use super::EncMessage;

mod retry;

const CBOR_MIME: HeaderValue = HeaderValue::from_static("application/cbor");
const MESSAGE_TYPE_HEADER: HeaderName = HeaderName::from_static("message-type");
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// Response with a parsed Message Type and authorization header.
#[derive(Debug)]
struct HttpResponse {
    msg_type: Msgtype,
    authorization: HeaderValue,
    inner: reqwest::Response,
}

/// Initial client to start an HTTP session
#[derive(Debug)]
pub struct InitialClient {
    inner: HttpClient,
}

impl InitialClient {
    /// Creates the client
    pub fn create(base_url: Url, tls: ClientConfig) -> Result<Self, Error> {
        HttpClient::create(base_url, tls).map(|inner| Self { inner })
    }

    /// Sets the authorization header for the session
    pub(crate) fn into_session(self, authorization: HeaderValue) -> AuthClient {
        AuthClient {
            authorization,
            inner: self.inner,
        }
    }

    pub(crate) async fn send<M>(
        &mut self,
        msg: &M,
    ) -> Result<(M::Response<'static>, HeaderValue), Error>
    where
        M: InitialMessage,
    {
        let req = self.inner.create_req(msg)?;
        let resp = self.inner.send_with_retry(req).await?;
        let resp = HttpClient::handle_repsonse(resp).await?;

        let msg = HttpClient::parse_msg::<M::Response<'static>>(resp.msg_type, resp.inner).await?;

        Ok((msg, resp.authorization))
    }

    pub(crate) async fn send_without_retry<M>(
        &mut self,
        msg: &M,
    ) -> Result<(M::Response<'static>, HeaderValue), Error>
    where
        M: InitialMessage,
    {
        let req = self.inner.create_req(msg)?;
        let resp = self.inner.send_single(req).await?;
        let resp = HttpClient::handle_repsonse(resp).await?;

        let msg = HttpClient::parse_msg::<M::Response<'static>>(resp.msg_type, resp.inner).await?;

        Ok((msg, resp.authorization))
    }
}

#[derive(Debug)]
pub(crate) struct AuthClient {
    authorization: HeaderValue,
    inner: HttpClient,
}

impl AuthClient {
    // Send a message with the current session
    pub(crate) async fn send<M>(&mut self, msg: &M) -> Result<M::Response<'static>, Error>
    where
        M: ClientMessage,
    {
        let resp = self.send_msg(msg).await?;

        let msg = HttpClient::parse_msg::<M::Response<'static>>(resp.msg_type, resp.inner).await?;

        Ok(msg)
    }

    pub(crate) async fn send_err(&mut self, err_msg: &ErrorMessage<'_>) -> Result<(), Error> {
        let mut req = self.inner.create_req(err_msg)?;
        req.headers_mut()
            .insert(AUTHORIZATION, self.authorization.clone());

        let resp = self.inner.send_with_retry(req).await?;

        trace!("HTTP response status {}", resp.status());

        Ok(())
    }

    /// Sends a generic FDO message without parsing the result
    async fn send_msg<M>(&mut self, msg: &M) -> Result<HttpResponse, Error>
    where
        M: Message,
    {
        let mut req = self.inner.create_req(msg)?;
        req.headers_mut()
            .insert(AUTHORIZATION, self.authorization.clone());

        let resp = self.inner.send_with_retry(req).await?;
        let resp = HttpClient::handle_repsonse(resp).await?;

        if resp.authorization != self.authorization {
            return Err(Error::new(ErrorKind::Invalid, "HTTP authorization header"));
        }

        Ok(resp)
    }

    pub(crate) fn into_encrypted(self, key: DefaultKeyExchange) -> EncryptedClient {
        EncryptedClient { key, inner: self }
    }
}

#[derive(Debug)]
pub(crate) struct EncryptedClient {
    key: DefaultKeyExchange,
    inner: AuthClient,
}

impl EncryptedClient {
    pub(crate) async fn send_plain<C, M>(&mut self, msg: &M) -> Result<M::Response<'static>, Error>
    where
        M: ClientMessage,
        C: Crypto,
    {
        let resp = self.inner.send_msg(msg).await?;

        let resp =
            HttpClient::parse_msg::<EncMessage<M::Response<'static>>>(resp.msg_type, resp.inner)
                .await?;

        resp.message::<C>(&self.key)
    }

    pub(crate) async fn send<C, S, M>(
        &mut self,
        ctx: &mut Ctx<'_, C, S>,
        msg: &M,
    ) -> Result<M::Response<'static>, Error>
    where
        M: ClientMessage,
        C: Crypto,
    {
        let msg = EncMessage::create(&mut self.inner.inner.buf, ctx.crypto, &self.key, msg)?;

        let resp = self.inner.send(&msg).await?;

        resp.message::<C>(&self.key)
    }
}

/// Client for the HTTP or HTTPS transport protocol
#[derive(Debug, Clone)]
pub(crate) struct HttpClient {
    base_url: Url,
    protocol_version: Protver,
    retry: HttpRetry,
    buf: Vec<u8>,
    inner: reqwest::Client,
}

impl HttpClient {
    /// Create the HTTP client from a base_url
    pub fn create(base_url: Url, tls: rustls::ClientConfig) -> Result<Self, Error> {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, CBOR_MIME);

        let inner = reqwest::ClientBuilder::new()
            .use_preconfigured_tls(tls)
            .default_headers(headers)
            // TODO: consider 302 and 307 for redirect in TO1.HelloRV
            .redirect(reqwest::redirect::Policy::none())
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .map_err(|err| {
                error!(error = %err, "couldn't build the client");

                Error::new(ErrorKind::Invalid, "client")
            })?;

        Ok(Self {
            base_url,
            protocol_version: PROTOCOL_VERSION,
            buf: Vec::new(),
            retry: HttpRetry::new(),
            inner,
        })
    }

    async fn handle_repsonse(mut resp: reqwest::Response) -> Result<HttpResponse, Error> {
        trace!("HTTP response status {}", resp.status());

        let headers = resp.headers();

        Self::check_content_type(headers)?;
        let msg_type = Self::get_message_type(headers)?;
        let authorization = Self::get_authorization(resp.headers_mut())?;

        let resp = HttpResponse {
            msg_type,
            authorization,
            inner: resp,
        };

        match resp.inner.status() {
            StatusCode::OK if msg_type == ErrorMessage::MSG_TYPE => {
                trace!("HTTP response message type ErrorMessage");

                Err(Self::parse_error_msg(resp).await)
            }
            StatusCode::OK => {
                trace!("HTTP response status OK");

                Ok(resp)
            }
            StatusCode::INTERNAL_SERVER_ERROR => {
                trace!("HTTP response status INTERNAL_SERVER_ERROR");

                Err(Self::parse_error_msg(resp).await)
            }
            status => {
                error!(%status, "responce has invalid status code");

                Err(Error::new(
                    ErrorKind::Io,
                    "invalid HTTP status code in response",
                ))
            }
        }
    }

    fn make_url<T>(&self) -> Result<Url, Error>
    where
        T: Message,
    {
        self.base_url
            .join(&format!(
                "/fdo/{}/msg/{}",
                self.protocol_version,
                T::MSG_TYPE
            ))
            .map_err(|err| {
                error!(error = %err, "couldn't parse URL");

                Error::new(ErrorKind::Invalid, "url")
            })
    }

    // TODO: this could receive the body directly
    fn create_req<M>(&mut self, msg: &M) -> Result<reqwest::Request, Error>
    where
        M: Message,
    {
        self.buf.clear();
        msg.encode(&mut self.buf)?;

        let url = self.make_url::<M>()?;
        let mut req = reqwest::Request::new(Method::POST, url);
        req.body_mut().replace(self.buf.clone().into());

        req.headers_mut()
            .insert(MESSAGE_TYPE_HEADER, M::MSG_TYPE.into());

        Ok(req)
    }

    async fn parse_error_msg(response: HttpResponse) -> Error {
        let error: ErrorMessage = match Self::parse_msg(response.msg_type, response.inner).await {
            Ok(err) => err,
            Err(error) => {
                error!("couldn't decode error message");

                return error;
            }
        };

        error!(%error, "response containing error messagge received");

        Error::new(ErrorKind::Message, "error messasge received")
    }

    async fn parse_msg<T>(msg_type: Msgtype, resp: reqwest::Response) -> Result<T, Error>
    where
        T: Message,
    {
        if msg_type != T::MSG_TYPE {
            error!(
                expected = T::MSG_TYPE,
                value = msg_type,
                "received invalid message-type header"
            );

            return Err(Error::new(ErrorKind::Invalid, "HTTP message-type header"));
        }

        let bytes = resp.bytes().await.map_err(|err| {
            error!(error = %err, "couldn't read request body");

            Error::new(ErrorKind::Io, "read request body")
        })?;

        trace!(msg = %astarte_fdo_protocol::utils::Hex::new(&bytes));

        let value = T::decode(&bytes)?;

        Ok(value)
    }

    fn get_message_type(headers: &HeaderMap) -> Result<Msgtype, Error> {
        headers
            .get(MESSAGE_TYPE_HEADER)
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
            })
    }

    fn get_authorization(headers: &mut HeaderMap) -> Result<HeaderValue, Error> {
        headers
            .remove(header::AUTHORIZATION)
            .map(|mut header| {
                header.set_sensitive(true);

                header
            })
            .ok_or(Error::new(
                ErrorKind::Invalid,
                "HTTP authorization header missing",
            ))
    }

    fn check_content_type(headers: &HeaderMap) -> Result<(), Error> {
        let content_type = headers.get(header::CONTENT_TYPE).ok_or(Error::new(
            ErrorKind::Invalid,
            "HTTP Content-Type header missing",
        ))?;

        if content_type != CBOR_MIME {
            let content_type = String::from_utf8_lossy(content_type.as_bytes());

            error!(%content_type, "invalid CONTENT_TYPE header");

            return Err(Error::new(ErrorKind::Invalid, "HTTP mime type"));
        }

        Ok(())
    }

    async fn send_with_retry(&mut self, req: reqwest::Request) -> Result<reqwest::Response, Error> {
        let req_cl = req.try_clone();

        let mut resp = self.send_single(req).await;

        let Some(req) = req_cl else {
            warn!("couldn't clone the request");

            return resp;
        };

        while let Some(retry) = self.retry.retry(&resp) {
            retry.await;

            let Some(req_cl) = req.try_clone() else {
                return resp;
            };

            resp = self.inner.execute(req_cl).await.map_err(|err| {
                error!(error = %err, "couldn't send HTTP request");

                Error::new(ErrorKind::Io, "send HTTP request")
            });
        }

        resp
    }

    async fn send_single(&mut self, req: reqwest::Request) -> Result<reqwest::Response, Error> {
        self.inner.execute(req).await.map_err(|err| {
            error!(error = %err, "couldn't send HTTP request");

            Error::new(ErrorKind::Io, "send HTTP request")
        })
    }
}
