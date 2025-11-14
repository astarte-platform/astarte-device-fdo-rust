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

use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use serde_bytes::Bytes;

use crate::error::ErrorKind;
use crate::Error;

fn parse_len_prefixed_slice(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (blen, rest) = bytes.split_first_chunk::<2>()?;

    let len: usize = u16::from_be_bytes(*blen).into();

    let first = rest.get(..len)?;
    let second = rest.get(len..)?;

    Some((first, second))
}

/// Key exchange from owner to device.
///
/// ```cddl
/// KeyExchange /= (
///     xAKeyExchange: bstr,
///     xBKeyExchange: bstr
/// )
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[repr(transparent)]
pub(crate) struct XAKeyExchange<'a>(Cow<'a, Bytes>);

impl<'a> XAKeyExchange<'a> {
    pub(crate) fn parse_ecdh(&self) -> Result<EcdhParams<'_>, crate::Error> {
        let rest = self.as_ref();

        let (x, rest) = parse_len_prefixed_slice(rest).ok_or(Error::new(
            ErrorKind::Invalid,
            "for len prefixed slice XAKeyExchange",
        ))?;
        let (y, rest) = parse_len_prefixed_slice(rest).ok_or(Error::new(
            ErrorKind::Invalid,
            "for len prefixed slice XAKeyExchange",
        ))?;
        let (rand, rest) = parse_len_prefixed_slice(rest).ok_or(Error::new(
            ErrorKind::Invalid,
            "for len prefixed slice XAKeyExchange",
        ))?;

        if !rest.is_empty() {
            return Err(Error::new(
                ErrorKind::Invalid,
                "for remaining bytes in XAKeyExchange",
            ));
        }

        Ok(EcdhParams { x, y, rand })
    }
}

impl AsRef<[u8]> for XAKeyExchange<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcdhParams<'a> {
    x: &'a [u8],
    y: &'a [u8],
    rand: &'a [u8],
}

impl<'a> EcdhParams<'a> {
    pub fn x(&self) -> &'a [u8] {
        self.x
    }

    pub fn y(&self) -> &'a [u8] {
        self.y
    }

    pub fn rand(&self) -> &'a [u8] {
        self.rand
    }
}

/// Key exchange from device to owner.
///
/// ```cddl
/// KeyExchange /= (
///     xAKeyExchange: bstr,
///     xBKeyExchange: bstr
/// )
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[repr(transparent)]
pub(crate) struct XBKeyExchange<'a>(pub(crate) Cow<'a, Bytes>);

impl XBKeyExchange<'static> {
    pub(crate) fn create(params: EcdhParams) -> Result<Self, Error> {
        let mut buf = Vec::new();

        let bx_len = u16::try_from(params.x.len())
            .map_err(|_| Error::new(ErrorKind::OutOfRange, "bx len too big"))?;
        let by_len = u16::try_from(params.y.len())
            .map_err(|_| Error::new(ErrorKind::OutOfRange, "by len too big"))?;
        let dv_rand_len = u16::try_from(params.rand.len())
            .map_err(|_| Error::new(ErrorKind::OutOfRange, "rand len too big"))?;

        buf.extend_from_slice(&bx_len.to_be_bytes());
        buf.extend_from_slice(params.x);
        buf.extend_from_slice(&by_len.to_be_bytes());
        buf.extend_from_slice(params.y);
        buf.extend_from_slice(&dv_rand_len.to_be_bytes());
        buf.extend_from_slice(params.rand);

        Ok(Self(Cow::Owned(buf.into())))
    }
}

impl AsRef<[u8]> for XBKeyExchange<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// ```cddl
/// IVData = bstr
/// ```
pub(crate) type IvData<'a> = Cow<'a, Bytes>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KexSuitNames {
    DHKEXid14,
    DHKEXid15,
    ASYMKEX2048,
    ASYMKEX3072,
    ECDH256,
    ECDH384,
}

impl KexSuitNames {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            KexSuitNames::DHKEXid14 => "DHKEXid14",
            KexSuitNames::DHKEXid15 => "DHKEXid15",
            KexSuitNames::ASYMKEX2048 => "ASYMKEX2048",
            KexSuitNames::ASYMKEX3072 => "ASYMKEX3072",
            KexSuitNames::ECDH256 => "ECDH256",
            KexSuitNames::ECDH384 => "ECDH384",
        }
    }
}
