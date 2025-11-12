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

use eyre::{ensure, Context, OptionExt};
use serde::{Deserialize, Serialize};
use serde_bytes::Bytes;

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
    pub(crate) fn parse_ecdh(&self) -> eyre::Result<(&[u8], &[u8], &[u8])> {
        let rest = self.as_ref();

        let (ax, rest) = parse_len_prefixed_slice(rest).ok_or_eyre("couldn't parse Ax")?;
        let (ay, rest) = parse_len_prefixed_slice(rest).ok_or_eyre("couldn't parse Ay")?;
        let (owner_rand, rest) =
            parse_len_prefixed_slice(rest).ok_or_eyre("couldn't parse Owner Random")?;

        ensure!(rest.is_empty(), "remaining bytes in input");

        Ok((ax, ay, owner_rand))
    }
}

impl AsRef<[u8]> for XAKeyExchange<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.0
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
    pub(crate) fn create(bx: &[u8], by: &[u8], dv_rand: &[u8]) -> eyre::Result<Self> {
        let mut buf = Vec::new();

        let bx_len = u16::try_from(bx.len()).wrap_err("bx len too big")?;
        let by_len = u16::try_from(by.len()).wrap_err("by len too big")?;
        let dv_rand_len = u16::try_from(dv_rand.len()).wrap_err("dv_rand len too big")?;

        buf.extend_from_slice(&bx_len.to_be_bytes());
        buf.extend_from_slice(bx);
        buf.extend_from_slice(&by_len.to_be_bytes());
        buf.extend_from_slice(by);
        buf.extend_from_slice(&dv_rand_len.to_be_bytes());
        buf.extend_from_slice(dv_rand);

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
