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
use std::fmt::Debug;

use eyre::bail;
use serde::{Deserialize, Serialize};
use serde_bytes::Bytes;

use crate::utils::Hex;

/// Crypto hash
///
/// ```cddl
/// Hash = [
///     hashtype: int, ;; negative values possible
///     hash: bstr
/// ]
/// ```
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Hash<'a> {
    pub(crate) hashtype: Hashtype,
    pub(crate) hash: Cow<'a, Bytes>,
}

impl<'a> Hash<'a> {
    pub(crate) fn into_owned(self) -> Hash<'static> {
        Hash {
            hashtype: self.hashtype,
            hash: Cow::Owned(self.hash.into_owned()),
        }
    }
}

impl Debug for Hash<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hash")
            .field("hashtype", &self.hashtype)
            .field("hash", &Hex::new(&self.hash))
            .finish()
    }
}

impl Serialize for Hash<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self { hashtype, hash } = self;

        (hashtype, hash).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Hash<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (hashtype, hash) = Deserialize::deserialize(deserializer)?;

        Ok(Self { hashtype, hash })
    }
}

/// A HMAC [RFC2104] is encoded as a hash.
///
/// ```cddl
/// HMac = Hash
/// ```
pub(crate) type HMac<'a> = Hash<'a>;

/// ```cddl
/// hashtype = (
///     SHA256: -16,
///     SHA384: -43,
///     HMAC-SHA256: 5,
///     HMAC-SHA384: 6
/// )
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "i8", into = "i8")]
#[repr(i8)]
pub(crate) enum Hashtype {
    Sha256 = -16,
    Sha384 = -43,
    HmacSha256 = 5,
    HmacSha384 = 6,
}

impl Hashtype {
    pub(crate) fn is_hmac(&self) -> bool {
        match self {
            Hashtype::HmacSha256 | Hashtype::HmacSha384 => true,
            Hashtype::Sha256 | Hashtype::Sha384 => false,
        }
    }

    pub(crate) fn is_hash(&self) -> bool {
        match self {
            Hashtype::Sha256 | Hashtype::Sha384 => true,
            Hashtype::HmacSha256 | Hashtype::HmacSha384 => false,
        }
    }
}

impl TryFrom<i8> for Hashtype {
    type Error = eyre::Report;

    fn try_from(value: i8) -> Result<Self, Self::Error> {
        let value = match value {
            -16 => Hashtype::Sha256,
            -43 => Hashtype::Sha384,
            5 => Hashtype::HmacSha256,
            6 => Hashtype::HmacSha384,
            _ => bail!("value out of range: {value}"),
        };

        Ok(value)
    }
}

impl From<Hashtype> for i8 {
    fn from(value: Hashtype) -> Self {
        value as i8
    }
}
