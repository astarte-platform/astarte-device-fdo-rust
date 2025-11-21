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

//! Protocol digests and signatures

use std::borrow::Cow;
use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use serde_bytes::Bytes;

use crate::error::ErrorKind;
use crate::utils::Hex;
use crate::Error;

/// Crypto hash
///
/// ```cddl
/// Hash = [
///     hashtype: int, ;; negative values possible
///     hash: bstr
/// ]
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Hash<'a> {
    pub(crate) hashtype: Hashtype,
    pub(crate) hash: Cow<'a, Bytes>,
}

impl<'a> Hash<'a> {
    /// Return an owned instance of the Hash.
    pub fn into_owned(self) -> Hash<'static> {
        Hash {
            hashtype: self.hashtype,
            hash: Cow::Owned(self.hash.into_owned()),
        }
    }
}

impl Debug for Hash<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { hashtype, hash } = self;

        f.debug_struct("Hash")
            .field("hashtype", &hashtype)
            .field("hash", &Hex::new(hash))
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

/// A HMAC RFC2104 is encoded as a hash.
///
/// ```cddl
/// HMac = Hash
/// ```
pub type HMac<'a> = Hash<'a>;

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
pub enum Hashtype {
    /// Sha256 Hash digest
    Sha256 = -16,
    /// Sha384 Hash digest
    Sha384 = -43,
    /// HMAC-SHA256 signature
    HmacSha256 = 5,
    /// HMAC-SHA384 signature
    HmacSha384 = 6,
}

impl Hashtype {
    /// Check if the hash type is a HMAC
    pub fn is_hmac(&self) -> bool {
        match self {
            Hashtype::HmacSha256 | Hashtype::HmacSha384 => true,
            Hashtype::Sha256 | Hashtype::Sha384 => false,
        }
    }

    /// Check if the hash type is a Digest
    pub fn is_hash(&self) -> bool {
        match self {
            Hashtype::Sha256 | Hashtype::Sha384 => true,
            Hashtype::HmacSha256 | Hashtype::HmacSha384 => false,
        }
    }
}

impl TryFrom<i8> for Hashtype {
    type Error = Error;

    fn try_from(value: i8) -> Result<Self, Self::Error> {
        let value = match value {
            -16 => Hashtype::Sha256,
            -43 => Hashtype::Sha384,
            5 => Hashtype::HmacSha256,
            6 => Hashtype::HmacSha384,
            _ => return Err(Error::new(ErrorKind::OutOfRange, "for HashType")),
        };

        Ok(value)
    }
}

impl From<Hashtype> for i8 {
    fn from(value: Hashtype) -> Self {
        value as i8
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use pretty_assertions::assert_eq;

    use crate::v101::tests::from_hex;

    use super::*;

    pub(crate) fn create_hash() -> Hash<'static> {
        Hash {
            hashtype: Hashtype::Sha256,
            // Not a valid hash
            hash: Cow::Owned(
                from_hex("7424985ee56213b1b0f3699408ac88eae810e6e25596213fc62f1301f96b7d80").into(),
            ),
        }
    }

    pub(crate) fn create_hmac() -> Hash<'static> {
        Hash {
            hashtype: Hashtype::HmacSha256,
            // Not a valid hash
            hash: Cow::Owned(
                from_hex("7611e85222ca622f3fddf9ef93b7385754ce5e3381e778e9149f130e485974e1").into(),
            ),
        }
    }

    #[test]
    fn hash_roundtrip() {
        let case = create_hash();
        let mut buf = Vec::new();
        ciborium::into_writer(&case, &mut buf).unwrap();

        let res: Hash = ciborium::from_reader(buf.as_slice()).unwrap();

        assert_eq!(res, case);

        insta::assert_binary_snapshot!(".cbor", buf);
    }

    #[test]
    fn hash_debug() {
        let case = create_hash();

        insta::assert_debug_snapshot!(case);
    }

    #[test]
    fn hash_into_owned() {
        let case = create_hash();

        let b: Hash<'static> = case.clone().into_owned();

        assert_eq!(b, case)
    }

    #[test]
    fn hash_type_roundtrip() {
        let cases = [
            Hashtype::Sha256,
            Hashtype::Sha384,
            Hashtype::HmacSha256,
            Hashtype::HmacSha384,
        ];

        for case in cases {
            let mut buf = Vec::new();
            ciborium::into_writer(&case, &mut buf).unwrap();

            let res: Hashtype = ciborium::from_reader(buf.as_slice()).unwrap();

            assert_eq!(res, case);

            insta::assert_binary_snapshot!(".cbor", buf);
        }
    }

    #[test]
    fn hash_type_try_from_error() {
        let err = Hashtype::try_from(42).unwrap_err();

        assert_eq!(*err.kind(), ErrorKind::OutOfRange);
    }

    #[test]
    fn hash_type_is_hmac_or_hash() {
        let cases = [
            (Hashtype::Sha256, true, false),
            (Hashtype::Sha384, true, false),
            (Hashtype::HmacSha256, false, true),
            (Hashtype::HmacSha384, false, true),
        ];

        for (case, is_hash, is_hmac) in cases {
            assert_eq!(case.is_hash(), is_hash);
            assert_eq!(case.is_hmac(), is_hmac);
        }
    }
}
