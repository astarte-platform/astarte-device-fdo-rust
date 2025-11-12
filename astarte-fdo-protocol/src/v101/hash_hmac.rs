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
    hashtype: Hashtype,
    hash: Cow<'a, Bytes>,
}

impl<'a> Hash<'a> {
    /// Return an owned instance of the Hash.
    pub fn into_owned(self) -> Hash<'static> {
        Hash {
            hashtype: self.hashtype,
            hash: Cow::Owned(self.hash.into_owned()),
        }
    }

    /// Create a [`SHA256`](Hashtype::Sha256)
    pub fn with_sha256(hash: Cow<'a, Bytes>) -> Option<Self> {
        (hash.len() == 32).then_some(Self {
            hashtype: Hashtype::Sha256,
            hash,
        })
    }

    /// Create a [`SHA384`](Hashtype::Sha384)
    pub fn with_sha384(hash: Cow<'a, Bytes>) -> Option<Self> {
        (hash.len() == 48).then_some(Self {
            hashtype: Hashtype::Sha384,
            hash,
        })
    }

    /// Returns the [`Hashtype`]
    pub fn hash_type(&self) -> Hashtype {
        self.hashtype
    }
}

impl AsRef<[u8]> for Hash<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.hash
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HMac<'a>(Hash<'a>);

impl<'a> HMac<'a> {
    /// Create an [`HMAC-SHA256`](Hashtype::HmacSha256)
    pub fn with_sha256(hash: Cow<'a, Bytes>) -> Option<Self> {
        (hash.len() == 32).then_some(Self(Hash {
            hashtype: Hashtype::HmacSha256,
            hash,
        }))
    }

    /// Create an [`HMAC-SHA384`](Hashtype::HmacSha384)
    pub fn with_sha384(hash: Cow<'a, Bytes>) -> Option<Self> {
        (hash.len() == 48).then_some(Self(Hash {
            hashtype: Hashtype::HmacSha384,
            hash,
        }))
    }

    /// Return the hash type.
    pub fn hash_type(&self) -> Hashtype {
        self.0.hash_type()
    }
}

impl AsRef<[u8]> for HMac<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Serialize for HMac<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for HMac<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hash = Hash::deserialize(deserializer)?;

        match hash.hash_type() {
            Hashtype::HmacSha256 | Hashtype::HmacSha384 => Ok(HMac(hash)),
            Hashtype::Sha256 | Hashtype::Sha384 => Err(serde::de::Error::custom(
                "invalid hashtype, not a hmac type",
            )),
        }
    }
}

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

    pub(crate) fn create_hmac() -> HMac<'static> {
        HMac(Hash {
            hashtype: Hashtype::HmacSha256,
            // Not a valid hash
            hash: Cow::Owned(
                from_hex("7611e85222ca622f3fddf9ef93b7385754ce5e3381e778e9149f130e485974e1").into(),
            ),
        })
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
    fn hamac_roundtrip() {
        let case = create_hmac();
        let mut buf = Vec::new();
        ciborium::into_writer(&case, &mut buf).unwrap();

        let res: HMac = ciborium::from_reader(buf.as_slice()).unwrap();

        assert_eq!(res, case);

        insta::assert_binary_snapshot!(".cbor", buf);
    }

    #[test]
    fn hash_as_ref() {
        let case = create_hash();

        assert_eq!(
            case.as_ref(),
            from_hex("7424985ee56213b1b0f3699408ac88eae810e6e25596213fc62f1301f96b7d80"),
        );
    }

    #[test]
    fn hmac_as_ref() {
        let case = create_hmac();

        assert_eq!(
            case.as_ref(),
            from_hex("7611e85222ca622f3fddf9ef93b7385754ce5e3381e778e9149f130e485974e1"),
        );
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

    #[test]
    fn hash_create() {
        let cases = [
            (
                from_hex("7424985ee56213b1b0f3699408ac88eae810e6e25596213fc62f1301f96b7d80"),
                Some(Hash {
                    hashtype: Hashtype::Sha256,
                    hash: Cow::Owned(
                        from_hex(
                            "7424985ee56213b1b0f3699408ac88eae810e6e25596213fc62f1301f96b7d80",
                        )
                        .into(),
                    ),
                }),
            ),
            (
                from_hex("1f0da65eda5eafeb7d7aaee622980693452f4e50b33eca779c85b76cf779985ef3026afa46dfa0f5b0d23959b3471179"),
                None,
            ),
        ];

        for (hash, exp) in cases {
            assert_eq!(Hash::with_sha256(Cow::Owned(hash.into())), exp)
        }

        let cases = [
            (
                from_hex("8d1e5565befe593307d98a73b4ce7aa22e94ed8d7812ce8393bc42373360bee6a404c283f3662b0d7c4745a34f97d900"),
                Some(Hash {
                    hashtype: Hashtype::Sha384,
                    hash: Cow::Owned(
                        from_hex(
                            "8d1e5565befe593307d98a73b4ce7aa22e94ed8d7812ce8393bc42373360bee6a404c283f3662b0d7c4745a34f97d900",
                        )
                        .into(),
                    ),
                }),
            ),
            (
                from_hex("7424985ee56213b1b0f3699408ac88eae810e6e25596213fc62f1301f96b7d80"),
                None,
            ),
        ];

        for (hash, exp) in cases {
            assert_eq!(Hash::with_sha384(Cow::Owned(hash.into())), exp)
        }
    }

    #[test]
    fn hmac_create() {
        let cases = [
            (
                from_hex("2037648dd0552e86c7fa2c9f607f7a78dab3247bc732af40efdb814c379d9184"),
                Some(HMac(Hash {
                    hashtype: Hashtype::HmacSha256,
                    hash: Cow::Owned(
                        from_hex(
                            "2037648dd0552e86c7fa2c9f607f7a78dab3247bc732af40efdb814c379d9184",
                        )
                        .into(),
                    ),
                })),
            ),
            (from_hex("1f0da65eda5eafeb7d7aaee622980693452f4e50b33eca779c85b76cf779985ef3026afa46dfa0f5b0d23959b3471179"), None),
        ];

        for (hash, exp) in cases {
            assert_eq!(HMac::with_sha256(Cow::Owned(hash.into())), exp)
        }

        let cases = [
            (
                from_hex("8d1e5565befe593307d98a73b4ce7aa22e94ed8d7812ce8393bc42373360bee6a404c283f3662b0d7c4745a34f97d900"),
                Some(HMac(Hash {
                    hashtype: Hashtype::HmacSha384,
                    hash: Cow::Owned(
                        from_hex(
                            "8d1e5565befe593307d98a73b4ce7aa22e94ed8d7812ce8393bc42373360bee6a404c283f3662b0d7c4745a34f97d900",
                        )
                        .into(),
                    ),
                })),
            ),
            (
                from_hex("7424985ee56213b1b0f3699408ac88eae810e6e25596213fc62f1301f96b7d80"),
                None,
            ),
        ];

        for (hash, exp) in cases {
            assert_eq!(HMac::with_sha384(Cow::Owned(hash.into())), exp)
        }
    }

    #[test]
    fn hash_hmac_hashtype() {
        let case = Hash::with_sha256(Cow::Owned(
            from_hex("7424985ee56213b1b0f3699408ac88eae810e6e25596213fc62f1301f96b7d80").into(),
        ))
        .unwrap();

        assert_eq!(case.hash_type(), Hashtype::Sha256);

        let case = HMac::with_sha256(Cow::Owned(
            from_hex("7424985ee56213b1b0f3699408ac88eae810e6e25596213fc62f1301f96b7d80").into(),
        ))
        .unwrap();

        assert_eq!(case.hash_type(), Hashtype::HmacSha256);
    }

    #[test]
    fn hash_can_deserialize_hmac() {
        let case = create_hmac();

        let mut buf = Vec::new();
        ciborium::into_writer(&case, &mut buf).unwrap();

        let res: Hash = ciborium::from_reader(buf.as_slice()).unwrap();

        assert_eq!(res, case.0);
    }

    #[test]
    fn hmac_cannot_deserialize_hash() {
        let case = create_hash();

        let mut buf = Vec::new();
        ciborium::into_writer(&case, &mut buf).unwrap();

        ciborium::from_reader::<HMac, _>(buf.as_slice()).unwrap_err();
    }
}
