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

//! Public Key encoding for signature keys.

use std::borrow::Cow;
use std::fmt::Debug;
use std::marker::PhantomData;

use coset::{AsCborValue, CoseKey};
use serde::de::Visitor;
use serde::{Deserialize, Serialize};
use serde_bytes::Bytes;

use crate::Error;
use crate::error::ErrorKind;

use super::x509::CoseX509;

/// ```cddl
/// PublicKey = [
///     pkType,
///     pkEnc,
///     pkBody
/// ]
/// ```
#[derive(Clone, PartialEq)]
pub struct PublicKey<'a> {
    pub(crate) pk_type: PkType,
    pub(crate) pk_enc: PkEnc,
    pub(crate) pk_body: PkBody<'a>,
}

impl<'a> PublicKey<'a> {
    /// Returns the public key bytes
    pub fn key(&self) -> Option<&[u8]> {
        self.pk_body.key()
    }

    /// Returns the [`PkType`]
    pub fn pk_type(&self) -> PkType {
        self.pk_type
    }
}

impl Debug for PublicKey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            pk_type,
            pk_enc,
            pk_body,
        } = self;

        f.debug_struct("PublicKey")
            .field("pk_type", pk_type)
            .field("pk_enc", pk_enc)
            .field("pk_body", pk_body)
            .finish()
    }
}

impl Serialize for PublicKey<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            pk_type,
            pk_enc,
            pk_body,
        } = self;

        (pk_type, pk_enc, pk_body).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PublicKey<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Default)]
        struct PubKeyVisitor<'a> {
            _marker: PhantomData<PublicKey<'a>>,
        }

        impl<'de, 'a> Visitor<'de> for PubKeyVisitor<'a> {
            type Value = PublicKey<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "expecting a PublicKey CBOR sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                if let Some(len) = seq.size_hint() {
                    if len != 3 {
                        return Err(serde::de::Error::invalid_length(
                            len,
                            &"should be a sequence of 3 elements",
                        ));
                    }
                }

                let pk_type = seq.next_element::<PkType>()?.ok_or_else(|| {
                    serde::de::Error::invalid_length(0, &"should be a sequence of 3 elements")
                })?;
                let pk_enc = seq.next_element::<PkEnc>()?.ok_or_else(|| {
                    serde::de::Error::invalid_length(1, &"should be a sequence of 3 elements")
                })?;

                let pk_body = match pk_enc {
                    PkEnc::Crypto => {
                        let body = seq.next_element::<Cow<'_, Bytes>>()?.ok_or_else(|| {
                            serde::de::Error::invalid_length(
                                2,
                                &"should be a sequence of 3 elements",
                            )
                        })?;

                        PkBody::Crypto(body)
                    }
                    PkEnc::X509 => {
                        let body = seq.next_element::<Cow<'_, Bytes>>()?.ok_or_else(|| {
                            serde::de::Error::invalid_length(
                                2,
                                &"should be a sequence of 3 elements",
                            )
                        })?;

                        PkBody::X509(body)
                    }
                    PkEnc::X5Chain => {
                        let chain = seq.next_element::<CoseX509<'_>>()?.ok_or_else(|| {
                            serde::de::Error::invalid_length(
                                2,
                                &"should be a sequence of 3 elements",
                            )
                        })?;

                        PkBody::X5Chain(chain)
                    }
                    PkEnc::CoseKey => {
                        let value = seq.next_element::<ciborium::Value>()?.ok_or_else(|| {
                            serde::de::Error::invalid_length(
                                2,
                                &"should be a sequence of 3 elements",
                            )
                        })?;

                        let key = coset::CoseKey::from_cbor_value(value)
                            .map_err(serde::de::Error::custom)?;

                        PkBody::CoseKey(key)
                    }
                };

                Ok(PublicKey {
                    pk_type,
                    pk_enc,
                    pk_body,
                })
            }
        }

        deserializer.deserialize_seq(PubKeyVisitor::default())
    }
}

/// KeyType is an FDO pkType enum.
///
/// ```cddl
/// pkType = (
///     RSA2048RESTR: 1, ;; RSA 2048 with restricted key/exponent (PKCS1 1.5 encoding)
///     RSAPKCS:      5, ;; RSA key, PKCS1, v1.5
///     RSAPSS:       6, ;; RSA key, PSS
///     SECP256R1:    10, ;; ECDSA secp256r1 = NIST-P-256 = prime256v1
///     SECP384R1:    11, ;; ECDSA secp384r1 = NIST-P-384
/// )
/// ;; These are identical
/// SECP256R1 = (
///     NIST-P-256,
///     PRIME256V1
/// )
/// ;; These are identical
/// SECP384R1 = (
///     NIST-P-384
/// )
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
#[repr(u8)]
pub enum PkType {
    /// RSA 2048 with restricted key/exponent (PKCS1 1.5 encoding)
    Rsa2048Restr = 1,
    /// RSA key, PKCS1, v1.5
    RsaPkcs = 5,
    /// RSA key, PSS
    RsaPss = 6,
    /// ECDSA secp256r1 = NIST-P-256 = prime256v1
    Secp256R1 = 10,
    /// ECDSA secp384r1 = NIST-P-384
    Secp384R1 = 11,
}

impl TryFrom<u8> for PkType {
    type Error = crate::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let value = match value {
            1 => PkType::Rsa2048Restr,
            5 => PkType::RsaPkcs,
            6 => PkType::RsaPss,
            10 => PkType::Secp256R1,
            11 => PkType::Secp384R1,
            _ => return Err(Error::new(ErrorKind::OutOfRange, "for PkType")),
        };

        Ok(value)
    }
}

impl From<PkType> for u8 {
    fn from(value: PkType) -> Self {
        value as u8
    }
}

/// Encoding of the PublicKey body
///
/// ```cddl
/// pkEnc = (
///     Crypto:       0      ;; applies to crypto with its own encoding (e.g., Intel® EPID)
///     X509:         1,     ;; X509 DER encoding, applies to RSA and ECDSA
///     X5CHAIN:      2,     ;; COSE x5chain, an ordered chain of X.509 certificates
///     COSEKEY:      3      ;; COSE key encoding
/// )
/// ```
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "u8", into = "u8")]
#[repr(u8)]
pub enum PkEnc {
    /// Applies to crypto with its own encoding (e.g., Intel® EPID)
    Crypto = 0,
    /// X509 DER encoding, applies to RSA and ECDSA
    X509 = 1,
    /// COSE x5chain, an ordered chain of X.509 certificates
    X5Chain = 2,
    /// COSE key encoding
    CoseKey = 3,
}

impl TryFrom<u8> for PkEnc {
    type Error = crate::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let value = match value {
            0 => PkEnc::Crypto,
            1 => PkEnc::X509,
            2 => PkEnc::X5Chain,
            3 => PkEnc::CoseKey,
            _ => return Err(Error::new(ErrorKind::OutOfRange, "for PkEnc")),
        };

        Ok(value)
    }
}

impl From<PkEnc> for u8 {
    fn from(value: PkEnc) -> Self {
        value as u8
    }
}

/// Body of a [`PublicKey`], it depends on the [`PkEnc`].
#[derive(Debug, Clone, PartialEq)]
pub enum PkBody<'a> {
    /// Applies to crypto with its own encoding (e.g., Intel® EPID)
    // NOTE: not sure if correct
    Crypto(Cow<'a, Bytes>),
    /// X509 DER encoding, applies to RSA and ECDSA
    X509(Cow<'a, Bytes>),
    /// COSE x5chain, an ordered chain of X.509 certificates
    X5Chain(CoseX509<'a>),
    /// COSE key encoding
    CoseKey(CoseKey),
}

impl<'a> PkBody<'a> {
    /// Public key as byte slice
    // TODO: parse cose key
    pub fn key(&self) -> Option<&[u8]> {
        match self {
            PkBody::X509(key) => Some(key),
            PkBody::X5Chain(chain) => Some(chain.cert_pub_key()),
            PkBody::Crypto(key) => Some(key),
            PkBody::CoseKey(_cose) => {
                #[cfg(feature = "tracing")]
                tracing::error!("cose public key functionality is not implemented");

                None
            }
        }
    }
}

impl Serialize for PkBody<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            PkBody::Crypto(cow) | PkBody::X509(cow) => cow.serialize(serializer),
            PkBody::X5Chain(cose_x509) => cose_x509.serialize(serializer),
            PkBody::CoseKey(cose_key) => cose_key
                .clone()
                .to_cbor_value()
                .map_err(serde::ser::Error::custom)?
                .serialize(serializer),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use coset::CoseKeyBuilder;

    use crate::tests::insta_settings;
    use crate::v101::x509::X509;
    use crate::v101::x509::tests::CERT_ECC;

    use super::*;

    pub(crate) const PUB_KEY_ECC: &[u8] = include_bytes!("../../../assets/examples/ec-pub-key.der");
    // openssl ec -pubin -in assets/examples/ec-pub-key.der -noout --text -param_out
    const PUB_ECC_KEY_PARAMS: &str = include_str!("../../../assets/examples/ec-pub-key.params.hex");
    pub(crate) const PUB_KEY_RSA: &[u8] =
        include_bytes!("../../../assets/examples/rsa-pub-key.der");

    fn cose_key() -> CoseKey {
        let (x, y) = ecc_p256_params();

        CoseKeyBuilder::new_ec2_pub_key(coset::iana::EllipticCurve::P_256, x.to_vec(), y.to_vec())
            .build()
    }

    pub(crate) fn ecc_p256_params() -> ([u8; 32], [u8; 32]) {
        let params = ecc_sec1_uncompressed();

        assert_eq!(params.len(), 1 + 32 + 32);

        // skip the 0x04 ecc ansi encoding
        let x = params[1..33].try_into().unwrap();
        let y = params[33..].try_into().unwrap();

        (x, y)
    }

    pub(crate) fn ecc_sec1_uncompressed() -> Vec<u8> {
        PUB_ECC_KEY_PARAMS
            .split(":")
            .flat_map(|s| s.split_whitespace())
            .filter(|s| !s.is_empty())
            .map(|s| u8::from_str_radix(s, 16).expect("should be hex"))
            .collect()
    }

    fn pub_key_cases() -> [(PkEnc, PkBody<'static>); 4] {
        let cert = X509::parse(CERT_ECC).unwrap();

        [
            (
                PkEnc::Crypto,
                PkBody::Crypto(Cow::Borrowed(Bytes::new(&[0, 1, 2, 3, 4]))),
            ),
            (
                PkEnc::X509,
                PkBody::X509(Cow::Borrowed(Bytes::new(PUB_KEY_ECC))),
            ),
            (PkEnc::X5Chain, PkBody::X5Chain(CoseX509::One(cert))),
            (PkEnc::CoseKey, PkBody::CoseKey(cose_key())),
        ]
    }

    #[test]
    fn public_key_roundtrip() {
        let cases = pub_key_cases();

        for (enc, case) in cases {
            let pub_key = PublicKey {
                pk_type: PkType::Secp256R1,
                pk_enc: enc,
                pk_body: case,
            };

            let mut buf = Vec::new();
            ciborium::into_writer(&pub_key, &mut buf).unwrap();

            let res: PublicKey = ciborium::from_reader(buf.as_slice()).unwrap();

            assert_eq!(res, pub_key);

            insta_settings!({
                insta::assert_binary_snapshot!(".cbor", buf);
            });
        }
    }

    #[test]
    fn public_key_debug() {
        let cases = pub_key_cases();

        for (enc, case) in cases {
            let pub_key = PublicKey {
                pk_type: PkType::Secp256R1,
                pk_enc: enc,
                pk_body: case,
            };

            insta_settings!({
                insta::assert_debug_snapshot!(pub_key);
            });
        }
    }

    #[test]
    fn pubkey_get_key() {
        let cert = X509::parse(CERT_ECC).unwrap();

        let cases = [
            (
                PkEnc::Crypto,
                Some([0, 1, 2, 3, 4].as_slice()),
                PkBody::Crypto(Cow::Borrowed(Bytes::new(&[0, 1, 2, 3, 4]))),
            ),
            (
                PkEnc::X509,
                Some(PUB_KEY_ECC),
                PkBody::X509(Cow::Borrowed(Bytes::new(PUB_KEY_ECC))),
            ),
            (
                PkEnc::X5Chain,
                Some(cert.key()),
                PkBody::X5Chain(CoseX509::One(cert.clone())),
            ),
            (PkEnc::CoseKey, None, PkBody::CoseKey(cose_key())),
        ];

        for (pk_enc, exp, pk_body) in cases {
            let pub_key = PublicKey {
                pk_type: PkType::Secp256R1,
                pk_enc,
                pk_body,
            };

            assert_eq!(pub_key.key(), exp);
        }
    }

    #[test]
    fn pk_type_roundtrip() {
        let cases = [
            PkType::Rsa2048Restr,
            PkType::RsaPkcs,
            PkType::RsaPss,
            PkType::Secp256R1,
            PkType::Secp384R1,
        ];

        for case in cases {
            let mut buf = Vec::new();
            ciborium::into_writer(&case, &mut buf).unwrap();

            let res: PkType = ciborium::from_reader(buf.as_slice()).unwrap();

            assert_eq!(res, case);

            insta_settings!({
                insta::assert_binary_snapshot!(".cbor", buf);
            });
        }
    }

    // See if all the error cases are covered
    #[test]
    fn public_key_err() {
        // Size hint case
        let mut buf = Vec::new();
        ciborium::into_writer(&ciborium::Value::Array(vec![]), &mut buf).unwrap();
        ciborium::from_reader::<PublicKey, _>(buf.as_slice()).unwrap_err();

        // No size hint
        let cases = [
            vec![],
            vec![ciborium::Value::Integer(u8::from(PkType::Secp256R1).into())],
            vec![
                ciborium::Value::Integer(u8::from(PkType::Secp256R1).into()),
                ciborium::Value::Integer(u8::from(PkEnc::X509).into()),
            ],
            vec![
                ciborium::Value::Integer(u8::from(PkType::Secp256R1).into()),
                ciborium::Value::Integer(u8::from(PkEnc::X509).into()),
            ],
            vec![
                ciborium::Value::Integer(u8::from(PkType::Secp256R1).into()),
                ciborium::Value::Integer(u8::from(PkEnc::Crypto).into()),
            ],
            vec![
                ciborium::Value::Integer(u8::from(PkType::Secp256R1).into()),
                ciborium::Value::Integer(u8::from(PkEnc::X5Chain).into()),
            ],
            vec![
                ciborium::Value::Integer(u8::from(PkType::Secp256R1).into()),
                ciborium::Value::Integer(u8::from(PkEnc::CoseKey).into()),
            ],
        ];

        for case in cases {
            ciborium::Value::Array(case)
                .deserialized::<PublicKey>()
                .unwrap_err();
        }
    }

    #[test]
    fn pk_type_err() {
        let err = PkType::try_from(12u8).unwrap_err();

        assert_eq!(*err.kind(), ErrorKind::OutOfRange);
    }

    #[test]
    fn pk_enc_err() {
        let err = PkEnc::try_from(4u8).unwrap_err();

        assert_eq!(*err.kind(), ErrorKind::OutOfRange);
    }

    #[test]
    fn pk_pk_type() {
        let pk_type = PkType::Secp256R1;
        let pk = PublicKey {
            pk_type,
            pk_enc: PkEnc::X509,
            pk_body: PkBody::X509(Cow::Borrowed(PUB_KEY_ECC.into())),
        };

        assert_eq!(pk.pk_type(), pk_type);
    }
}
