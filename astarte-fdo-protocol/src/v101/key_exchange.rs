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

//! Key exchange parameters, in either direction.

use std::borrow::Cow;
use std::fmt::Display;

use serde::{Deserialize, Serialize};
use serde_bytes::Bytes;

use crate::error::ErrorKind;
use crate::Error;

/// Returns the value as a Key
pub trait AsEccKey<const N: usize, const M: usize> {
    /// Return the x param of the ECC
    fn x(&self) -> &[u8; N];

    /// Return the y param of the ECC
    fn y(&self) -> &[u8; N];

    /// Return the key SEC.1 uncompressed key.
    fn as_key(&self) -> [u8; M] {
        let mut array = [0u8; M];

        array[0] = 0x4;
        let slice = &mut array[1..(N + 1)];
        debug_assert_eq!(slice.len(), N);
        slice.copy_from_slice(self.x());

        let slice = &mut array[(N + 1)..];
        debug_assert_eq!(slice.len(), N);
        slice.copy_from_slice(self.y());

        array
    }
}

/// Parameters for a key exchange with ECC keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcdhParams<'a, const N: usize> {
    x: &'a [u8; N],
    y: &'a [u8; N],
    rand: &'a [u8],
}

impl<'a, const N: usize> EcdhParams<'a, N> {
    /// Return the random part
    pub fn rand(&self) -> &'a [u8] {
        self.rand
    }
}

impl<'a> EcdhParams<'a, 32> {
    /// Create the P-256 params
    pub fn with_p256(x: &'a [u8; 32], y: &'a [u8; 32], rand: &'a [u8]) -> Self {
        Self { x, y, rand }
    }
}

impl<'a> EcdhParams<'a, 48> {
    /// Create the P-256 params
    pub fn with_p384(x: &'a [u8; 48], y: &'a [u8; 48], rand: &'a [u8]) -> Self {
        Self { x, y, rand }
    }
}

impl<'a> AsEccKey<32, 65> for EcdhParams<'a, 32> {
    fn x(&self) -> &[u8; 32] {
        self.x
    }

    fn y(&self) -> &[u8; 32] {
        self.y
    }
}

impl<'a> AsEccKey<48, 97> for EcdhParams<'a, 48> {
    fn x(&self) -> &[u8; 48] {
        self.x
    }

    fn y(&self) -> &[u8; 48] {
        self.y
    }
}

impl<'a, const N: usize> TryFrom<&'a [u8]> for EcdhParams<'a, N> {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<EcdhParams<'_, N>, Self::Error> {
        let (x, rest) = parse_len_prefixed_array(value).ok_or(Error::new(
            ErrorKind::Invalid,
            "for len prefixed slice EcdhParams",
        ))?;

        let (y, rest) = parse_len_prefixed_array(rest).ok_or(Error::new(
            ErrorKind::Invalid,
            "for len prefixed slice EcdhParams",
        ))?;
        let (rand, rest) = parse_len_prefixed_slice(rest).ok_or(Error::new(
            ErrorKind::Invalid,
            "for len prefixed slice EcdhParams",
        ))?;

        if !rest.is_empty() {
            return Err(Error::new(
                ErrorKind::Invalid,
                "for remaining bytes in EcdhParams",
            ));
        }

        Ok(EcdhParams { x, y, rand })
    }
}

fn parse_len_prefixed_array<const N: usize>(bytes: &[u8]) -> Option<(&[u8; N], &[u8])> {
    let (slice, rest) = parse_len_prefixed_slice(bytes)?;

    let array = slice
        .try_into()
        .inspect_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "wrong slice size, expected {N}");
        })
        .ok()?;

    Some((array, rest))
}

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
pub struct XAKeyExchange<'a>(pub(crate) Cow<'a, Bytes>);

impl<'a> XAKeyExchange<'a> {
    /// Returns the [`EcdhParams`] of the exchange.
    pub fn parse_ecdh_p256(&self) -> Result<EcdhParams<'_, 32>, crate::Error> {
        let rest = self.as_ref();

        EcdhParams::try_from(rest)
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
pub struct XBKeyExchange<'a>(pub(crate) Cow<'a, Bytes>);

impl XBKeyExchange<'static> {
    /// Create the XBKeyExchange from [`EcdhParams`]
    pub fn create<const N: usize>(params: EcdhParams<'_, N>) -> Result<Self, Error> {
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
pub type IvData<'a> = Cow<'a, Bytes>;

/// Session cryptography algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KexSuitNames {
    /// Diffie-Hellman key exchange method using a standard Diffie-Hellman mechanism.
    ///
    /// With a standard NIST exponent and 2048-bit modulus (RFC3526, id 14). This is the preferred
    /// method for RSA2048RESTR Owner keys.
    DHKEXid14,
    /// Diffie-Hellman key exchange method using a standard Diffie-Hellman mechanism
    ///
    /// With a standard National Institute of Standards and Technology (NIST) exponent and 3072-bit
    /// modulus. (RFC3526, id 15), This is the preferred method for RSA 3072-bit Owner keys.
    DHKEXid15,
    /// Asymmetric key exchange method uses the encryption by an Owner key based on RSA2048RESTR.
    ///
    /// This method is useful in FIDO Device Onboard Client environments where Diffie-Hellman
    /// computation is slow or difficult to code.
    ASYMKEX2048,
    /// The Asymmetric key exchange method uses the encryption by an Owner key based on RSA with 3072-bit key.
    ASYMKEX3072,
    /// The ECDH method uses a standard Diffie-Hellman mechanism for ECDSA keys.
    ///
    /// The ECC keys follow NIST P-256 (SECP256R1)
    ECDH256,
    /// Standard Diffie-Hellman mechanism ECC NIST P-384 (SECP384R1)
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

impl Display for KexSuitNames {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use crate::v101::public_key::tests::{ecc_p256_params, ecc_sec1_uncompressed};

    use super::*;

    #[test]
    fn xb_key_exchange_roundtrip() {
        let (x, y) = ecc_p256_params();

        let params = EcdhParams::with_p256(&x, &y, &[0xde, 0xad, 0xbe, 0xef]);

        let value = XBKeyExchange::create(params).unwrap();

        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf).unwrap();

        let res: XBKeyExchange = ciborium::from_reader(buf.as_slice()).unwrap();

        assert_eq!(res, value);

        insta::assert_binary_snapshot!(".cbor", buf);
    }

    #[test]
    fn xa_key_exchange_roundtrip() {
        let (x, y) = ecc_p256_params();

        let params = EcdhParams::with_p256(&x, &y, &[0xde, 0xad, 0xbe, 0xef]);

        // Make it valid
        let value = XBKeyExchange::create(params).unwrap();
        let value = XAKeyExchange(value.0);

        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf).unwrap();

        let res: XAKeyExchange = ciborium::from_reader(buf.as_slice()).unwrap();

        assert_eq!(res, value);

        insta::assert_binary_snapshot!(".cbor", buf);
    }

    #[test]
    fn xb_key_exchange_param_roundtrip() {
        let (x, y) = ecc_p256_params();
        let params = EcdhParams::with_p256(&x, &y, &[0xde, 0xad, 0xbe, 0xef]);

        let bx = XBKeyExchange::create(params).unwrap();
        let ax = XAKeyExchange(bx.0);

        let res = ax.parse_ecdh_p256().unwrap();

        assert_eq!(res, params);
    }

    #[test]
    fn xb_key_as_ref() {
        let (x, y) = ecc_p256_params();
        let params = EcdhParams::with_p256(&x, &y, &[0xde, 0xad, 0xbe, 0xef]);

        let bx = XBKeyExchange::create(params).unwrap();

        let ax = XAKeyExchange(bx.0.clone());

        assert_eq!(bx.as_ref(), ax.as_ref());
    }

    #[test]
    fn ecc_params_as_key() {
        let (x, y) = ecc_p256_params();
        let params = EcdhParams::with_p256(&x, &y, &[0xde, 0xad, 0xbe, 0xef]);

        let exp = ecc_sec1_uncompressed();
        assert_eq!(params.as_key().as_slice(), exp);
    }

    #[test]
    fn kex_suit_names_display() {
        let case = [
            KexSuitNames::DHKEXid14,
            KexSuitNames::DHKEXid15,
            KexSuitNames::ASYMKEX2048,
            KexSuitNames::ASYMKEX3072,
            KexSuitNames::ECDH256,
            KexSuitNames::ECDH384,
        ]
        .map(|k| k.to_string())
        .join("\n");

        insta::assert_snapshot!(case);
    }

    #[test]
    fn ecdh_params_getters() {
        let (x, y) = ecc_p256_params();
        let rand = &[0xde, 0xad, 0xbe, 0xef];
        let params = EcdhParams::with_p256(&x, &y, rand);

        assert_eq!(*params.x(), x);
        assert_eq!(*params.y(), y);
        assert_eq!(params.rand(), rand);
    }

    #[test]
    fn ecdh_params_errors() {
        // Empty
        XAKeyExchange(Cow::Borrowed(Bytes::new(&[])))
            .parse_ecdh_p256()
            .unwrap_err();

        let x = &[1, 2, 3, 4];
        let y = &[5, 6, 7, 8];

        let mut buf: Vec<u8> = Vec::new();

        // Wrong prefix
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(x);
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(y);

        XAKeyExchange(Cow::Borrowed(Bytes::new(buf.as_slice())))
            .parse_ecdh_p256()
            .unwrap_err();

        let mut buf: Vec<u8> = Vec::new();

        // missing last
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(x);
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(y);

        XAKeyExchange(Cow::Borrowed(Bytes::new(buf.as_slice())))
            .parse_ecdh_p256()
            .unwrap_err();

        let mut buf: Vec<u8> = Vec::new();

        // remaining bytes
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(x);
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(y);
        buf.extend_from_slice(&3u16.to_be_bytes());
        // rand
        buf.extend_from_slice(y);

        XAKeyExchange(Cow::Borrowed(Bytes::new(buf.as_slice())))
            .parse_ecdh_p256()
            .unwrap_err();
    }
}
