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

//! Structures for a X509 cert chain X5CHAIN following COSE spec.
//!
//!

use std::borrow::Cow;
use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use serde_bytes::Bytes;

use crate::Error;
use crate::error::ErrorKind;
use crate::utils::{Hex, Repetition};

/// X509 Certificate
///
/// From COSE RFC
///
/// ```cddl
/// COSE_X509 = bstr / [ 2*certs: bstr ]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// TODO: could be better
#[serde(untagged)]
pub enum CoseX509<'a> {
    /// List of certificates
    ///
    /// This is more lenient than the spec, it should require a minimum of 2.
    Certs(Repetition<1, X509<'a>>),
    /// A single
    One(X509<'a>),
}

impl<'a> CoseX509<'a> {
    /// Returns `true` if the cose x509 is [`One`].
    ///
    /// [`One`]: CoseX509::One
    #[must_use]
    pub fn is_one(&self) -> bool {
        matches!(self, Self::One(..))
    }

    /// Return the first certificate public key.
    pub fn cert_pub_key(&self) -> &[u8] {
        let cert = match self {
            CoseX509::Certs(repetition) => repetition.first(),
            CoseX509::One(cow) => cow,
        };

        cert.key()
    }
}

/// DER-encoded X.509 Certificate
#[derive(Clone, Eq)]
pub struct X509<'a> {
    cert: Cow<'a, Bytes>,
    key: Vec<u8>,
}

impl<'a> X509<'a> {
    /// Parses a DER encoded certificate from a slice.
    pub fn parse(cert: &'a [u8]) -> Result<Self, Error> {
        let (rest, parsed) = x509_parser::parse_x509_certificate(cert).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't parse x509 certificate");

            Error::new(ErrorKind::Invalid, "x509 certificate")
        })?;

        debug_assert!(rest.is_empty());

        Ok(Self {
            key: parsed.subject_pki.raw.to_vec(),
            cert: Cow::Borrowed(Bytes::new(cert)),
        })
    }

    pub(crate) fn key(&self) -> &[u8] {
        &self.key
    }
}

impl Serialize for X509<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.cert.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for X509<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let cert: Cow<'_, Bytes> = Deserialize::deserialize(deserializer)?;

        let (rest, parsed) =
            x509_parser::parse_x509_certificate(&cert).map_err(serde::de::Error::custom)?;

        debug_assert!(rest.is_empty());

        Ok(Self {
            key: parsed.subject_pki.raw.to_vec(),
            cert,
        })
    }
}

impl Debug for X509<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { cert, key } = self;

        f.debug_struct("X509")
            .field("cert", &Hex::new(cert))
            .field("key", &Hex::new(key))
            .finish()
    }
}

impl PartialEq for X509<'_> {
    fn eq(&self, other: &Self) -> bool {
        let Self { cert, key: _ } = self;

        *cert == other.cert
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use pretty_assertions::assert_eq;

    use crate::tests::insta_settings;
    use crate::v101::public_key::tests::{PUB_KEY_ECC, PUB_KEY_RSA};

    use super::*;

    pub(crate) const CERT_ECC: &[u8] = include_bytes!("../../../assets/examples/x509-ecc-ca.der");
    pub(crate) const CERT_RSA: &[u8] = include_bytes!("../../../assets/examples/x509-rsa-ca.der");

    pub(crate) fn create_cose_x509() -> CoseX509<'static> {
        let ecc = X509::parse(CERT_ECC).unwrap();
        CoseX509::One(ecc)
    }

    #[test]
    fn cose_x509_roundtrip() {
        let ecc = X509::parse(CERT_ECC).unwrap();
        let rsa = X509::parse(CERT_RSA).unwrap();
        let cases = [
            create_cose_x509(),
            CoseX509::Certs(Repetition::new(vec![ecc, rsa]).unwrap()),
        ];

        insta_settings!({
            for case in cases {
                let mut buf = Vec::new();
                ciborium::into_writer(&case, &mut buf).unwrap();

                let res: CoseX509 = ciborium::from_reader(buf.as_slice()).unwrap();

                assert_eq!(res, case);

                insta::assert_binary_snapshot!(".cbor", buf);
            }
        });
    }

    #[test]
    fn cose_x509_cert_pub_key() {
        let ecc = X509::parse(CERT_ECC).unwrap();
        let rsa = X509::parse(CERT_RSA).unwrap();
        let cases = [
            (CoseX509::One(ecc.clone()), PUB_KEY_ECC),
            (CoseX509::One(rsa.clone()), PUB_KEY_RSA),
            (
                CoseX509::Certs(Repetition::new(vec![ecc, rsa]).unwrap()),
                PUB_KEY_ECC,
            ),
        ];

        for (case, exp) in cases {
            assert_eq!(case.cert_pub_key(), exp);
        }
    }

    #[test]
    fn cose_x509_is_one() {
        let ecc = X509::parse(CERT_ECC).unwrap();
        let rsa = X509::parse(CERT_RSA).unwrap();
        let cases = [
            (CoseX509::One(ecc.clone()), true),
            (
                CoseX509::Certs(Repetition::new(vec![ecc, rsa]).unwrap()),
                false,
            ),
        ];

        for (case, exp) in cases {
            assert_eq!(case.is_one(), exp);
        }
    }

    #[test]
    fn x509_parse_err() {
        let err = X509::parse(PUB_KEY_ECC).unwrap_err();

        assert_eq!(*err.kind(), ErrorKind::Invalid);
    }
}
