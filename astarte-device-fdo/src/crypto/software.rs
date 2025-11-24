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

//! Software based crypto operations.

use std::borrow::Cow;

use astarte_fdo_protocol::error::ErrorKind;
use astarte_fdo_protocol::v101::hash_hmac::{HMac, Hashtype};
use astarte_fdo_protocol::Error;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair};
use coset::{CoseSign1, CoseSign1Builder, HeaderBuilder};
use rcgen::{CertificateParams, DistinguishedName, DnType};
use serde_bytes::ByteBuf;
use tracing::error;
use zeroize::Zeroizing;

use crate::storage::Storage;

use super::{Crypto, DefaultKeyExchange};

const PRIVATE_ECC_KEY_FILE: &str = "private-key.ecc.p8";

/// Software base cryptographic operations.
pub struct SoftwareCrypto<S> {
    rng: SystemRandom,
    storage: S,
}

impl<S> SoftwareCrypto<S> {
    /// Creates a new instance.
    pub async fn create(storage: S) -> Result<Self, Error>
    where
        S: Storage,
    {
        let rand = SystemRandom::new();

        let this = Self { rng: rand, storage };

        if !this.storage.exists(PRIVATE_ECC_KEY_FILE).await? {
            this.create_signing_keys().await?;
        }

        if !this.storage.exists(PRIVATE_ECC_KEY_FILE).await? {
            this.create_signing_keys().await?;
        }

        Ok(this)
    }

    fn alg() -> &'static aws_lc_rs::signature::EcdsaSigningAlgorithm {
        &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING
    }

    async fn create_signing_keys(&self) -> Result<(), Error>
    where
        S: Storage,
    {
        let key = EcdsaKeyPair::generate_pkcs8(Self::alg(), &self.rng)
            .map_err(|_| Error::new(ErrorKind::Crypto, "to generate siging key"))?;

        self.storage
            .write_immutable(PRIVATE_ECC_KEY_FILE, key.as_ref())
            .await?;

        Ok(())
    }

    async fn signing_key(
        &self,
        alg: &'static aws_lc_rs::signature::EcdsaSigningAlgorithm,
    ) -> Result<EcdsaKeyPair, Error>
    where
        S: Storage,
    {
        let bytes = self
            .storage
            .read(PRIVATE_ECC_KEY_FILE)
            .await
            .and_then(|key| key.ok_or(Error::new(ErrorKind::Io, "signing key is missing")))?;

        let bytes = Zeroizing::new(bytes);

        let key = EcdsaKeyPair::from_pkcs8(alg, &bytes).map_err(|err| {
            error!(error = %err, "couldn't parse signing key");

            Error::new(ErrorKind::Crypto, "to parse signing key")
        })?;

        Ok(key)
    }
}

impl<S> Crypto for SoftwareCrypto<S>
where
    S: Storage + Send + Sync,
{
    type KeyExchange = DefaultKeyExchange;

    fn rng(&mut self) -> &SystemRandom {
        &self.rng
    }

    async fn csr(&mut self, device_info: &str) -> Result<Vec<u8>, Error> {
        // The device info for the certificate
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, device_info);

        let mut csr_param = CertificateParams::new([]).map_err(|err| {
            error!(error = %err,"coudln't create csr parameters");

            Error::new(ErrorKind::Crypto, "to create csr parameters")
        })?;
        csr_param.distinguished_name = dn;

        let key = self
            .signing_key(&aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING)
            .await?;

        let compat = RcgenKeyCompat::new(&key, &self.rng);

        // Singed CSR
        let csr = csr_param.serialize_request(&compat).map_err(|err| {
            error!(error = %err,"coudln't create serialize csr");

            Error::new(ErrorKind::Crypto, "to serialize csr")
        })?;

        Ok(csr.der().to_vec())
    }

    async fn create_hmac_secret(&mut self) -> Result<Vec<u8>, Error> {
        let mut hmac_secret = vec![0; aws_lc_rs::digest::SHA256_OUTPUT_LEN];

        self.rng
            .fill(hmac_secret.as_mut_slice())
            .map_err(|_| Error::new(ErrorKind::Crypto, "to generate hmac secret"))?;

        Ok(hmac_secret)
    }

    async fn hmac(&mut self, secret: &[u8], data: &[u8]) -> Result<HMac<'static>, Error> {
        let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, secret);

        let tag = aws_lc_rs::hmac::sign(&key, data);

        let hmac = HMac::with_sha256(Cow::Owned(ByteBuf::from(tag.as_ref())))
            .ok_or(Error::new(ErrorKind::Invalid, "to create hmac"))?;

        Ok(hmac)
    }

    async fn verify_hmac(
        &mut self,
        secret: &[u8],
        hmac: &HMac<'_>,
        data: &[u8],
    ) -> Result<(), Error> {
        let alg = match hmac.hash_type() {
            Hashtype::HmacSha256 => {
                debug_assert_eq!(secret.len(), 32, "secret length");

                aws_lc_rs::hmac::HMAC_SHA256
            }
            Hashtype::HmacSha384 => {
                debug_assert_eq!(secret.len(), 48, "secret length");

                aws_lc_rs::hmac::HMAC_SHA384
            }
            Hashtype::Sha256 | Hashtype::Sha384 => {
                return Err(Error::new(ErrorKind::Invalid, "hash type for hmac"));
            }
        };

        let key = aws_lc_rs::hmac::Key::new(alg, secret);

        aws_lc_rs::hmac::verify(&key, data, hmac.as_ref())
            .map_err(|_| Error::new(ErrorKind::Crypto, "to verify hmac"))
    }

    async fn cose_sign(
        &mut self,
        unprotected: HeaderBuilder,
        payload: Vec<u8>,
    ) -> Result<CoseSign1, Error> {
        let key = self
            .signing_key(&aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED_SIGNING)
            .await?;

        let protected = HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::ES256)
            .build();

        let unprotected = unprotected.build();

        let eat = CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(payload)
            .try_create_signature(&[], |bytes| {
                let sign = key
                    .sign(&self.rng, bytes)
                    .map_err(|_| Error::new(ErrorKind::Crypto, "to sign cose"))?;

                Ok(sign.as_ref().to_vec())
            })?
            .build();

        Ok(eat)
    }
}

struct RcgenKeyCompat<'a> {
    keys: &'a EcdsaKeyPair,
    rand: &'a SystemRandom,
}

impl<'a> RcgenKeyCompat<'a> {
    fn new(keys: &'a EcdsaKeyPair, rand: &'a SystemRandom) -> Self {
        Self { keys, rand }
    }
}

impl rcgen::PublicKeyData for RcgenKeyCompat<'_> {
    fn der_bytes(&self) -> &[u8] {
        self.keys.public_key().as_ref()
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for RcgenKeyCompat<'_> {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.keys
            .sign(self.rand, msg)
            .map(|signature| signature.as_ref().to_vec())
            .map_err(|_| rcgen::Error::RingUnspecified)
    }
}
