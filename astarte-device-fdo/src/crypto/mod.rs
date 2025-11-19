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

//! Crypto operations like signing,and encryption.

use std::borrow::Cow;
use std::future::Future;

use astarte_fdo_protocol::error::ErrorKind;
use astarte_fdo_protocol::Error;
use coset::iana::Algorithm as CoseAlgorithm;
use coset::{CoseEncrypt0, CoseSign1, HeaderBuilder};
use serde_bytes::ByteBuf;
use tracing::debug;

use astarte_fdo_protocol::v101::hash_hmac::{HMac, Hash, Hashtype};
use astarte_fdo_protocol::v101::key_exchange::{KexSuitNames, XAKeyExchange, XBKeyExchange};
use astarte_fdo_protocol::v101::public_key::{PkEnc, PkType, PublicKey};
use astarte_fdo_protocol::v101::sign_info::DeviceSgType;
use astarte_fdo_protocol::v101::Nonce;

pub(crate) mod kdf;
pub mod software;

// TODO: this can be simplified, encryption can be done by aws_lc_rs in most cases.

/// Cryptographic operations needed for FDO
pub trait Crypto {
    /// Public key encoding
    const PK_ENC: PkEnc;

    /// Public key type
    fn pk_type(&mut self) -> PkType;

    /// Device Signing information.
    ///
    /// Is used to encode parameters for the device attestation signature.
    fn sign_info_type(&self) -> DeviceSgType;

    /// Key exchange parameters.
    fn kex_suit(&mut self) -> KexSuitNames;

    /// Encryption algorithm for `CoseEncrypt0` objects
    fn cipher_suite(&mut self) -> CoseAlgorithm;

    /// Create and sing a CSR with the CN of the device info
    fn csr(&mut self, device_info: &str) -> impl Future<Output = Result<Vec<u8>, Error>> + Send;

    /// Create a hmac_secret and return an encrypted version.
    fn hmac_secret(&mut self) -> impl Future<Output = Result<CoseEncrypt0, Error>> + Send;

    /// Singes the header using the provided encrypted secret.
    fn hmac(
        &mut self,
        enc_secret: &CoseEncrypt0,
        header: &[u8],
    ) -> impl Future<Output = Result<HMac<'static>, Error>> + Send;

    /// Verifies an HMac signature with a provided encrypted secret.
    fn verify_hmac(
        &mut self,
        ec_secret: &CoseEncrypt0,
        hmac: &HMac<'_>,
        data: &[u8],
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Computes a digest
    fn hash(&mut self, data: &[u8]) -> Result<Hash<'static>, Error> {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data);

        Hash::with_sha256(Cow::Owned(ByteBuf::from(digest.as_ref())))
            .ok_or(Error::new(ErrorKind::Invalid, "digest"))
    }

    /// Singes a payload into a COSE Sign1 object.
    fn cose_sign(
        &mut self,
        unprotected: HeaderBuilder,
        payload: Vec<u8>,
    ) -> impl Future<Output = Result<CoseSign1, Error>> + Send;

    /// Creates a random [`Nonce`]
    fn create_nonce(&mut self) -> impl Future<Output = Result<Nonce, Error>> + Send;

    /// Verifies a COSE signature.
    fn verify_cose_signature(sign: &CoseSign1, pub_key: &PublicKey) -> Result<(), Error> {
        let alg = sign
            .protected
            .header
            .alg
            .as_ref()
            .and_then(|alg| match alg {
                coset::RegisteredLabelWithPrivate::Assigned(alg) => Some(alg),
                coset::RegisteredLabelWithPrivate::PrivateUse(_)
                | coset::RegisteredLabelWithPrivate::Text(_) => None,
            })
            .ok_or(Error::new(ErrorKind::Invalid, "missing alg header"))?;

        debug!(
            pub_key = ?pub_key.pk_type(),
            algo = ?alg,
            "checking algorithm and public key"
        );

        let key = pub_key
            .key()
            .ok_or(Error::new(ErrorKind::Invalid, "public key"))?;

        let key = match (pub_key.pk_type(), alg) {
            (PkType::Secp256R1, coset::iana::Algorithm::ES256) => {
                aws_lc_rs::signature::UnparsedPublicKey::new(
                    &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED,
                    key,
                )
            }
            (PkType::Secp384R1, coset::iana::Algorithm::ES384) => {
                aws_lc_rs::signature::UnparsedPublicKey::new(
                    &aws_lc_rs::signature::ECDSA_P384_SHA384_FIXED,
                    key,
                )
            }
            (PkType::Rsa2048Restr, coset::iana::Algorithm::RS256)
            | (PkType::RsaPkcs, coset::iana::Algorithm::RS256) => {
                aws_lc_rs::signature::UnparsedPublicKey::new(
                    &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256,
                    key,
                )
            }
            (PkType::RsaPkcs, coset::iana::Algorithm::RS384) => {
                aws_lc_rs::signature::UnparsedPublicKey::new(
                    &aws_lc_rs::signature::RSA_PKCS1_3072_8192_SHA384,
                    key,
                )
            }
            (PkType::RsaPss, coset::iana::Algorithm::RS256) => {
                aws_lc_rs::signature::UnparsedPublicKey::new(
                    &aws_lc_rs::signature::RSA_PSS_2048_8192_SHA256,
                    key,
                )
            }
            (PkType::RsaPss, coset::iana::Algorithm::RS384) => {
                aws_lc_rs::signature::UnparsedPublicKey::new(
                    &aws_lc_rs::signature::RSA_PSS_2048_8192_SHA384,
                    key,
                )
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::Invalid,
                    "unsupported or invalid cose signing algorithm and public key pair",
                ))
            }
        };

        sign.verify_signature(&[], |signature, message| key.verify(message, signature))
            .map_err(|_| Error::new(ErrorKind::Crypto, "to verify cose signature"))?;

        Ok(())
    }

    /// Verifies an Hash
    fn verify_hash(to_check: &Hash<'_>, data: &[u8]) -> Result<(), Error> {
        let alg = match to_check.hash_type() {
            Hashtype::Sha256 => &aws_lc_rs::digest::SHA256,
            Hashtype::Sha384 => &aws_lc_rs::digest::SHA384,
            Hashtype::HmacSha256 | Hashtype::HmacSha384 => {
                return Err(Error::new(ErrorKind::Invalid, "hmac type instead of hash"))
            }
        };

        let digest = aws_lc_rs::digest::digest(alg, data);

        if to_check.as_ref() != digest.as_ref() {
            return Err(Error::new(ErrorKind::Invalid, "hash mismatch"));
        }

        Ok(())
    }

    /// Verifies an Hash
    type KeyExchange;

    /// Used in the key exchange.
    ///
    /// This should return an ephemeral key for the communication with the owner.
    fn key_exchange(
        &mut self,
        ow_key: &XAKeyExchange,
    ) -> impl Future<Output = Result<(XBKeyExchange<'static>, Self::KeyExchange), Error>> + Send;

    /// Decrypts a COSE Encrypted objects.
    fn cose_decrypt(enc: &CoseEncrypt0, key: &Self::KeyExchange) -> Result<Vec<u8>, Error>;

    /// Encrypts a COSE Encrypted objects.
    fn cose_encrypt(
        &mut self,
        key: &Self::KeyExchange,
        payload: &[u8],
    ) -> Result<CoseEncrypt0, Error>;
}
