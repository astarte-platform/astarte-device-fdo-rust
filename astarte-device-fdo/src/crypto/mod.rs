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

//! Crypto operations like signing,and encryption.

use std::borrow::Cow;
use std::future::Future;
use std::io::Write;

use astarte_fdo_protocol::error::ErrorKind;
use astarte_fdo_protocol::Error;
use aws_lc_rs::rand::SecureRandom;
use coset::iana::Algorithm as CoseAlgorithm;
use coset::{CoseEncrypt0, CoseSign1, HeaderBuilder};
use serde_bytes::ByteBuf;
use tracing::{debug, error};

use astarte_fdo_protocol::v101::hash_hmac::{HMac, Hash, Hashtype};
use astarte_fdo_protocol::v101::key_exchange::{
    AsEccKey, EcdhParams, KexSuitNames, XAKeyExchange, XBKeyExchange,
};
use astarte_fdo_protocol::v101::public_key::{PkEnc, PkType, PublicKey};
use astarte_fdo_protocol::v101::sign_info::DeviceSgType;
use astarte_fdo_protocol::v101::Nonce;
use zeroize::Zeroizing;

pub(crate) mod kdf;
pub mod software;
#[cfg(feature = "tpm")]
pub mod tpm;

pub(crate) type DefaultKeyExchange = Zeroizing<[u8; 32]>;

/// Cryptographic operations needed for FDO
// TODO: this can be simplified, encryption can be done by aws_lc_rs in most cases.
pub trait Crypto {
    /// Public key encoding
    const PK_ENC: PkEnc = PkEnc::X509;

    /// Type used in the key exchange
    type KeyExchange;

    /// Public key type
    fn pk_type(&mut self) -> PkType {
        PkType::Secp256R1
    }

    /// Device Signing information.
    ///
    /// Is used to encode parameters for the device attestation signature.
    fn sign_info_type(&self) -> DeviceSgType {
        DeviceSgType::StSecP256R1
    }

    /// Key exchange parameters.
    fn kex_suit(&mut self) -> KexSuitNames {
        KexSuitNames::ECDH256
    }

    /// Encryption algorithm for `CoseEncrypt0` objects
    fn cipher_suite(&mut self) -> CoseAlgorithm {
        CoseAlgorithm::A256GCM
    }

    /// Encryption algorithm for `CoseEncrypt0` objects
    fn rng(&mut self) -> &aws_lc_rs::rand::SystemRandom;

    /// Create and sing a CSR with the CN of the device info
    fn csr(&mut self, device_info: &str) -> impl Future<Output = Result<Vec<u8>, Error>> + Send;

    /// Create a hmac_secret and return an encrypted version.
    // TODO: not sure if this is the best abstraction, it's form the spec where they say:
    //
    //       > To the extent possible, storage of the HMAC secret SHOULD be linked to storage of the
    //       > other device credentials, so that modifying any credential invalidates the HMAC secret.
    //
    //       here we should invalidate the previous secret
    fn create_hmac_secret(&mut self) -> impl Future<Output = Result<Vec<u8>, Error>> + Send;

    /// Singes the data using the provided encrypted secret.
    fn hmac(
        &mut self,
        secret: &[u8],
        data: &[u8],
    ) -> impl Future<Output = Result<HMac<'static>, Error>> + Send;

    /// Verifies an HMac signature with a provided encrypted secret.
    fn verify_hmac(
        &mut self,
        secret: &[u8],
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
    fn create_nonce(&mut self) -> Result<Nonce, Error> {
        let mut nonce = Nonce::default();

        self.rng()
            .fill(nonce.as_mut_slice())
            .map_err(|_| Error::new(ErrorKind::Crypto, "to create nonce"))?;

        Ok(nonce)
    }

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

    /// Used in the key exchange.
    ///
    /// This should return an ephemeral key for the communication with the owner.
    fn key_exchange(
        &mut self,
        ow_key: &XAKeyExchange,
    ) -> Result<(XBKeyExchange<'static>, DefaultKeyExchange), Error> {
        let dv_priv_key = aws_lc_rs::agreement::EphemeralPrivateKey::generate(
            &aws_lc_rs::agreement::ECDH_P256,
            self.rng(),
        )
        .map_err(|_| Error::new(ErrorKind::Crypto, "to create agreement key"))?;

        // 128 bits for ECDH256
        let mut dv_rand = [0u8; 16];
        self.rng()
            .fill(dv_rand.as_mut_slice())
            .map_err(|_| Error::new(ErrorKind::Crypto, "to create random part"))?;

        let dv_pub_key = dv_priv_key
            .compute_public_key()
            .map_err(|_| Error::new(ErrorKind::Crypto, "to compute the public key"))?;

        let (bx, by) = parse_ecc_params::<32>(dv_pub_key.as_ref())?;

        let params = EcdhParams::<32>::with_p256(bx, by, &dv_rand);
        let xb_key_exchange = XBKeyExchange::create(params)?;

        let ow_params = ow_key.parse_ecdh_p256()?;

        debug!(ax = ow_params.x().len(), ay = ow_params.y().len());

        if (ow_params.x().len(), ow_params.y().len()) != (32, 32) {
            return Err(Error::new(ErrorKind::Invalid, "mismatched point length"));
        }

        let ow_pub_key = ow_params.as_key();

        let ow_pub_key = aws_lc_rs::agreement::UnparsedPublicKey::new(
            &aws_lc_rs::agreement::ECDH_P256,
            ow_pub_key,
        );

        let key = aws_lc_rs::agreement::agree_ephemeral(
            dv_priv_key,
            ow_pub_key,
            Error::new(ErrorKind::Crypto, "failed key agreement"),
            |sh_x: &[u8]| {
                // create key
                let len = sh_x
                    .len()
                    .checked_add(dv_rand.len())
                    .and_then(|len| len.checked_add(ow_params.rand().len()))
                    .ok_or(Error::new(ErrorKind::OutOfRange, "len overflow"))?;

                let mut sh_se = Zeroizing::new(vec![0u8; len]);

                let mut cursor = std::io::Cursor::new(sh_se.as_mut_slice());

                cursor
                    .write(sh_x)
                    .and_then(|_| cursor.write(dv_rand.as_slice()))
                    .and_then(|_| cursor.write(ow_params.rand()))
                    .map_err(|_| Error::new(ErrorKind::OutOfRange, "for shared secret"))?;

                const LABEL: &[u8; 8] = b"FIDO-KDF";
                // Context rand is "" for ECDH256
                const CONTEXT: &[u8; 22] = b"AutomaticOnboardTunnel";

                const OUTPUT_LEN: usize = 32;

                let mut output_key = [0u8; OUTPUT_LEN];

                kdf::kdf_ru8_lu16::<OUTPUT_LEN>(
                    aws_lc_rs::hmac::HMAC_SHA256,
                    &sh_se,
                    LABEL,
                    CONTEXT,
                    &mut output_key,
                )?;

                let output_key = Zeroizing::new(output_key);

                Ok(output_key)
            },
        )?;

        Ok((xb_key_exchange, key))
    }

    /// Decrypts a COSE Encrypted objects.
    fn cose_decrypt(enc: &CoseEncrypt0, key: &DefaultKeyExchange) -> Result<Vec<u8>, Error> {
        let alg = enc.protected.header.alg.as_ref().ok_or(Error::new(
            ErrorKind::Invalid,
            "missing alg header in cose object",
        ))?;

        debug!(?alg);

        if *alg != coset::RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::A256GCM) {
            return Err(Error::new(ErrorKind::Invalid, "invalid cose algorithm"));
        }

        let key =
            aws_lc_rs::aead::RandomizedNonceKey::new(&aws_lc_rs::aead::AES_256_GCM, key.as_slice())
                .map_err(|_| Error::new(ErrorKind::Crypto, "to create randomized nonce"))?;
        debug!("key created");

        let nonce = aws_lc_rs::aead::Nonce::try_assume_unique_for_key(&enc.unprotected.iv)
            .map_err(|_| Error::new(ErrorKind::Crypto, "to create aead nonce"))?;
        debug!("nonce created");

        enc.decrypt_ciphertext(
            &[],
            || Error::new(ErrorKind::Invalid, "missing cypher text"),
            |ciphertext, aad| {
                let aad = aws_lc_rs::aead::Aad::from(aad);
                let mut in_out = Vec::from(ciphertext);

                let len = key
                    .open_in_place(nonce, aad, &mut in_out)
                    .map_err(|_| Error::new(ErrorKind::Crypto, "to decrypt message"))?
                    .len();

                // remove the length
                in_out.resize(len, 0);

                Ok(in_out)
            },
        )
    }

    /// Encrypts a COSE Encrypted objects.
    fn cose_encrypt(
        &mut self,
        key: &DefaultKeyExchange,
        payload: &[u8],
    ) -> Result<CoseEncrypt0, Error> {
        let key =
            aws_lc_rs::aead::RandomizedNonceKey::new(&aws_lc_rs::aead::AES_256_GCM, key.as_slice())
                .map_err(|_| Error::new(ErrorKind::Crypto, "to create randomized nonce"))?;

        let protected = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::A256GCM)
            .build();

        let mut nonce = None;

        let builder = coset::CoseEncrypt0Builder::new()
            .protected(protected)
            .try_create_ciphertext(payload, &[], |plain, aad| {
                let mut in_out = Vec::from(plain);

                let gen_nonce = key
                    .seal_in_place_append_tag(aws_lc_rs::aead::Aad::from(aad), &mut in_out)
                    .map_err(|_| Error::new(ErrorKind::Crypto, "to encrypt message"))?;
                nonce = Some(gen_nonce);

                Ok(in_out)
            })?;

        let nonce = nonce.ok_or(Error::new(ErrorKind::Invalid, "nonce not created"))?;

        let unprotected = coset::HeaderBuilder::new()
            .iv(nonce.as_ref().to_vec())
            .build();

        let enc = builder.unprotected(unprotected).build();

        Ok(enc)
    }
}

fn parse_ecc_params<const N: usize>(buf: &[u8]) -> Result<(&[u8; N], &[u8; N]), Error> {
    // 0x4 || x || y
    if buf.len() != 1 + N + N {
        debug!(key_len = buf.len());

        return Err(Error::new(ErrorKind::Invalid, "ecc key length"));
    }

    if buf[0] != 0x4 {
        debug!(first_byte = buf[0]);

        return Err(Error::new(ErrorKind::Invalid, "ecc first byte encoding"));
    }

    let (x, y) = buf[1..].split_at(32);

    let x: &[u8; N] = x.try_into().map_err(|err| {
        error!(error = %err, "couldn't parse ecc x param");

        Error::new(ErrorKind::Invalid, "x param length")
    })?;

    let y: &[u8; N] = y.try_into().map_err(|err| {
        error!(error = %err, "couldn't parse ecc y param");

        Error::new(ErrorKind::Invalid, "x param length")
    })?;

    Ok((x, y))
}
