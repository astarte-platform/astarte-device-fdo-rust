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

//! Software based crypto operations.

use std::borrow::Cow;
use std::io::Write;

use astarte_fdo_protocol::error::ErrorKind;
use astarte_fdo_protocol::v101::hash_hmac::{HMac, Hashtype};
use astarte_fdo_protocol::v101::key_exchange::{
    AsEccKey, EcdhParams, KexSuitNames, XAKeyExchange, XBKeyExchange,
};
use astarte_fdo_protocol::v101::public_key::{PkEnc, PkType};
use astarte_fdo_protocol::v101::sign_info::DeviceSgType;
use astarte_fdo_protocol::v101::Nonce;
use astarte_fdo_protocol::Error;
use aws_lc_rs::aead::{Aad, RandomizedNonceKey};
use aws_lc_rs::agreement;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair};
use coset::iana::Algorithm as CoseAlgorithm;
use coset::{CoseEncrypt0, CoseSign1, CoseSign1Builder, HeaderBuilder};
use rcgen::{CertificateParams, DistinguishedName, DnType};
use serde_bytes::ByteBuf;
use tracing::{debug, error};
use zeroize::Zeroizing;

use crate::crypto::kdf;
use crate::storage::Storage;

use super::Crypto;

const AES_256_KEY_FILE: &str = "aes-256-key.bin";
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

        if !this.storage.exists(AES_256_KEY_FILE).await? {
            this.create_aes_key().await?;
        }

        if !this.storage.exists(PRIVATE_ECC_KEY_FILE).await? {
            this.create_signing_keys().await?;
        }

        Ok(this)
    }

    fn alg() -> &'static aws_lc_rs::signature::EcdsaSigningAlgorithm {
        &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING
    }

    async fn create_aes_key(&self) -> Result<(), Error>
    where
        S: Storage,
    {
        let mut key = Zeroizing::new(vec![0; aws_lc_rs::digest::SHA256_OUTPUT_LEN]);

        self.rng
            .fill(key.as_mut_slice())
            .map_err(|_| Error::new(ErrorKind::Crypto, "to generate key"))?;

        self.storage.write_immutable(AES_256_KEY_FILE, &key).await?;

        Ok(())
    }

    async fn aes_key(&self) -> Result<Zeroizing<Vec<u8>>, Error>
    where
        S: Storage + Send + Sync,
    {
        let key = self
            .storage
            .read_secret(AES_256_KEY_FILE)
            .await
            .and_then(|key| key.ok_or(Error::new(ErrorKind::Io, "key file is missing")))?;

        debug_assert_eq!(key.len(), 32);

        Ok(key)
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

    async fn signing_key(&self) -> Result<EcdsaKeyPair, Error>
    where
        S: Storage,
    {
        let bytes = self
            .storage
            .read(PRIVATE_ECC_KEY_FILE)
            .await
            .and_then(|key| key.ok_or(Error::new(ErrorKind::Io, "signing key is missing")))?;

        let bytes = Zeroizing::new(bytes);

        let key = EcdsaKeyPair::from_pkcs8(Self::alg(), &bytes).map_err(|err| {
            error!(error = %err, "couldn't parse signing key");

            Error::new(ErrorKind::Crypto, "to parse signing key")
        })?;

        Ok(key)
    }

    async fn decrypt_secret(
        &mut self,
        ec_secret: &coset::CoseEncrypt0,
    ) -> Result<Zeroizing<Vec<u8>>, Error>
    where
        S: Storage,
    {
        let alg = ec_secret.protected.header.alg.as_ref().ok_or(Error::new(
            ErrorKind::Invalid,
            "missing alg header in cose object",
        ))?;

        if *alg != coset::RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::A256GCM) {
            return Err(Error::new(ErrorKind::Invalid, "invalid cose algorithm"));
        }

        let aes_key = self.aes_key().await?;

        let key = RandomizedNonceKey::new(&aws_lc_rs::aead::AES_256_GCM, &aes_key)
            .map_err(|_| Error::new(ErrorKind::Crypto, "to create randomized nonce"))?;

        let nonce = aws_lc_rs::aead::Nonce::try_assume_unique_for_key(&ec_secret.unprotected.iv)
            .map_err(|_| Error::new(ErrorKind::Invalid, "iv for nonce"))?;

        let hmac_secret = ec_secret
            .decrypt_ciphertext(
                &[],
                || Error::new(ErrorKind::Invalid, "missing chiphertext"),
                |ciphertext, aad| {
                    let aad = Aad::from(aad);
                    let mut ciphertext = Vec::from(ciphertext);

                    let len = key
                        .open_in_place(nonce, aad, &mut ciphertext)
                        .map_err(|_| Error::new(ErrorKind::Crypto, "to aead decrypt secret"))?
                        .len();

                    ciphertext.resize(len, 0);

                    Ok(ciphertext)
                },
            )
            .map(Zeroizing::new)?;

        Ok(hmac_secret)
    }

    async fn encrypt_secret(
        &mut self,
        hmac_secret: Zeroizing<Vec<u8>>,
    ) -> Result<coset::CoseEncrypt0, Error>
    where
        S: Storage,
    {
        let aes_key = self.aes_key().await?;

        let key = RandomizedNonceKey::new(&aws_lc_rs::aead::AES_256_GCM, &aes_key)
            .map_err(|_| Error::new(ErrorKind::Crypto, "to generate randomized nonce"))?;

        let protected = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::A256GCM)
            .build();

        let mut nonce = None;

        let builder = coset::CoseEncrypt0Builder::new()
            .protected(protected)
            .try_create_ciphertext(&hmac_secret, &[], |plain, aad| {
                let mut in_out = Vec::from(plain);

                let gen_nonce = key
                    .seal_in_place_append_tag(Aad::from(aad), &mut in_out)
                    .map_err(|_| Error::new(ErrorKind::Crypto, "to AEAD encrypt"))?;

                nonce = Some(gen_nonce);

                Ok(in_out)
            })?;

        let nonce = nonce.ok_or(Error::new(ErrorKind::Invalid, "nonce not created"))?;

        let unprotected = coset::HeaderBuilder::new()
            .iv(nonce.as_ref().to_vec())
            .build();

        let hmac_enc = builder.unprotected(unprotected).build();

        Ok(hmac_enc)
    }
}

impl<S> Crypto for SoftwareCrypto<S>
where
    S: Storage + Send + Sync,
{
    const PK_ENC: PkEnc = PkEnc::X509;

    fn pk_type(&mut self) -> PkType {
        PkType::Secp256R1
    }

    fn sign_info_type(&self) -> DeviceSgType {
        DeviceSgType::StSecP256R1
    }

    fn kex_suit(&mut self) -> KexSuitNames {
        KexSuitNames::ECDH256
    }

    fn cipher_suite(&mut self) -> CoseAlgorithm {
        CoseAlgorithm::A256GCM
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

        let key = self.signing_key().await?;

        let compat = RcgenKeyCompat::new(&key, &self.rng);

        // Singed CSR
        let csr = csr_param.serialize_request(&compat).map_err(|err| {
            error!(error = %err,"coudln't create serialize csr");

            Error::new(ErrorKind::Crypto, "to serialize csr")
        })?;

        Ok(csr.der().to_vec())
    }

    async fn hmac_secret(&mut self) -> Result<coset::CoseEncrypt0, Error> {
        let mut hmac_secret = Zeroizing::new(vec![0; aws_lc_rs::digest::SHA256_OUTPUT_LEN]);

        self.rng
            .fill(hmac_secret.as_mut_slice())
            .map_err(|_| Error::new(ErrorKind::Crypto, "to generate hmac secret"))?;

        let hmac_enc = self.encrypt_secret(hmac_secret).await?;

        Ok(hmac_enc)
    }

    async fn hmac(
        &mut self,
        ec_secret: &coset::CoseEncrypt0,
        data: &[u8],
    ) -> Result<HMac<'static>, Error> {
        let hmac_secret = self.decrypt_secret(ec_secret).await?;

        let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, hmac_secret.as_slice());

        let tag = aws_lc_rs::hmac::sign(&key, data);

        let hmac = HMac::with_sha256(Cow::Owned(ByteBuf::from(tag.as_ref())))
            .ok_or(Error::new(ErrorKind::Invalid, "to create hmac"))?;

        Ok(hmac)
    }

    async fn verify_hmac(
        &mut self,
        ec_secret: &CoseEncrypt0,
        hmac: &HMac<'_>,
        data: &[u8],
    ) -> Result<(), Error> {
        let sec = self.decrypt_secret(ec_secret).await?;

        let alg = match hmac.hash_type() {
            Hashtype::HmacSha256 => {
                debug_assert_eq!(sec.len(), 32, "secret length");

                aws_lc_rs::hmac::HMAC_SHA256
            }
            Hashtype::HmacSha384 => {
                debug_assert_eq!(sec.len(), 48, "secret length");

                aws_lc_rs::hmac::HMAC_SHA384
            }
            Hashtype::Sha256 | Hashtype::Sha384 => {
                return Err(Error::new(ErrorKind::Invalid, "hash type for hmac"));
            }
        };

        let key = aws_lc_rs::hmac::Key::new(alg, &sec);

        aws_lc_rs::hmac::verify(&key, data, hmac.as_ref())
            .map_err(|_| Error::new(ErrorKind::Crypto, "to verify hmac"))
    }

    async fn cose_sign(
        &mut self,
        unprotected: HeaderBuilder,
        payload: Vec<u8>,
    ) -> Result<CoseSign1, Error> {
        let key = self.signing_key().await?;

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

    async fn create_nonce(&mut self) -> Result<Nonce, Error> {
        let mut nonce = Nonce::default();

        self.rng
            .fill(nonce.as_mut_slice())
            .map_err(|_| Error::new(ErrorKind::Crypto, "to create nonce"))?;

        Ok(nonce)
    }

    type KeyExchange = Zeroizing<[u8; 32]>;

    // TODO: support different keys?
    async fn key_exchange(
        &mut self,
        ow_key: &XAKeyExchange<'_>,
    ) -> Result<(XBKeyExchange<'static>, Self::KeyExchange), Error> {
        let dv_priv_key =
            agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &self.rng)
                .map_err(|_| Error::new(ErrorKind::Crypto, "to create agreement key"))?;

        // 128 bits for ECDH256
        let mut dv_rand = [0u8; 16];
        self.rng
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

    fn cose_decrypt(enc: &CoseEncrypt0, key: &Self::KeyExchange) -> Result<Vec<u8>, Error> {
        let alg = enc.protected.header.alg.as_ref().ok_or(Error::new(
            ErrorKind::Invalid,
            "missing alg header in cose object",
        ))?;

        debug!(?alg);

        if *alg != coset::RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::A256GCM) {
            return Err(Error::new(ErrorKind::Invalid, "invalid cose algorithm"));
        }

        let key = RandomizedNonceKey::new(&aws_lc_rs::aead::AES_256_GCM, key.as_slice())
            .map_err(|_| Error::new(ErrorKind::Crypto, "to create randomized nonce"))?;
        debug!("key created");

        let nonce = aws_lc_rs::aead::Nonce::try_assume_unique_for_key(&enc.unprotected.iv)
            .map_err(|_| Error::new(ErrorKind::Crypto, "to create aead nonce"))?;
        debug!("nonce created");

        enc.decrypt_ciphertext(
            &[],
            || Error::new(ErrorKind::Invalid, "missing cypher text"),
            |ciphertext, aad| {
                let aad = Aad::from(aad);
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

    fn cose_encrypt(
        &mut self,
        key: &Self::KeyExchange,
        payload: &[u8],
    ) -> Result<CoseEncrypt0, Error> {
        let key = RandomizedNonceKey::new(&aws_lc_rs::aead::AES_256_GCM, key.as_slice())
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
                    .seal_in_place_append_tag(Aad::from(aad), &mut in_out)
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
