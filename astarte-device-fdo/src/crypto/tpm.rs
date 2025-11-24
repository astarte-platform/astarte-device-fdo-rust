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

//! Stores secrets and sign messages using a TPM.

use std::borrow::Cow;
use std::cell::RefCell;
use std::str::FromStr;

use astarte_fdo_protocol::error::ErrorKind;
use astarte_fdo_protocol::v101::hash_hmac::HMac;
use astarte_fdo_protocol::v101::key_exchange::{AsEccKey, EcdhParams};
use astarte_fdo_protocol::Error;
use coset::{CoseSign1Builder, HeaderBuilder};
use rcgen::{CertificateParams, DistinguishedName, DnType};
use serde_bytes::{ByteBuf, Bytes};
use tracing::{error, info};
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{
    CreateKeyResult, Digest, EccPoint, HashScheme, KeyedHashScheme, MaxBuffer, PcrSelectionList,
    PcrSlot, Private, Public, PublicBuilder, PublicEccParameters, PublicKeyedHashParameters,
    Signature, SignatureScheme, SymmetricCipherParameters, SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::traits::{Marshall, UnMarshall};

use crate::Storage;

use super::{Crypto, DefaultKeyExchange};

const TPM_CONNECTION: &str = "device:/dev/tpmrm0";

struct TpmEcc {
    private: Private,
    public: Public,
}

impl TpmEcc {
    const FILE_PUBLIC: &'static str = "public-key.ecc.bin";
    const FILE_PRIVATE: &'static str = "private-key.ecc.bin";

    async fn load<S>(
        ctx: &mut tss_esapi::Context,
        primary: KeyHandle,
        storage: &S,
    ) -> Result<Self, Error>
    where
        S: Storage,
    {
        let public = storage.read(Self::FILE_PUBLIC).await?;
        let private = storage.read(Self::FILE_PRIVATE).await?;

        let Some((public, private)) = public.iter().zip(private).next() else {
            return Self::create(ctx, primary, storage).await;
        };

        let private = Private::try_from(private).map_err(|error| {
            error!(%error, "couldn't read private");

            Error::new(ErrorKind::Decode, "ECC private part")
        })?;
        let public = Public::unmarshall(public).map_err(|error| {
            error!(%error, "couldn't unmarshall public");

            Error::new(ErrorKind::Decode, "ECC public part")
        })?;

        if !matches!(public, Public::Ecc { .. }) {
            return Err(Error::new(ErrorKind::Invalid, "public part is not for ECC"));
        }

        Ok(Self { private, public })
    }

    async fn create<S>(
        ctx: &mut tss_esapi::Context,
        primary: KeyHandle,
        storage: &S,
    ) -> Result<Self, Error>
    where
        S: Storage,
    {
        let this = Self::generate(ctx, primary).map_err(|error| {
            error!(%error, "coudln't create TPM signing key");

            Error::new(ErrorKind::Crypto, "to create TPM signing key")
        })?;

        let public = this.public.marshall().map_err(|error| {
            error!(%error, "couldn't encode TPM signing public key");

            Error::new(ErrorKind::Encode, "TPM signing public key")
        })?;
        storage.write_immutable(Self::FILE_PUBLIC, &public).await?;
        storage
            .write_immutable(Self::FILE_PRIVATE, &this.private)
            .await?;

        Ok(this)
    }

    fn generate(
        ctx: &mut tss_esapi::Context,
        primary: KeyHandle,
    ) -> Result<Self, tss_esapi::Error> {
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(false)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            // The key is used only for signing.
            .with_sign_encrypt(true)
            .build()?;

        let ecc_params = PublicEccParameters::builder()
            .with_ecc_scheme(tss_esapi::structures::EccScheme::EcDsa(HashScheme::new(
                HashingAlgorithm::Sha256,
            )))
            .with_curve(EccCurve::NistP256)
            .with_key_derivation_function_scheme(
                tss_esapi::structures::KeyDerivationFunctionScheme::Null,
            )
            .with_is_signing_key(true)
            .build()?;

        let key_pub = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_ecc_parameters(ecc_params)
            .with_object_attributes(object_attributes)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()?;

        let key = ctx.execute_with_nullauth_session(|ctx| {
            ctx.create(primary, key_pub, None, None, None, None)
        })?;

        info!("created signing key");

        Ok(TpmEcc::from(key))
    }
}

impl From<CreateKeyResult> for TpmEcc {
    fn from(value: CreateKeyResult) -> Self {
        Self {
            private: value.out_private,
            public: value.out_public,
        }
    }
}

// TODO: this can be passed to the DI/TO2 after creating it, to be stored in the DeviceCredentials
struct TpmHmac {
    public: Public,
    private: Private,
}

impl TpmHmac {
    async fn decode(secret: &[u8]) -> Result<Self, Error> {
        let [public, private]: [Cow<Bytes>; 2] =
            ciborium::from_reader(secret).map_err(|error| {
                error!(%error, "couldn't decode TPM HMAC secret");

                Error::new(ErrorKind::Decode, "HMAC secret")
            })?;

        let private: &[u8] = private.as_ref();
        let private = Private::try_from(private).map_err(|error| {
            error!(%error, "couldn't read private");

            Error::new(ErrorKind::Decode, "HMAC private part")
        })?;
        let public = Public::unmarshall(&public).map_err(|error| {
            error!(%error, "couldn't unmarshall public");

            Error::new(ErrorKind::Decode, "HMAC public part")
        })?;

        if !matches!(public, Public::KeyedHash { .. }) {
            return Err(Error::new(
                ErrorKind::Invalid,
                "public part is not for HMAC",
            ));
        }

        Ok(Self { public, private })
    }

    async fn create(ctx: &mut tss_esapi::Context, primary: KeyHandle) -> Result<Vec<u8>, Error> {
        let this = Self::generate(ctx, primary).map_err(|error| {
            error!(%error, "coudln't create TPM signing key");

            Error::new(ErrorKind::Crypto, "to create TPM signing key")
        })?;

        let public = this.public.marshall().map_err(|error| {
            error!(%error, "couldn't encode TPM signing public key");

            Error::new(ErrorKind::Encode, "TPM signing public key")
        })?;

        let mut buf = Vec::new();
        ciborium::into_writer(&[public.as_slice(), this.private.as_slice()], &mut buf).map_err(
            |error| {
                error!(%error, "couldn't encode TPM HMAC secret");

                Error::new(ErrorKind::Encode, "HMAC secret")
            },
        )?;

        Ok(buf)
    }

    fn generate(
        ctx: &mut tss_esapi::Context,
        primary: KeyHandle,
    ) -> Result<TpmHmac, tss_esapi::Error> {
        // Create the HMAC key. This key exists under the primary key in it's hierarchy
        // and can only be used if the same primary key is recreated from the parameters
        // defined above.
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(false)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            // The key is used only for signing.
            .with_sign_encrypt(true)
            .build()
            .expect("Failed to build object attributes");

        let key_pub = PublicBuilder::new()
            // This key is a HMAC key
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
                KeyedHashScheme::HMAC_SHA_256,
            ))
            .with_keyed_hash_unique_identifier(Digest::default())
            .build()
            .unwrap();

        ctx.execute_with_nullauth_session(|ctx| {
            // Create the HMAC key given our primary key as it's parent. This returns the private
            // and public portions of the key. It's *important* to note that the private component
            // is *encrypted* by a key associated with the primary key. It is not plaintext or
            // leaked in this step.
            ctx.create(primary, key_pub, None, None, None, None)
        })
        .map(TpmHmac::from)
        .inspect(|_| info!("TPM hmac created"))
    }
}

impl From<CreateKeyResult> for TpmHmac {
    fn from(value: CreateKeyResult) -> Self {
        Self {
            private: value.out_private,
            public: value.out_public,
        }
    }
}

/// TPM handle
pub struct Tpm {
    ctx: tss_esapi::Context,
    primary: KeyHandle,
    sign: TpmEcc,
    rng: aws_lc_rs::rand::SystemRandom,
}

impl Tpm {
    /// Create a new TPM with defaults parameters
    ///
    /// Defaults to: 0,1,5    Firmware, Options, GPT
    ///              7        Secure Boot
    pub async fn create<S>(storage: &S) -> Result<Self, Error>
    where
        S: Storage,
    {
        Self::with_pcrs(storage, &[0, 2, 4, 6, 7]).await
    }

    /// Create a new TPM with defaults parameters
    pub async fn with_pcrs<S>(storage: &S, pcrs: &[u8]) -> Result<Self, Error>
    where
        S: Storage,
    {
        Self::with_connection(storage, TPM_CONNECTION, pcrs).await
    }

    /// Create a new TPM using the provided connection string and PCRs registries.
    pub async fn with_connection<S>(
        storage: &S,
        tpm_connection: &str,
        pcrs: &[u8],
    ) -> Result<Self, Error>
    where
        S: Storage,
    {
        let conf = TctiNameConf::from_str(tpm_connection).map_err(|error| {
            error!(%error, "couldn't parse TPM connection");

            Error::new(ErrorKind::Invalid, "TPM connection")
        })?;
        // TODO: check if we need to use new_with_tabrmgr for multiuser
        let mut ctx = tss_esapi::Context::new(conf).map_err(|error| {
            error!(%error, "couldn't connect TPM device");

            Error::new(ErrorKind::Io, "to connect with TPM device")
        })?;

        info!(tpm_connection, "connected to tpm");

        // TODO: should we support multiple enc or check capabilities
        //let caps = Self::read_caps(&mut ctx)?;
        // info!(?caps, "capabilities gathered");

        let pcrs = Self::pcr_slots(pcrs)?;
        let pcrs = PcrSelectionList::builder()
            .with_selection(HashingAlgorithm::Sha256, &pcrs)
            .build()
            .map_err(|error| {
                error!(%error, "couldn't get TPM PCRs selection");

                Error::new(ErrorKind::Io, "to get TPM PCRs selection")
            })?;

        let primary = Self::create_primary(&mut ctx, pcrs).map_err(|error| {
            error!(%error,"couldn't create primary sym key");

            Error::new(ErrorKind::Io, "to create primary TPM key")
        })?;
        let sign = TpmEcc::load(&mut ctx, primary, storage).await?;

        Ok(Self {
            ctx,
            primary,
            sign,
            rng: aws_lc_rs::rand::SystemRandom::new(),
        })
    }

    fn pcr_slots(pcrs: &[u8]) -> Result<Vec<PcrSlot>, Error> {
        pcrs.iter()
            .map(|value| {
                let pcr = match value {
                    0 => PcrSlot::Slot0,
                    1 => PcrSlot::Slot1,
                    2 => PcrSlot::Slot2,
                    3 => PcrSlot::Slot3,
                    4 => PcrSlot::Slot4,
                    5 => PcrSlot::Slot5,
                    6 => PcrSlot::Slot6,
                    7 => PcrSlot::Slot7,
                    8 => PcrSlot::Slot8,
                    9 => PcrSlot::Slot9,
                    10 => PcrSlot::Slot10,
                    11 => PcrSlot::Slot11,
                    12 => PcrSlot::Slot12,
                    13 => PcrSlot::Slot13,
                    14 => PcrSlot::Slot14,
                    15 => PcrSlot::Slot15,
                    16 => PcrSlot::Slot16,
                    17 => PcrSlot::Slot17,
                    18 => PcrSlot::Slot18,
                    19 => PcrSlot::Slot19,
                    20 => PcrSlot::Slot20,
                    21 => PcrSlot::Slot21,
                    22 => PcrSlot::Slot22,
                    23 => PcrSlot::Slot23,
                    24 => PcrSlot::Slot24,
                    25 => PcrSlot::Slot25,
                    26 => PcrSlot::Slot26,
                    27 => PcrSlot::Slot27,
                    28 => PcrSlot::Slot28,
                    29 => PcrSlot::Slot29,
                    30 => PcrSlot::Slot30,
                    31 => PcrSlot::Slot31,
                    _ => {
                        error!(slot = value, "PCRs slot out of range");

                        return Err(Error::new(ErrorKind::OutOfRange, "PCRs slot"));
                    }
                };

                Ok(pcr)
            })
            .collect()
    }

    fn create_primary(
        ctx: &mut tss_esapi::Context,
        pcrs: PcrSelectionList,
    ) -> Result<KeyHandle, tss_esapi::Error> {
        // These other objects are encrypted by the primary key allowing them to persist
        // over a reboot and reloads.
        //
        // A primary key is derived from a seed, and provided that the same inputs are given
        // the same primary key will be derived in the tpm. This means that you do not need
        // to store or save the details of this key - only the parameters of how it was created.

        let object_attributes = ObjectAttributesBuilder::new()
            // Indicate the key can only exist within this tpm and can not be exported.
            .with_fixed_tpm(true)
            // The primary key and it's descendent keys can't be moved to other primary
            // keys.
            .with_fixed_parent(true)
            // The primary key will persist over suspend and resume of the system.
            .with_st_clear(false)
            // The primary key was generated entirely inside the TPM - only this TPM
            // knows it's content.
            .with_sensitive_data_origin(true)
            // This key requires "authentication" to the TPM to access - this can be
            // an HMAC or password session. HMAC sessions are used by default with
            // the "execute_with_nullauth_session" function.
            .with_user_with_auth(true)
            // This key has the ability to decrypt
            .with_decrypt(true)
            // This key may only be used to encrypt or sign objects that are within
            // the TPM - it can not encrypt or sign external data.
            .with_restricted(true)
            .build()?;

        let primary_pub = PublicBuilder::new()
            // This key is a symmetric key.
            .with_public_algorithm(PublicAlgorithm::SymCipher)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_symmetric_cipher_parameters(SymmetricCipherParameters::new(
                SymmetricDefinitionObject::AES_256_CFB,
            ))
            .with_symmetric_cipher_unique_identifier(tss_esapi::structures::Digest::default())
            .build()?;

        ctx.execute_with_nullauth_session(|ctx| {
            // Create the key under the "owner" hierarchy. Other hierarchies are platform
            // which is for boot services, null which is ephemeral and resets after a reboot,
            // and endorsement which allows key certification by the TPM manufacturer.
            ctx.create_primary(Hierarchy::Owner, primary_pub, None, None, None, Some(pcrs))
        })
        .map(|res| res.key_handle)
        .inspect(|_| info!("created primary key handle"))
    }

    fn sign(&mut self, data: &[u8]) -> Result<p256::ecdsa::Signature, Error> {
        let data = MaxBuffer::try_from(data).map_err(|error| {
            error!(%error, "couldn't allocate signing max buffer");

            Error::new(ErrorKind::Crypto, "to allocate signing buffer")
        })?;

        self.ctx
            .execute_with_nullauth_session(|ctx| {
                let hash_alg = HashingAlgorithm::Sha256;
                let (digest, validation) = ctx.hash(data, hash_alg, Hierarchy::Null)?;

                let key = ctx.load(
                    self.primary,
                    self.sign.private.clone(),
                    self.sign.public.clone(),
                )?;

                let scheme = SignatureScheme::EcDsa {
                    hash_scheme: HashScheme::new(hash_alg),
                };

                let res = ctx.sign(key, digest, scheme, validation);

                if let Err(error) = ctx.flush_context(key.into()) {
                    error!(%error, "couldn't flush key from TPM");
                }

                res
            })
            .map_err(|error| {
                error!(%error, "couldn't sign data with TPM");

                Error::new(ErrorKind::Crypto, "to sign with TPM")
            })
            .and_then(|signature| {
                let Signature::EcDsa(signature) = signature else {
                    error!("not a ecc signature");

                    return Err(Error::new(ErrorKind::Invalid, "signature"));
                };

                // https://datatracker.ietf.org/doc/html/rfc3279#section-2.2.3
                // Ecdsa-Sig-Value  ::=  SEQUENCE  {
                // r     INTEGER,
                // s     INTEGER  }
                let r: [u8; 32] = signature
                    .signature_r()
                    .value()
                    .try_into()
                    .map_err(|error| {
                        error!(%error,"signature parameter r is too big");

                        Error::new(ErrorKind::Invalid, "r signature parameter")
                    })?;
                let s: [u8; 32] = signature
                    .signature_s()
                    .value()
                    .try_into()
                    .map_err(|error| {
                        error!(%error,"signature parameter s is too big");

                        Error::new(ErrorKind::Invalid, "r signature parameter")
                    })?;

                p256::ecdsa::Signature::from_scalars(r, s).map_err(|error| {
                    error!(%error, "couldn't parse ecdsa signature" );

                    Error::new(ErrorKind::Invalid, "ecdsa signature")
                })
            })
    }
}

impl Crypto for Tpm {
    type KeyExchange = DefaultKeyExchange;

    fn rng(&mut self) -> &aws_lc_rs::rand::SystemRandom {
        &self.rng
    }

    async fn csr(&mut self, device_info: &str) -> Result<Vec<u8>, Error> {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, device_info);

        let mut csr_param = CertificateParams::new([]).map_err(|err| {
            error!(error = %err,"coudln't create csr parameters");

            Error::new(ErrorKind::Crypto, "to create csr parameters")
        })?;
        csr_param.distinguished_name = dn;

        let compat = RcgenKeyCompat::create(self)?;

        // Singed CSR
        let csr = csr_param.serialize_request(&compat).map_err(|err| {
            error!(error = %err,"coudln't create serialize csr");

            Error::new(ErrorKind::Crypto, "to serialize csr")
        })?;

        Ok(csr.der().to_vec())
    }

    // TODO: refactor this so that the secret is returned
    async fn create_hmac_secret(&mut self) -> Result<Vec<u8>, Error> {
        TpmHmac::create(&mut self.ctx, self.primary).await
    }

    // TODO: refactor this to receive the HMAC as a parameter
    async fn hmac(&mut self, secret: &[u8], data: &[u8]) -> Result<HMac<'static>, Error> {
        let hmac = TpmHmac::decode(secret).await?;

        let buffer = MaxBuffer::try_from(data).map_err(|error| {
            error!(%error, "couldn't create buffer for hmac signign");

            Error::new(ErrorKind::Crypto, "to create buffer for hmac signing")
        })?;

        self.ctx
            .execute_with_nullauth_session(|ctx| {
                // Load the HMAC key into the tpm context.
                let hmac_key = ctx.load(self.primary, hmac.private, hmac.public)?;

                // Perform the HMAC.
                let res = ctx.hmac(hmac_key.into(), buffer, HashingAlgorithm::Sha256);

                if let Err(error) = ctx.flush_context(hmac_key.into()) {
                    error!(%error, "couldn't flush key from TPM");
                }

                res
            })
            .map_err(|error| {
                error!(%error, "couldn't hmac sign");

                Error::new(ErrorKind::Crypto, "to hmac sign")
            })
            .and_then(|digest| {
                HMac::with_sha256(Cow::Owned(ByteBuf::from(digest.value())))
                    .ok_or(Error::new(ErrorKind::Invalid, "hmac"))
            })
    }

    async fn verify_hmac(
        &mut self,
        secret: &[u8],
        hmac: &HMac<'_>,
        data: &[u8],
    ) -> Result<(), Error> {
        let new = self.hmac(secret, data).await?;

        if new != *hmac {
            return Err(Error::new(ErrorKind::Crypto, "to validate hmac"));
        }

        Ok(())
    }

    async fn cose_sign(
        &mut self,
        unprotected: coset::HeaderBuilder,
        payload: Vec<u8>,
    ) -> Result<coset::CoseSign1, Error> {
        let protected = HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::ES256)
            .build();

        let unprotected = unprotected.build();

        let eat = CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(payload)
            .try_create_signature(&[], |bytes| {
                let signature = self.sign(bytes)?;

                Ok(signature.to_vec())
            })?
            .build();

        Ok(eat)
    }
}

struct RcgenKeyCompat<'a> {
    tpm: RefCell<&'a mut Tpm>,
    pub_sec1: [u8; 65],
}

impl<'a> RcgenKeyCompat<'a> {
    fn create(tpm: &'a mut Tpm) -> Result<Self, Error> {
        let tss_esapi::structures::Public::Ecc { unique, .. } = &tpm.sign.public else {
            return Err(Error::new(ErrorKind::Invalid, "public key"));
        };

        let x = unique.x().value().try_into().map_err(|error| {
            error!(%error, "x ecc point wrong size");

            Error::new(ErrorKind::Invalid, "x ecc point")
        })?;

        let y = unique.y().value().try_into().map_err(|error| {
            error!(%error, "x ecc point wrong size");

            Error::new(ErrorKind::Invalid, "x ecc point")
        })?;

        let key = EcdhParams::with_p256(x, y, &[]).as_key();

        Ok(Self {
            pub_sec1: key,
            tpm: RefCell::new(tpm),
        })
    }
}

impl rcgen::PublicKeyData for RcgenKeyCompat<'_> {
    fn der_bytes(&self) -> &[u8] {
        self.pub_sec1.as_slice()
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for RcgenKeyCompat<'_> {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.tpm
            .try_borrow_mut()
            .map_err(|_| rcgen::Error::RingUnspecified)
            .and_then(|mut tpm| tpm.sign(msg).map_err(|_| rcgen::Error::RingUnspecified))
            .map(|sign| sign.to_der().as_bytes().to_vec())
    }
}
