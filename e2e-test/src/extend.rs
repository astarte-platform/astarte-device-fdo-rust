// This file is part of Astarte.
//
// Copyright 2026 SECO Mind Srl
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::fmt::Display;
use std::path::PathBuf;

use astarte_device_fdo::astarte_fdo_protocol;
use astarte_device_fdo::astarte_fdo_protocol::v101::hash_hmac::Hash;
use astarte_device_fdo::astarte_fdo_protocol::v101::ownership_voucher::{
    OvEntry, OvEntryPayload, OwnershipVoucher,
};
use astarte_device_fdo::astarte_fdo_protocol::v101::public_key::PkType;
use astarte_device_fdo::astarte_fdo_protocol::v101::x509::X509;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::ParsedPublicKey;
use base64::Engine;
use coset::{CoseSign1, CoseSign1Builder, HeaderBuilder};
use eyre::{Context, OptionExt, eyre};
use rustls_pki_types::pem::SectionKind;
use serde_bytes::ByteBuf;
use tokio::io::{AsyncWriteExt, BufWriter};
use tracing::{info, instrument};

const PREFIX: &str = "-----BEGIN OWNERSHIP VOUCHER-----";
const SUFFIX: &str = "-----END OWNERSHIP VOUCHER-----";
const BASE64: &base64::engine::GeneralPurpose = &base64::engine::general_purpose::STANDARD;

pub(crate) fn parse_voucher(ov_voucher: &str) -> eyre::Result<OwnershipVoucher<'static>> {
    let voucher = ov_voucher
        .trim()
        .strip_prefix(PREFIX)
        .ok_or_eyre("missing ov header")?;
    let voucher = voucher.strip_suffix(SUFFIX).ok_or_eyre("missing footer")?;

    let voucher: String = voucher.split_ascii_whitespace().collect();
    let voucher = BASE64.decode(voucher)?;

    let voucher: OwnershipVoucher =
        ciborium::from_reader(voucher.as_slice()).wrap_err("couldn't parse ownership voucher")?;

    Ok(voucher)
}

#[derive(Debug, Clone, clap::Args)]
pub(crate) struct Extend {
    /// Key format
    #[arg(long)]
    in_format: KeyFormat,

    /// Key algorithm to use.
    #[arg(long)]
    alg: Alg,

    /// Current owner private key
    #[arg(long)]
    current_ow_priv: PathBuf,

    /// Next owner certificate
    #[arg(long)]
    next_ow_cert: PathBuf,

    /// Ownership voucher to extend
    #[arg(long)]
    voucher: PathBuf,

    #[arg(long)]
    output: PathBuf,
}

impl Extend {
    #[instrument(skip_all)]
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let Self {
            in_format,
            alg,
            current_ow_priv,
            next_ow_cert,
            voucher,
            output,
        } = self;

        let voucher = tokio::fs::read_to_string(&voucher)
            .await
            .wrap_err("couldn't read ownership voucher")?;
        let current_ow_priv = tokio::fs::read(&current_ow_priv)
            .await
            .wrap_err("couldn't read current owner key")?;
        let next_ow_cert = tokio::fs::read(&next_ow_cert)
            .await
            .wrap_err("couldn't read next owner cert")?;

        let mut voucher = parse_voucher(&voucher)?;

        let current_owner_priv = PrivateKey::read(in_format, alg, &current_ow_priv)?;
        let next_ow_cert = cert_pem_to_der(&next_ow_cert)?;
        let next_ow_cert = PublicKey::from_cert_der(alg, &next_ow_cert)?;

        let mut buf: Vec<u8> = Vec::new();
        buf.extend(voucher.ov_header_tag.get_value().ov_guid.as_slice());
        buf.extend(voucher.ov_header_tag.get_value().ov_device_info.as_bytes());

        let ov_e_hash_hdr_info = alg.hash(&buf)?;

        // TODO: owner key should match last signature
        let prev = voucher
            .ov_entry_array
            .last()
            .ok_or_eyre("empty voucher entries")?;
        buf.clear();
        ciborium::into_writer(prev, &mut buf)?;

        let ov_e_hash_prev_entry = alg.hash(&buf)?;

        let next_entry_payload = OvEntryPayload {
            ov_e_hash_prev_entry,
            ov_e_hash_hdr_info,
            ov_e_extra: None,
            ov_e_pubkey: next_ow_cert.to_pub_key(alg),
        };

        buf.clear();
        ciborium::into_writer(&next_entry_payload, &mut buf)?;

        let sign = current_owner_priv.cose_sign(alg, buf.clone())?;

        let next_entry = OvEntry::new(sign);

        voucher.ov_entry_array.push(next_entry);

        buf.clear();
        ciborium::into_writer(&voucher, &mut buf)?;

        let voucher = BASE64.encode(&buf);

        let output = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)
            .await
            .wrap_err("output file already exists")?;

        let mut output = BufWriter::new(output);
        output.write_all(PREFIX.as_bytes()).await?;
        output.write_all(b"\n").await?;

        // Base64 safe to use bytes
        for line in voucher.as_bytes().chunks(64) {
            output.write_all(line).await?;
            output.write_all(b"\n").await?;
        }
        output.write_all(SUFFIX.as_bytes()).await?;
        output.write_all(b"\n").await?;

        output.flush().await?;

        info!("ownership voucher extended");

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum KeyFormat {
    Pem,
    Der,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum Alg {
    Rsa2048,
    Rsa3072,
    Secp256r1,
    Secp384r1,
}

impl Alg {
    fn hash(&self, data: &[u8]) -> eyre::Result<Hash<'static>> {
        match self {
            Alg::Rsa2048 | Alg::Secp256r1 => {
                let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data);

                Hash::with_sha256(Cow::Owned(ByteBuf::from(hash.as_ref())))
                    .ok_or_eyre("couldn't hash")
            }
            Alg::Rsa3072 | Alg::Secp384r1 => {
                let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA384, data);

                Hash::with_sha384(Cow::Owned(ByteBuf::from(hash.as_ref())))
                    .ok_or_eyre("couldn't hash")
            }
        }
    }
}

impl Display for Alg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Alg::Rsa2048 => write!(f, "RSA2048"),
            Alg::Rsa3072 => write!(f, "RSA3072"),
            Alg::Secp256r1 => write!(f, "SECP256R1"),
            Alg::Secp384r1 => write!(f, "SECP384R1"),
        }
    }
}

impl From<Alg> for PkType {
    fn from(value: Alg) -> Self {
        match value {
            Alg::Rsa2048 => PkType::Rsa2048Restr,
            Alg::Rsa3072 => PkType::RsaPkcs,
            Alg::Secp256r1 => PkType::Secp256R1,
            Alg::Secp384r1 => PkType::Secp384R1,
        }
    }
}

impl From<Alg> for coset::iana::Algorithm {
    fn from(value: Alg) -> Self {
        match value {
            Alg::Rsa2048 => coset::iana::Algorithm::RS256,
            Alg::Rsa3072 => coset::iana::Algorithm::RS384,
            Alg::Secp256r1 => coset::iana::Algorithm::ES256,
            Alg::Secp384r1 => coset::iana::Algorithm::ES384,
        }
    }
}

enum PrivateKey {
    Rsa(aws_lc_rs::signature::RsaKeyPair),
    Ecdsa(aws_lc_rs::signature::EcdsaKeyPair),
}

impl PrivateKey {
    #[instrument(skip(buf, alg))]
    fn read(format: KeyFormat, alg: Alg, buf: &[u8]) -> eyre::Result<Self> {
        match format {
            KeyFormat::Pem => Self::from_pem(alg, buf),
            KeyFormat::Der => Self::from_der(alg, buf),
        }
    }

    #[instrument(skip_all)]
    fn from_pem(alg: Alg, mut pem: &[u8]) -> eyre::Result<Self> {
        let (kind, der) = rustls_pki_types::pem::from_buf(&mut pem)
            .wrap_err("couldn't parse private key")?
            .ok_or_eyre("empty pem file")?;

        match (kind, alg) {
            (SectionKind::RsaPrivateKey | SectionKind::PrivateKey, Alg::Rsa2048) => {
                Self::from_der(alg, &der)
            }
            (SectionKind::EcPrivateKey | SectionKind::PrivateKey, Alg::Secp256r1) => {
                Self::from_der(alg, &der)
            }
            (SectionKind::EcPrivateKey | SectionKind::PrivateKey, Alg::Secp384r1) => {
                Self::from_der(alg, &der)
            }
            _ => Err(eyre!(
                "invalid algorithm, expected {alg} private key but pem file is {kind:?}"
            )),
        }
    }

    #[instrument(skip(der))]
    fn from_der(alg: Alg, der: &[u8]) -> eyre::Result<Self> {
        match alg {
            Alg::Rsa2048 | Alg::Rsa3072 => aws_lc_rs::signature::RsaKeyPair::from_der(der)
                .map(PrivateKey::Rsa)
                .wrap_err("couldn't decode RSA2048 rivate key"),
            Alg::Secp256r1 => aws_lc_rs::signature::EcdsaKeyPair::from_private_key_der(
                &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                der,
            )
            .map(PrivateKey::Ecdsa)
            .wrap_err("couldn't decode SECP256R1 private key"),
            Alg::Secp384r1 => aws_lc_rs::signature::EcdsaKeyPair::from_private_key_der(
                &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                der,
            )
            .map(PrivateKey::Ecdsa)
            .wrap_err("couldn't decode SECP256R1 private key"),
        }
    }

    fn sign(&self, alg: Alg, payload: &[u8]) -> eyre::Result<Vec<u8>> {
        match (self, alg) {
            (PrivateKey::Rsa(key_pair), Alg::Rsa2048) => {
                let mut signature = vec![0; key_pair.public_modulus_len()];

                key_pair.sign(
                    &aws_lc_rs::signature::RSA_PKCS1_SHA256,
                    &SystemRandom::new(),
                    payload,
                    &mut signature,
                )?;

                Ok(signature)
            }
            (PrivateKey::Rsa(key_pair), Alg::Rsa3072) => {
                let mut signature = vec![0; key_pair.public_modulus_len()];

                key_pair.sign(
                    &aws_lc_rs::signature::RSA_PKCS1_SHA384,
                    &SystemRandom::new(),
                    payload,
                    &mut signature,
                )?;

                Ok(signature)
            }

            (PrivateKey::Ecdsa(ecdsa_key_pair), Alg::Secp256r1 | Alg::Secp384r1) => {
                let signature = ecdsa_key_pair.sign(&SystemRandom::new(), payload)?;

                Ok(signature.as_ref().to_vec())
            }
            _ => Err(eyre!("invalid alg for pub key")),
        }
    }

    fn cose_sign(&self, alg: Alg, payload: Vec<u8>) -> eyre::Result<CoseSign1> {
        let protected = HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::ES256)
            .build();

        let unprotected = HeaderBuilder::new().build();

        let eat = CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(payload)
            .try_create_signature(&[], |bytes| self.sign(alg, bytes))?
            .build();

        Ok(eat)
    }
}

struct PublicKey<'a> {
    cert: X509<'a>,
    _inner: ParsedPublicKey,
}

impl<'a> PublicKey<'a> {
    #[instrument(skip(cert))]
    fn from_cert_der(alg: Alg, cert: &'a [u8]) -> eyre::Result<Self> {
        let cert = X509::parse(cert).wrap_err("couldn't parse certificate")?;

        let inner = match alg {
            Alg::Rsa2048 | Alg::Rsa3072 => ParsedPublicKey::new(
                &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256,
                cert.key(),
            )
            .wrap_err("couldn't parse RSA2048 key")?,
            Alg::Secp256r1 => {
                ParsedPublicKey::new(&aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED, cert.key())
                    .wrap_err("couldn't parse SECP256R1 key")?
            }
            Alg::Secp384r1 => {
                ParsedPublicKey::new(&aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED, cert.key())
                    .wrap_err("couldn't parse SECP384R1 key")?
            }
        };

        Ok(Self {
            _inner: inner,
            cert,
        })
    }

    fn to_pub_key(&self, alg: Alg) -> astarte_fdo_protocol::v101::public_key::PublicKey<'_> {
        astarte_fdo_protocol::v101::public_key::PublicKey::with_x509_pub_key(
            PkType::from(alg),
            Cow::Owned(ByteBuf::from(self.cert.key())),
        )
    }
}

// TODO: oid can be validated
fn cert_pem_to_der(mut cert: &[u8]) -> eyre::Result<Vec<u8>> {
    let (kind, der) = rustls_pki_types::pem::from_buf(&mut cert)
        .wrap_err("couldn't parse certificate")?
        .ok_or_eyre("empty pem file")?;

    match kind {
        SectionKind::Certificate => Ok(der),

        _ => Err(eyre!(
            "invalid algorithm, expected a certificate but pem file is {kind:?}"
        )),
    }
}
