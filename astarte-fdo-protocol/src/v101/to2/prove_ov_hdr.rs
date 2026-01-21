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

//! Prove Ownership Voucher Header, Type 61
//!
//! From Owner Onboarding Service to Device:
//!
//! Message Format:
//!
//! ```cddl
//! TO2.ProveOVHdr = CoseSignature
//! TO2ProveOVHdrPayload = [
//!     bstr .cbor OVHeader,     ;; Ownership Voucher header
//!     NumOVEntries, ;; number of ownership voucher entries
//!     HMac,         ;; Ownership Voucher "hmac" of hdr
//!     NonceTO2ProveOV, ;; nonce from TO2.HelloDevice
//!     eBSigInfo,    ;; Device attestation signature info
//!     xAKeyExchange,;; Key exchange first step
//!     helloDeviceHash: Hash, ;; hash of HelloDevice message
//!     maxOwnerMessageSize
//! ]
//! NumOVEntries = uint8
//! TO2ProveOVHdrUnprotectedHeaders = (
//!     CUPHNonce:       NonceTO2ProveDv, ;; nonce is used below in TO2.ProveDevice and TO2.Done
//!     CUPHOwnerPubKey: PublicKey ;; Owner key, as convenience to Device
//! )
//! $COSEPayloads /= (
//!     TO2ProveOVHdrPayload
//! )
//! $$COSEUnprotectedHeaders /= (
//!     TO2ProveOVHdrUnprotectedHeaders
//! )
//!
//! maxOwnerMessageSize = uint16
//! ```
//!
//! This message serves several purposes:
//!
//! - The Owner begins sending the Ownership Voucher to the device (only the header is in this
//!   message).
//! - The Owner signs the message with the Owner key (the last key in the Ownership Voucher),
//!   allowing the Device to verify (later on) that the Owner controls this private key.
//! - The Owner starts the key exchange protocol by sending the initial key exchange parameter
//!   xAKeyExchange (e.g., in Diffie Hellman, the parameter ‘A’) to the Device.

use std::io::Write;

use coset::iana::{EnumI64, HeaderParameter};
use coset::{CoseSign1, Label, TaggedCborSerializable};
use serde::{Deserialize, Serialize};

use crate::Error;
use crate::error::ErrorKind;
use crate::utils::CborBstr;
use crate::v101::hash_hmac::{HMac, Hash};
use crate::v101::key_exchange::XAKeyExchange;
use crate::v101::ownership_voucher::OvHeader;
use crate::v101::public_key::PublicKey;
use crate::v101::sign_info::EBSigInfo;
use crate::v101::{Message, Msgtype, NonceTo2ProveDv, NonceTo2ProveOv};

/// ```cddl
/// TO2.ProveOVHdr = CoseSignature
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct ProveOvHdr {
    pub(crate) sign: CoseSign1,
}

impl ProveOvHdr {
    /// Returns the singed Cose
    pub fn sign(&self) -> &CoseSign1 {
        &self.sign
    }

    /// Returns the decoded Cose payload
    pub fn payload(&self) -> Result<PvOvHdrPayload<'static>, Error> {
        let payload = self.sign.payload.as_deref().ok_or(Error::new(
            ErrorKind::Invalid,
            "the TO2.ProveOvHdr payload is missing",
        ))?;

        ciborium::from_reader(payload).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't decode TO2.ProveOvHdr payload");

            Error::new(ErrorKind::Decode, "the TO2.ProveOvHdr payload")
        })
    }

    /// Returns the decoded Cose header
    pub fn header(&self) -> Result<PvOvHdrUnprotected<'static>, Error> {
        let pubkey_param = Label::Int(HeaderParameter::CuphOwnerPubKey.to_i64());

        let pubkey = self
            .sign
            .unprotected
            .rest
            .iter()
            .find_map(|(label, value)| (*label == pubkey_param).then_some(value))
            .ok_or(Error::new(
                ErrorKind::Invalid,
                "the TO2.ProveOvHdr owner public key is missing",
            ))?;

        let pubkey = pubkey.deserialized().map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't decode TO2.ProveOvHdr owner public key header ");

            Error::new(
                ErrorKind::Decode,
                "the TO2.ProveOvHdr header owner public key",
            )
        })?;

        let nonce_param = Label::Int(HeaderParameter::CuphNonce.to_i64());

        let nonce = self
            .sign
            .unprotected
            .rest
            .iter()
            .find_map(|(label, value)| (*label == nonce_param).then_some(value))
            .ok_or(Error::new(
                ErrorKind::Invalid,
                "the TO2.ProveOvHdr nonce is missing",
            ))?;

        let nonce = nonce.deserialized().map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't decode TO2.ProveOvHdr nonce header ");

            Error::new(ErrorKind::Decode, "the TO2.ProveOvHdr nonce header")
        })?;

        Ok(PvOvHdrUnprotected {
            cuph_nonce: nonce,
            cuph_owner_pubkey: pubkey,
        })
    }
}

impl Message for ProveOvHdr {
    const MSG_TYPE: Msgtype = 61;

    fn decode(buf: &[u8]) -> Result<Self, Error> {
        let sign = CoseSign1::from_tagged_slice(buf).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't decode TO2.ProveOvHdr");

            Error::new(ErrorKind::Decode, "the TO2.ProveOvHdr")
        })?;

        if sign.payload.is_none() {
            return Err(Error::new(
                ErrorKind::Invalid,
                "the TO2.ProveOvHdr payload is missing",
            ));
        }

        Ok(Self { sign })
    }

    fn encode<W>(&self, write: &mut W) -> Result<(), Error>
    where
        W: Write,
    {
        self.sign
            .clone()
            .to_tagged_vec()
            .map_err(|err| {
                #[cfg(feature = "tracing")]
                tracing::error!(error = %err, "couldn't encode TO2.ProveOvHdr");

                Error::new(ErrorKind::Encode, "the TO2.ProveOvHdr")
            })
            .and_then(|buf| {
                write.write_all(&buf).map_err(|err| {
                    #[cfg(feature = "tracing")]
                    tracing::error!(error = %err, "couldn't write TO2.ProveOvHdr");

                    Error::new(ErrorKind::Write, "the TO2.ProveOvHdr")
                })
            })
    }
}

/// ```cddl
/// TO2ProveOVHdrPayload = [
///     bstr .cbor OVHeader,     ;; Ownership Voucher header
///     NumOVEntries, ;; number of ownership voucher entries
///     HMac,         ;; Ownership Voucher "hmac" of hdr
///     NonceTO2ProveOV, ;; nonce from TO2.HelloDevice
///     eBSigInfo,    ;; Device attestation signature info
///     xAKeyExchange,;; Key exchange first step
///     helloDeviceHash: Hash, ;; hash of HelloDevice message
///     maxOwnerMessageSize
/// ]
/// NumOVEntries = uint8
/// $COSEPayloads /= (
///     TO2ProveOVHdrPayload
/// )
/// maxOwnerMessageSize = uint16
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct PvOvHdrPayload<'a> {
    /// Ownership Voucher header
    pub ov_header: CborBstr<'a, OvHeader<'a>>,
    /// Number of ownership voucher entries
    pub num_ov_entries: u8,
    /// Ownership Voucher "hmac" of hdr
    pub hmac: HMac<'a>,
    /// nonce from TO2.HelloDevice
    pub nonce_to2_prove_ov: NonceTo2ProveOv,
    /// Device attestation signature info
    pub eb_sign_info: EBSigInfo<'a>,
    /// Key exchange first step
    pub x_a_key_exchange: XAKeyExchange<'a>,
    /// hash of HelloDevice message
    pub hello_device_hash: Hash<'a>,
    /// Max ownership message size
    pub max_owner_message_size: u16,
}

impl Serialize for PvOvHdrPayload<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            ov_header,
            num_ov_entries,
            hmac,
            nonce_to2_prove_ov,
            eb_sign_info,
            x_a_key_exchange,
            hello_device_hash,
            max_owner_message_size,
        } = self;

        (
            ov_header,
            num_ov_entries,
            hmac,
            nonce_to2_prove_ov,
            eb_sign_info,
            x_a_key_exchange,
            hello_device_hash,
            max_owner_message_size,
        )
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PvOvHdrPayload<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (
            ov_header,
            num_ov_entries,
            hmac,
            nonce_to2_prove_ov,
            eb_sign_info,
            x_a_key_exchange,
            hello_device_hash,
            max_owner_message_size,
        ) = Deserialize::deserialize(deserializer)?;

        Ok(Self {
            ov_header,
            num_ov_entries,
            hmac,
            nonce_to2_prove_ov,
            eb_sign_info,
            x_a_key_exchange,
            hello_device_hash,
            max_owner_message_size,
        })
    }
}

/// ```cddl
/// TO2ProveOVHdrUnprotectedHeaders = (
///     CUPHNonce:       NonceTO2ProveDv, ;; nonce is used below in TO2.ProveDevice and TO2.Done
///     CUPHOwnerPubKey: PublicKey ;; Owner key, as convenience to Device
/// )
/// $$COSEUnprotectedHeaders /= (
///     TO2ProveOVHdrUnprotectedHeaders
/// )
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct PvOvHdrUnprotected<'a> {
    pub(crate) cuph_nonce: NonceTo2ProveDv,
    pub(crate) cuph_owner_pubkey: PublicKey<'a>,
}

impl<'a> PvOvHdrUnprotected<'a> {
    /// Public key
    pub fn pubkey(&self) -> &PublicKey<'a> {
        &self.cuph_owner_pubkey
    }

    /// Nonce
    pub fn nonce(&self) -> NonceTo2ProveDv {
        self.cuph_nonce
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use coset::{CoseSign1Builder, HeaderBuilder};
    use pretty_assertions::assert_eq;

    use crate::tests::insta_settings;
    use crate::v101::Nonce;
    use crate::v101::hash_hmac::tests::{create_hash, create_hmac};
    use crate::v101::key_exchange::{EcdhParams, XAKeyExchange, XBKeyExchange};
    use crate::v101::ownership_voucher::tests::{ECC_SIGNATURE, create_ov_header};
    use crate::v101::public_key::tests::{PUB_KEY_ECC, ecc_p256_params};
    use crate::v101::public_key::{PkBody, PkEnc, PkType};
    use crate::v101::sign_info::{DeviceSgType, SigInfo};

    use super::*;

    fn create_prove_ov_hdr(hdr: PvOvHdrUnprotected, payload: PvOvHdrPayload) -> ProveOvHdr {
        let mut buf = Vec::new();

        ciborium::into_writer(&payload, &mut buf).unwrap();

        let unprotected = HeaderBuilder::new()
            .value(
                HeaderParameter::CuphOwnerPubKey.to_i64(),
                ciborium::Value::serialized(&hdr.cuph_owner_pubkey).unwrap(),
            )
            .value(
                HeaderParameter::CuphNonce.to_i64(),
                ciborium::Value::serialized(&hdr.cuph_nonce).unwrap(),
            )
            .build();

        let sign = CoseSign1Builder::new()
            .unprotected(unprotected)
            .protected(
                HeaderBuilder::new()
                    .algorithm(coset::iana::Algorithm::PS256)
                    .build(),
            )
            .payload(buf)
            .signature(ECC_SIGNATURE.to_vec())
            .build();

        ProveOvHdr { sign }
    }

    fn create_pv_ov_hdr_payload() -> PvOvHdrPayload<'static> {
        let (x, y) = ecc_p256_params();

        let params = EcdhParams::with_p256(&x, &y, &[0xde, 0xad, 0xbe, 0xef]);

        let value = XBKeyExchange::create(params).unwrap();
        let value = XAKeyExchange(value.0);

        let nonce = Nonce::from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        PvOvHdrPayload {
            ov_header: CborBstr::new(create_ov_header()),
            num_ov_entries: 2,
            hmac: create_hmac(),
            nonce_to2_prove_ov: NonceTo2ProveOv(nonce),
            eb_sign_info: EBSigInfo(SigInfo::new(DeviceSgType::StSecP256R1)),
            x_a_key_exchange: value,
            hello_device_hash: create_hash(),
            max_owner_message_size: 1400,
        }
    }

    fn create_pv_ov_hdr_unprotected() -> PvOvHdrUnprotected<'static> {
        let nonce = Nonce::from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let pub_k = PublicKey {
            pk_type: PkType::Secp256R1,
            pk_enc: PkEnc::X509,
            pk_body: PkBody::X509(Cow::Borrowed(serde_bytes::Bytes::new(PUB_KEY_ECC))),
        };

        PvOvHdrUnprotected {
            cuph_nonce: NonceTo2ProveDv(nonce),
            cuph_owner_pubkey: pub_k,
        }
    }

    #[test]
    fn prove_ov_hdr_roundtrip() {
        let hdr = create_pv_ov_hdr_unprotected();
        let payload = create_pv_ov_hdr_payload();
        let info = create_prove_ov_hdr(hdr, payload);

        let mut buf = Vec::new();

        info.encode(&mut buf).unwrap();

        let mut res = ProveOvHdr::decode(&buf).unwrap();
        res.sign.protected.original_data.take();

        assert_eq!(res, info);

        insta_settings!({
            insta::assert_binary_snapshot!(".cbor", buf);
        });
    }

    #[test]
    fn prove_ov_hdr_methods() {
        let hdr = create_pv_ov_hdr_unprotected();
        let payload = create_pv_ov_hdr_payload();
        let info = create_prove_ov_hdr(hdr.clone(), payload.clone());

        assert_eq!(*info.sign(), info.sign);

        let res = info.payload().unwrap();

        payload.ov_header.bytes().unwrap();
        assert_eq!(res, payload);

        let res = info.header().unwrap();

        payload.ov_header.bytes().unwrap();
        assert_eq!(res, hdr);
    }

    #[test]
    fn prove_ov_hdr_unprotected_methods() {
        let hdr = create_pv_ov_hdr_unprotected();

        assert_eq!(*hdr.pubkey(), hdr.cuph_owner_pubkey);
        assert_eq!(hdr.nonce(), hdr.cuph_nonce);
    }
}
