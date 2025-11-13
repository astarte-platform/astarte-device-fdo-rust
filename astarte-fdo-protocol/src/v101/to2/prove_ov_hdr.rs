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

use std::io::Write;

use coset::iana::{EnumI64, HeaderParameter};
use coset::{CoseSign1, Label, TaggedCborSerializable};
use serde::{Deserialize, Serialize};

use crate::error::ErrorKind;
use crate::utils::CborBstr;
use crate::v101::hash_hmac::{HMac, Hash};
use crate::v101::key_exchange::XAKeyExchange;
use crate::v101::ownership_voucher::OvHeader;
use crate::v101::public_key::PublicKey;
use crate::v101::sign_info::EBSigInfo;
use crate::v101::{Message, Msgtype, NonceTo2ProveDv, NonceTo2ProveOv};
use crate::Error;

/// ```cddl
/// TO2.ProveOVHdr = CoseSignature
/// ```
#[derive(Debug)]
pub(crate) struct ProveOvHdr {
    pub(crate) sign: CoseSign1,
}

impl ProveOvHdr {
    pub(crate) fn payload(&self) -> Result<PvOvHdrPayload<'static>, Error> {
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

    pub(crate) fn header(&self) -> Result<PvOvHdrUnprotected<'static>, Error> {
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
#[derive(Debug)]
pub(crate) struct PvOvHdrPayload<'a> {
    pub(crate) ov_header: CborBstr<'a, OvHeader<'a>>,
    pub(crate) num_ov_entries: u8,
    pub(crate) hmac: HMac<'a>,
    pub(crate) nonce_to2_prove_ov: NonceTo2ProveOv,
    pub(crate) eb_sign_info: EBSigInfo<'a>,
    pub(crate) x_a_key_exchange: XAKeyExchange<'a>,
    pub(crate) hello_device_hash: Hash<'a>,
    pub(crate) max_owner_message_size: u16,
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
pub(crate) struct PvOvHdrUnprotected<'a> {
    pub(crate) cuph_nonce: NonceTo2ProveDv,
    pub(crate) cuph_owner_pubkey: PublicKey<'a>,
}
