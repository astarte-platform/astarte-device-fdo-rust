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

use coset::iana::{EnumI64, HeaderParameter};
use coset::{CoseSign1, Label, TaggedCborSerializable};
use eyre::{ensure, Context, OptionExt};
use serde::{Deserialize, Serialize};

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
#[derive(Debug)]
pub(crate) struct ProveOvHdr {
    pub(crate) sign: CoseSign1,
}

impl ProveOvHdr {
    pub(crate) fn payload(&self) -> eyre::Result<PvOvHdrPayload<'static>> {
        let payload = self
            .sign
            .payload
            .as_deref()
            .ok_or_eyre("missing cose payload")?;

        ciborium::from_reader(payload).wrap_err("couldn't decode prove owner header payload")
    }

    pub(crate) fn header(&self) -> eyre::Result<PvOvHdrUnprotected<'static>> {
        let pubkey_param = Label::Int(HeaderParameter::CuphOwnerPubKey.to_i64());

        let payload = self
            .sign
            .unprotected
            .rest
            .iter()
            .find_map(|(label, value)| (*label == pubkey_param).then_some(value))
            .ok_or_eyre("missing owner public key")?;

        let pubkey = payload
            .deserialized()
            .wrap_err("couldn't decode header owner public key")?;

        let nonce_param = Label::Int(HeaderParameter::CuphNonce.to_i64());

        let payload = self
            .sign
            .unprotected
            .rest
            .iter()
            .find_map(|(label, value)| (*label == nonce_param).then_some(value))
            .ok_or_eyre("missing owner public key")?;

        let nonce = payload
            .deserialized()
            .wrap_err("couldn't decode header nonce")?;

        Ok(PvOvHdrUnprotected {
            cuph_nonce: nonce,
            cuph_owner_pubkey: pubkey,
        })
    }
}

impl Message for ProveOvHdr {
    const MSG_TYPE: Msgtype = 61;

    fn decode(buf: &[u8]) -> eyre::Result<Self> {
        let sign = CoseSign1::from_tagged_slice(buf)?;

        ensure!(sign.payload.is_some(), "missing payload");

        Ok(Self { sign })
    }

    fn encode(&self) -> eyre::Result<Vec<u8>> {
        let buf = self.sign.clone().to_tagged_vec()?;

        Ok(buf)
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
