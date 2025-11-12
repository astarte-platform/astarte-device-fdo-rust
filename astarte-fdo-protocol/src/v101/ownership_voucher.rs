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

use std::borrow::Cow;

use coset::{AsCborValue, CoseSign1};
use eyre::{Context, OptionExt};
use serde::{Deserialize, Serialize};
use serde_bytes::Bytes;

use crate::utils::CborBstr;

use super::hash_hmac::{HMac, Hash};
use super::public_key::PublicKey;
use super::randezvous_info::RendezvousInfo;
use super::x509::CoseX509;
use super::{Guid, Protver};

/// Ownership Voucher top level structure
///
/// ```cddl
/// OwnershipVoucher = [
///     OVProtVer:      protver,           ;; protocol version
///     OVHeaderTag:    bstr .cbor OVHeader,
///     OVHeaderHMac:   HMac,              ;; hmac[DCHmacSecret, OVHeader]
///     OVDevCertChain: OVDevCertChainOrNull,
///     OVEntryArray:   OVEntries
/// ]
/// ```
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct OwnershipVoucher<'a> {
    ov_prot_ver: Protver,
    ov_header_tag: CborBstr<'a, OvHeader<'a>>,
    ov_header_hmac: HMac<'a>,
    ov_dev_cert_chain: OVDevCertChainOrNull<'a>,
    ov_entry_array: OvEntries,
}

impl Serialize for OwnershipVoucher<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            ov_prot_ver,
            ov_header_tag,
            ov_header_hmac,
            ov_dev_cert_chain,
            ov_entry_array,
        } = self;

        (
            ov_prot_ver,
            ov_header_tag,
            ov_header_hmac,
            ov_dev_cert_chain,
            ov_entry_array,
        )
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OwnershipVoucher<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (ov_prot_ver, ov_header_tag, ov_header_hmac, ov_dev_cert_chain, ov_entry_array) =
            Deserialize::deserialize(deserializer)?;

        Ok(Self {
            ov_prot_ver,
            ov_header_tag,
            ov_header_hmac,
            ov_dev_cert_chain,
            ov_entry_array,
        })
    }
}

/// ;; Ownership Voucher header, also used in TO1 protocol
/// OVHeader = [
///     OVHProtVer:        protver,        ;; protocol version
///     OVGuid:            Guid,           ;; guid
///     OVRVInfo:          RendezvousInfo, ;; rendezvous instructions
///     OVDeviceInfo:      tstr,           ;; DeviceInfo
///     OVPubKey:          PublicKey,      ;; mfg public key
///     OVDevCertChainHash:OVDevCertChainHashOrNull
/// ]
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct OvHeader<'a> {
    pub(crate) ovh_prot_ver: Protver,
    pub(crate) ov_guid: Guid,
    pub(crate) ov_rv_info: RendezvousInfo<'a>,
    pub(crate) ov_device_info: Cow<'a, str>,
    pub(crate) ov_pub_key: PublicKey<'a>,
    pub(crate) ov_dev_cert_chain_hash: OvDevCertChainHashOrNull<'a>,
}

impl Serialize for OvHeader<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            ovh_prot_ver,
            ov_guid,
            ov_rv_info,
            ov_device_info,
            ov_pub_key,
            ov_dev_cert_chain_hash,
        } = self;

        (
            ovh_prot_ver,
            ov_guid,
            ov_rv_info,
            ov_device_info,
            ov_pub_key,
            ov_dev_cert_chain_hash,
        )
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OvHeader<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (ovh_prot_ver, ov_guid, ov_rv_info, ov_device_info, ov_pub_key, ov_dev_cert_chain_hash) =
            Deserialize::deserialize(deserializer)?;

        Ok(Self {
            ovh_prot_ver,
            ov_guid,
            ov_rv_info,
            ov_device_info,
            ov_pub_key,
            ov_dev_cert_chain_hash,
        })
    }
}

/// ```cddl
/// ;; Hash of Device certificate chain
/// ;; use null for Intel® EPID
/// OVDevCertChainHashOrNull = Hash / null       ;; CBOR null for Intel® EPID device key
/// ```
pub(crate) type OvDevCertChainHashOrNull<'a> = Option<Hash<'a>>;

/// ``cddl
/// ;; Device certificate chain
/// ;; use null for Intel® EPID.
/// OVDevCertChainOrNull     = X5CHAIN / null  ;; CBOR null for Intel® EPID device key
/// ```
pub(crate) type OVDevCertChainOrNull<'a> = Option<CoseX509<'a>>;

/// ```cddl
/// ;; Ownership voucher entries array
/// OVEntries = [ * OVEntry ]
/// ```
pub(crate) type OvEntries = Vec<OvEntry>;

/// ```cddl
/// ;; ...each entry is a COSE Sign1 object with a payload
/// OVEntry = CoseSignature
/// $COSEProtectedHeaders //= (
///     1: OVSignType
/// )
/// $COSEPayloads /= (
///    OVEntryPayload
///)
/// ```
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct OvEntry {
    pub(crate) entry: CoseSign1,
}

const SIGN_TAG: u64 = coset::iana::CborTag::CoseSign1 as u64;

impl OvEntry {
    pub(crate) fn payload(self) -> eyre::Result<(Vec<u8>, OvEntryPayload<'static>)> {
        let payload = self
            .entry
            .payload
            .ok_or_eyre("ov entry payload is missing")?;

        let value: OvEntryPayload<'static> =
            ciborium::from_reader(payload.as_slice()).wrap_err("coudldn't decode payload")?;

        Ok((payload, value))
    }
}

impl Serialize for OvEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let value = self
            .entry
            .clone()
            .to_cbor_value()
            .map_err(serde::ser::Error::custom)?;

        ciborium::tag::Required::<_, SIGN_TAG>(value).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OvEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value =
            ciborium::tag::Accepted::<ciborium::Value, SIGN_TAG>::deserialize(deserializer)?;

        CoseSign1::from_cbor_value(value.0)
            .map(|entry| Self { entry })
            .map_err(serde::de::Error::custom)
    }
}

/// ```cddl
/// ;; ... each payload contains the hash of the previous entry
/// ;; and the signature of the public key to verify the next signature
/// ;; (or the Owner, in the last entry).
/// OVEntryPayload = [
///     OVEHashPrevEntry: Hash,
///     OVEHashHdrInfo:   Hash,  ;; hash[GUID||DeviceInfo] in header
///     OVEExtra:         null / bstr .cbor OVEExtraInfo
///     OVEPubKey:        PublicKey
/// ]
/// ```
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct OvEntryPayload<'a> {
    pub(crate) ov_e_hash_prev_entry: Hash<'a>,
    pub(crate) ov_e_hash_hdr_info: Hash<'a>,
    pub(crate) ov_e_extra: Option<CborBstr<'a, OvExtraInfo<'a>>>,
    pub(crate) ov_e_pubkey: PublicKey<'a>,
}

impl Serialize for OvEntryPayload<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            ov_e_hash_prev_entry,
            ov_e_hash_hdr_info,
            ov_e_extra,
            ov_e_pubkey,
        } = self;

        (
            ov_e_hash_prev_entry,
            ov_e_hash_hdr_info,
            ov_e_extra,
            ov_e_pubkey,
        )
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OvEntryPayload<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (ov_e_hash_prev_entry, ov_e_hash_hdr_info, ov_e_extra, ov_e_pubkey) =
            Deserialize::deserialize(deserializer)?;

        Ok(Self {
            ov_e_hash_prev_entry,
            ov_e_hash_hdr_info,
            ov_e_extra,
            ov_e_pubkey,
        })
    }
}

// OVEExtraInfo = { * OVEExtraInfoType: bstr }
// OVEExtraInfoType = int
//
// ;;OVSignType = Supporting COSE signature type
type OvExtraInfo<'a> = rustc_hash::FxHashMap<i64, Cow<'a, Bytes>>;
