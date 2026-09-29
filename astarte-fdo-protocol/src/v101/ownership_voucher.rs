// This file is part of Astarte.
//
// Copyright 2025, 2026 SECO Mind Srl
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

//! The Ownership Voucher is a structured digital document that links the Manufacturer with the
//! Owner.
//!
//! It is formed as a chain of signed public keys, each signature of a public key authorizing the
//! possessor of the corresponding private key to take ownership of the Device or pass ownership
//! through another link in the chain.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Display;

use coset::{AsCborValue, CoseSign1};
use serde::{Deserialize, Serialize};
use serde_bytes::Bytes;

use crate::Error;
use crate::error::ErrorKind;
use crate::utils::{CborBstr, DisplayDebug, DisplaySlice, Hex};

use super::hash_hmac::{HMac, Hash};
use super::public_key::PublicKey;
use super::rendezvous_info::RendezvousInfo;
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
pub struct OwnershipVoucher<'a> {
    /// Protocol version
    ///
    /// Must match the `OVHeader.OVHProtVer`.
    pub ov_prot_ver: Protver,
    /// Ownership voucher header
    pub ov_header_tag: CborBstr<'a, OvHeader<'a>>,
    /// HMac of the Device secret and OVHeader
    pub ov_header_hmac: HMac<'a>,
    /// Hash of the concatenation of the contents of each byte string in "OwnershipVoucher.OVDevCertChain"
    pub ov_dev_cert_chain: OVDevCertChainOrNull<'a>,
    /// Entries in the ownership voucher
    pub ov_entry_array: OvEntries,
}

impl Display for OwnershipVoucher<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            ov_prot_ver,
            ov_header_tag,
            ov_header_hmac,
            ov_dev_cert_chain,
            ov_entry_array,
        } = self;

        let mut d = f.debug_struct("OwnershipVoucher");

        d.field("ov_prot_ver", &DisplayDebug(ov_prot_ver))
            .field("ov_header_tag", &DisplayDebug(ov_header_tag))
            .field("ov_header_hmac", &DisplayDebug(ov_header_hmac));

        if let Some(ov_dev_cert_chain) = ov_dev_cert_chain {
            d.field("ov_dev_cert_chain", &DisplayDebug(ov_dev_cert_chain));
        } else {
            d.field("ov_dev_cert_chain", &None::<CoseX509>);
        }

        d.field("ov_entry_array", &DisplaySlice(ov_entry_array.as_slice()))
            .finish()
    }
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
pub struct OvHeader<'a> {
    /// Protocol version
    pub ovh_prot_ver: Protver,
    /// Device GUID
    pub ov_guid: Guid,
    /// RendezvousInfo for the RVServer
    pub ov_rv_info: RendezvousInfo<'a>,
    /// Device info
    pub ov_device_info: Cow<'a, str>,
    /// Manufacturing public key
    pub ov_pub_key: PublicKey<'a>,
    /// Device certificate chain
    pub ov_dev_cert_chain_hash: OvDevCertChainHashOrNull<'a>,
}

impl Display for OvHeader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            ovh_prot_ver,
            ov_guid,
            ov_rv_info,
            ov_device_info,
            ov_pub_key,
            ov_dev_cert_chain_hash,
        } = self;

        let mut d = f.debug_struct("OvHeader");
        d.field("ovh_prot_ver", &DisplayDebug(ovh_prot_ver))
            .field("ov_guid", &DisplayDebug(ov_guid))
            .field("ov_rv_info", &DisplayDebug(ov_rv_info))
            .field("ov_device_info", &DisplayDebug(ov_device_info))
            .field("ov_pub_key", &DisplayDebug(ov_pub_key));

        if let Some(ov_dev_cert_chain_hash) = ov_dev_cert_chain_hash {
            d.field(
                "ov_dev_cert_chain_hash",
                &DisplayDebug(ov_dev_cert_chain_hash),
            );
        } else {
            d.field("ov_dev_cert_chain_hash", &None::<Hash>);
        }

        d.finish()
    }
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
pub type OvDevCertChainHashOrNull<'a> = Option<Hash<'a>>;

/// ```cddl
/// ;; Device certificate chain
/// ;; use null for Intel® EPID.
/// OVDevCertChainOrNull     = X5CHAIN / null  ;; CBOR null for Intel® EPID device key
/// ```
pub type OVDevCertChainOrNull<'a> = Option<CoseX509<'a>>;

/// ```cddl
/// ;; Ownership voucher entries array
/// OVEntries = [ * OVEntry ]
/// ```
pub type OvEntries = Vec<OvEntry>;

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
pub struct OvEntry {
    pub(crate) entry: CoseSign1,
}

const SIGN_TAG: u64 = coset::iana::CborTag::CoseSign1 as u64;

impl OvEntry {
    /// Create a new entry.
    pub fn new(entry: CoseSign1) -> Self {
        Self { entry }
    }

    /// Returns the Cose sign
    pub fn sign(&self) -> &CoseSign1 {
        &self.entry
    }

    /// Return the [CoseSign1] payload decode for this entry.
    pub fn try_payload(&self) -> Result<OvEntryPayload<'static>, Error> {
        let payload = self
            .entry
            .payload
            .as_deref()
            .ok_or(Error::new(ErrorKind::Invalid, "OVEntry payload is missing"))?;

        let value: OvEntryPayload<'static> = ciborium::from_reader(payload).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't decode OvEntryPayload");

            Error::new(ErrorKind::Decode, "the OVEntry payload")
        })?;

        Ok(value)
    }

    /// Return the [CoseSign1] payload decode for this entry.
    #[deprecated(since = "1.1.0", note = "use try_payload")]
    pub fn payload(self) -> Result<(Vec<u8>, OvEntryPayload<'static>), Error> {
        let payload = self
            .entry
            .payload
            .ok_or(Error::new(ErrorKind::Invalid, "OVEntry payload is missing"))?;

        let value: OvEntryPayload<'static> =
            ciborium::from_reader(payload.as_slice()).map_err(|err| {
                #[cfg(feature = "tracing")]
                tracing::error!(error = %err, "couldn't decode OvEntryPayload");

                Error::new(ErrorKind::Decode, "the OVEntry payload")
            })?;

        Ok((payload, value))
    }
}

impl Display for OvEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("OvEntry");

        d.field("protected", &self.entry.protected.header)
            .field("unprotected", &self.entry.unprotected);

        match self.clone().try_payload() {
            Ok(payload) => {
                d.field("payload", &DisplayDebug(payload));
            }
            Err(_) => {
                d.field("payload", &"Invalid");
            }
        }

        d.field("signature", &Hex::new(&self.entry.signature))
            .finish_non_exhaustive()
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
pub struct OvEntryPayload<'a> {
    /// Hash of the previous entry
    pub ov_e_hash_prev_entry: Hash<'a>,
    /// Hash of the GUID and Device Info in the header
    pub ov_e_hash_hdr_info: Hash<'a>,
    /// Extra data for the entry
    pub ov_e_extra: Option<CborBstr<'a, OvExtraInfo<'a>>>,
    /// Entry owner public key
    pub ov_e_pubkey: PublicKey<'a>,
}

impl<'a> OvEntryPayload<'a> {
    /// Returns the previous entry hash
    pub fn prev(&self) -> &Hash<'a> {
        &self.ov_e_hash_prev_entry
    }

    /// Returns the hrd entry hash.
    ///
    /// hash[GUID||DeviceInfo] in header
    pub fn hdr(&self) -> &Hash<'a> {
        &self.ov_e_hash_hdr_info
    }

    /// Returns the ov entry public key
    pub fn take_pubkey(self) -> PublicKey<'a> {
        self.ov_e_pubkey
    }
}

impl<'a> Display for OvEntryPayload<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            ov_e_hash_prev_entry,
            ov_e_hash_hdr_info,
            ov_e_extra,
            ov_e_pubkey,
        } = self;

        let mut d = f.debug_struct("OvEntryPayload");
        d.field("ov_e_hash_prev_entry", &DisplayDebug(ov_e_hash_prev_entry))
            .field("ov_e_hash_hdr_info", &DisplayDebug(ov_e_hash_hdr_info));

        if let Some(ov_e_extra) = ov_e_extra {
            d.field("ov_e_extra", ov_e_extra.get_value());
        } else {
            d.field("ov_e_extra", &None::<HashMap<i64, Cow<Bytes>>>);
        }

        d.field("ov_e_pubkey", &DisplayDebug(ov_e_pubkey)).finish()
    }
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

/// ```cddl
/// OVEExtraInfo = { * OVEExtraInfoType: bstr }
/// OVEExtraInfoType = int
///
/// ;;OVSignType = Supporting COSE signature type
/// ```
pub type OvExtraInfo<'a> = rustc_hash::FxHashMap<i64, Cow<'a, Bytes>>;

#[cfg(test)]
pub(crate) mod tests {
    use coset::{CoseSign1Builder, HeaderBuilder};
    use pretty_assertions::assert_eq;

    use crate::tests::insta_settings;
    use crate::v101::PROTOCOL_VERSION;
    use crate::v101::hash_hmac::tests::{create_hash, create_hmac};
    use crate::v101::public_key::tests::PUB_KEY_ECC;
    use crate::v101::public_key::{PkBody, PkEnc, PkType};
    use crate::v101::rendezvous_info::tests::create_rv_info;
    use crate::v101::tests::{create_guid, from_hex};
    use crate::v101::x509::tests::create_cose_x509;

    use super::*;

    pub(crate) const ECC_SIGNATURE: &[u8] =
        include_bytes!("../../../assets/examples/ov-entry-sign.der");

    pub(crate) fn create_ov_header() -> OvHeader<'static> {
        OvHeader {
            ovh_prot_ver: PROTOCOL_VERSION,
            ov_guid: create_guid(),
            ov_rv_info: create_rv_info(),
            ov_device_info: "fdo-astarte".into(),
            ov_pub_key: PublicKey {
                pk_type: PkType::Secp256R1,
                pk_enc: PkEnc::X509,
                pk_body: PkBody::X509(Cow::Borrowed(PUB_KEY_ECC.into())),
            },
            ov_dev_cert_chain_hash: Some(create_hash()),
        }
    }

    pub(crate) fn create_ov_entry(payload: &OvEntryPayload) -> OvEntry {
        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf).unwrap();

        let entry = CoseSign1Builder::new()
            .protected(
                HeaderBuilder::new()
                    .algorithm(coset::iana::Algorithm::PS256)
                    .build(),
            )
            .payload(buf)
            .signature(ECC_SIGNATURE.to_vec())
            .build();

        OvEntry { entry }
    }

    pub(crate) fn create_ov_entry_payload() -> OvEntryPayload<'static> {
        OvEntryPayload {
            ov_e_hash_prev_entry: Hash::with_sha256(Cow::Owned(
                from_hex("9be58b34344cfaab4b798288b7adedbbe451a2cf7cacf9b0d2aecef26cc0e1d1").into(),
            ))
            .unwrap(),
            ov_e_hash_hdr_info: Hash::with_sha256(Cow::Owned(
                from_hex("3443c6b88aeb31f50eceb9d8acf0591fb757dcf6e50b23b75d0fb9c00fba2d65").into(),
            ))
            .unwrap(),
            ov_e_extra: Some(CborBstr::new(Default::default())),
            ov_e_pubkey: PublicKey {
                pk_type: PkType::Secp256R1,
                pk_enc: PkEnc::X509,
                pk_body: PkBody::X509(Cow::Borrowed(PUB_KEY_ECC.into())),
            },
        }
    }

    #[test]
    fn ownership_voucher_roundtrip() {
        let case = OwnershipVoucher {
            ov_prot_ver: PROTOCOL_VERSION,
            ov_header_tag: CborBstr::new(create_ov_header()),
            ov_header_hmac: create_hmac(),
            ov_dev_cert_chain: Some(create_cose_x509()),
            ov_entry_array: vec![create_ov_entry(&create_ov_entry_payload())],
        };

        let mut buf = Vec::new();
        ciborium::into_writer(&case, &mut buf).unwrap();

        let mut res: OwnershipVoucher = ciborium::from_reader(buf.as_slice()).unwrap();

        // For the diff
        res.ov_entry_array[0].entry.protected.original_data = None;

        assert_eq!(res, case);

        insta_settings!({
            insta::assert_binary_snapshot!(".cbor", buf);
        });
    }

    #[test]
    fn ov_header_roundtrip() {
        let case = create_ov_header();

        let mut buf = Vec::new();
        ciborium::into_writer(&case, &mut buf).unwrap();

        let res: OvHeader = ciborium::from_reader(buf.as_slice()).unwrap();

        assert_eq!(res, case);

        insta_settings!({
            insta::assert_binary_snapshot!(".cbor", buf);
        });
    }

    #[test]
    fn ov_entry_roundtrip() {
        let payload = create_ov_entry_payload();
        let case = create_ov_entry(&payload);

        let mut buf = Vec::new();
        ciborium::into_writer(&case, &mut buf).unwrap();

        let mut res: OvEntry = ciborium::from_reader(buf.as_slice()).unwrap();

        // For the diff
        res.entry.protected.original_data = None;

        assert_eq!(res, case);

        insta_settings!({
            insta::assert_binary_snapshot!(".cbor", buf);
        });
    }

    #[test]
    fn ov_entry_payload() {
        let payload = create_ov_entry_payload();
        let case = create_ov_entry(&payload);

        let value = case.try_payload().unwrap();

        assert_eq!(value, payload);
    }

    #[test]
    fn ov_entry_sign() {
        let payload = create_ov_entry_payload();
        let case = create_ov_entry(&payload);

        let value = case.sign();

        assert_eq!(*value, case.entry);
    }

    #[test]
    fn ov_entry_payload_roundtrip() {
        let case = create_ov_entry_payload();

        let mut buf = Vec::new();
        ciborium::into_writer(&case, &mut buf).unwrap();

        let res: OvEntryPayload = ciborium::from_reader(buf.as_slice()).unwrap();

        assert_eq!(res, case);

        insta_settings!({
            insta::assert_binary_snapshot!(".cbor", buf);
        });
    }

    #[test]
    fn ov_entry_payload_getters() {
        let case = create_ov_entry_payload();

        assert_eq!(*case.prev(), case.ov_e_hash_prev_entry);
        assert_eq!(*case.hdr(), case.ov_e_hash_hdr_info);
        assert_eq!(case.clone().take_pubkey(), case.ov_e_pubkey);
    }
}
