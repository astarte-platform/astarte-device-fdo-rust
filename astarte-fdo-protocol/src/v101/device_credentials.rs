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

//! The Device Credential type indicates those values which must be persisted in the Device (e.g.,
//! during manufacturing) to prepare it for FIDO Device Onboard onboarding.

use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use serde_bytes::Bytes;

use super::hash_hmac::Hash;
use super::rendezvous_info::RendezvousInfo;
use super::{Guid, Protver};

/// Persisted device credentials after DI.
///
/// The stored DCGuid, DCRVInfo and DCPubKeyHash fields are updated during the TO2 protocol. See
/// TO2.SetupDevice for details. These fields must be stored in a non-volatile, mutable storage
/// medium.
///
/// ```cddl
/// DeviceCredential = [
///     DCActive:     bool,
///     DCProtVer:    protver,
///     DCHmacSecret: bstr,           ;; confidentiality required
///     DCDeviceInfo: tstr,
///     DCGuid:       Guid,           ;; modified in TO2
///     DCRVInfo:     RendezvousInfo, ;; modified in TO2
///     DCPubKeyHash: Hash            ;; modified in TO2
/// ]
///
/// ```
// TODO: remove serde
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceCredential<'a> {
    /// Indicates whether FIDO Device Onboard is active.
    ///
    /// When a device is manufactured, this field is initialized to True, indicating that FIDO
    /// Device Onboard must start when the device is powered on. When the TO2 protocol is
    /// successful, this field is set to False, indicating that FIDO Device Onboard should remain
    /// dormant.
    pub dc_active: bool,
    /// Specifies the protocol version.
    pub dc_prot_ver: Protver,
    /// Contains a secret.
    ///
    /// Initialized with a random value by the Device during the DI protocol or equivalent Device
    /// initialization.
    ///
    /// Requires confidentiality.
    pub dc_hmac_secret: Cow<'a, Bytes>,
    /// Device information.
    ///
    /// Is a text string that is used by the manufacturer to indicate the device type, sufficient to
    /// allow an onboarding procedure or script to be selected by the Owner.
    pub dc_device_info: Cow<'a, str>,
    /// Current device’s GUID.
    ///
    /// To be used for the next ownership transfer.
    ///
    /// Modified in TO2
    pub dc_guid: Guid,
    /// Contains instructions on how to find the Secure Device Onboard Rendezvous Server.
    ///
    /// Modified in TO2
    pub dc_rv_info: RendezvousInfo<'a>,
    /// Is a hash of the manufacturer’s public key, which must match the hash of OwnershipVoucher.OVHeader.OVPubKey
    ///
    /// Modified in TO2
    pub dc_pub_key_hash: Hash<'a>,
}
