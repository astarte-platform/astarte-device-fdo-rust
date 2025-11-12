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

//! Implements the version 1.1 of the specification.
//!
//! You can find the spec [here](https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-PS-v1.1-20220419/FIDO-Device-Onboard-PS-v1.1-20220419.html)

use std::borrow::Cow;
use std::fmt::{Debug, Display};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Deref;

use eyre::bail;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteArray;

use super::utils::Hex;

pub(crate) mod device_credentials;
pub(crate) mod eat_signature;
pub mod error;
pub(crate) mod hash_hmac;
pub(crate) mod key_exchange;
pub(crate) mod ownership_voucher;
pub(crate) mod public_key;
pub(crate) mod randezvous_info;
pub(crate) mod rv_to2_addr;
pub(crate) mod service_info;
pub(crate) mod sign_info;
pub(crate) mod x509;

pub(crate) mod di;
pub(crate) mod to1;
pub(crate) mod to2;

// Type names used in the specification
pub(crate) type Protver = u16;
pub(crate) type Msglen = u16;
pub(crate) type Msgtype = u16;

pub(crate) const PROTOCOL_VERSION_MAJOR: Protver = 1;
pub(crate) const PROTOCOL_VERSION_MINOR: Protver = 1;
pub(crate) const PROTOCOL_VERSION: Protver = PROTOCOL_VERSION_MAJOR * 100 + PROTOCOL_VERSION_MINOR;

pub(crate) trait Message: Sized {
    const MSG_TYPE: Msgtype;

    fn decode(buf: &[u8]) -> eyre::Result<Self>;

    fn encode(&self) -> eyre::Result<Vec<u8>>;
}

/// Message sent from the device to the server
pub(crate) trait ClientMessage: Message {
    type Response<'a>: Message;
}

/// Initial message in a protocol (DI, TO1, or TO2).
///
/// This message doesn't require authentication.
pub(crate) trait InitialMessage: ClientMessage {}

/// Guid is implemented as a 128-bit cryptographically strong random number.
///
/// The Guid type identifies a Device during onboarding, and is replaced each time onboarding is successful in the Transfer Ownership 2 (TO2) protocol.
///
/// ```cddl
/// Guid = bstr .size 16
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub(crate) struct Guid(ByteArray<16>);

impl Deref for Guid {
    type Target = ByteArray<16>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Guid")
            .field(&Hex::new(self.0.as_slice()))
            .finish()
    }
}

impl Display for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&Hex::new(self.0.as_slice()), f)
    }
}

/// ```cddl
/// IPAddress = ip4 / ip6
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum IpAddress {
    Ipv4(Ipv4),
    Ipv6(Ip6),
}

impl From<IpAddress> for IpAddr {
    fn from(value: IpAddress) -> Self {
        match value {
            IpAddress::Ipv4(byte_array) => {
                let bits = u32::from_be_bytes(byte_array.into_array());

                IpAddr::V4(Ipv4Addr::from(bits))
            }
            IpAddress::Ipv6(byte_array) => {
                let bits = u128::from_be_bytes(byte_array.into_array());

                IpAddr::V6(Ipv6Addr::from(bits)).to_canonical()
            }
        }
    }
}

/// ```cddl
/// ip4 = bstr .size 4
/// ```
pub(crate) type Ipv4 = ByteArray<4>;

/// ```cddl
/// ip6 = bstr .size 16
/// ```
pub(crate) type Ip6 = ByteArray<16>;

/// ```cddl
/// DNSAddress = tstr
/// ```
pub(crate) type DnsAddress<'a> = Cow<'a, str>;

/// ```cddl
/// Port = uint16
/// ```
pub(crate) type Port = u16;

/// ``` cddl
/// TransportProtocol /= (
///     ProtTCP:    1,     ;; bare TCP stream
///     ProtTLS:    2,     ;; bare TLS stream
///     ProtHTTP:   3,
///     ProtCoAP:   4,
///     ProtHTTPS:  5,
///     ProtCoAPS:  6,
/// )
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
#[repr(u8)]
pub enum TransportProtocol {
    Tcp = 1,
    Tls = 2,
    Http = 3,
    CoAp = 4,
    Https = 5,
    CoAps = 6,
}

impl TryFrom<u8> for TransportProtocol {
    type Error = eyre::Report;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let value = match value {
            1 => TransportProtocol::Tcp,
            2 => TransportProtocol::Tls,
            3 => TransportProtocol::Http,
            4 => TransportProtocol::Https,
            5 => TransportProtocol::CoAp,
            6 => TransportProtocol::CoAps,
            _ => bail!("value out of range: {value}"),
        };

        Ok(value)
    }
}

impl From<TransportProtocol> for u8 {
    fn from(value: TransportProtocol) -> Self {
        value as u8
    }
}

/// The protocol keeps several nonces in play during the
/// authentication phase.  Nonces are named in the spec, to make it
/// easier to see where the protocol requires the same nonce value.
///
/// ```cddl
/// Nonce = bstr .size 16
/// ```
pub(crate) type Nonce = ByteArray<16>;

/// ```cddl
/// NonceTO0Sign = Nonce
/// ```
pub(crate) type NonceTo0Sign = Nonce;

/// ```cddl
/// NonceTO1Proof = Nonce
/// ```
pub(crate) type NonceTo1Proof = Nonce;

/// ```cddl
/// NonceTO2ProveOV = Nonce
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[repr(transparent)]
pub(crate) struct NonceTo2ProveOv(pub(crate) Nonce);

/// ```cddl
/// NonceTO2ProveDv = Nonce
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[repr(transparent)]
pub(crate) struct NonceTo2ProveDv(pub(crate) Nonce);

/// ```cddl
/// NonceTO2SetupDv = Nonce
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[repr(transparent)]
pub(crate) struct NonceTo2SetupDv(pub(crate) Nonce);
