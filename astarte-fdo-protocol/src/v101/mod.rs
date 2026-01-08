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

use serde::{Deserialize, Serialize};
use serde_bytes::ByteArray;

use crate::error::ErrorKind;
use crate::Error;

use super::utils::Hex;

pub mod device_credentials;
pub mod eat_signature;
pub mod error;
pub mod hash_hmac;
pub mod key_exchange;
pub mod ownership_voucher;
pub mod public_key;
pub mod rendezvous_info;
pub mod rv_to2_addr;
pub mod service_info;
pub mod sign_info;
pub mod x509;

pub mod di;
pub mod to1;
pub mod to2;

/// Major version of the protocol
pub const PROTOCOL_VERSION_MAJOR: Protver = 1;
/// Minor version of the protocol
pub const PROTOCOL_VERSION_MINOR: Protver = 1;
/// Protocol version to pass in the path:
///
/// ```text
/// major * 100 + minor
/// ```
pub const PROTOCOL_VERSION: Protver = PROTOCOL_VERSION_MAJOR * 100 + PROTOCOL_VERSION_MINOR;

/// Protocol version: the version of the transmitted ("wire") protocol
pub type Protver = u16;
/// Length of the CBOR data in the message.
pub type Msglen = u16;
/// A message type, which acts to identify the message body.
pub type Msgtype = u16;

/// Serialize and deserialize a message.
pub trait Message: Sized {
    /// A message type, which acts to identify the message body.
    const MSG_TYPE: Msgtype;

    /// Decodes a message from a buffer.
    fn decode(buf: &[u8]) -> Result<Self, crate::Error>;

    /// Encode a message into the writer using the provided puffer for support.
    ///
    /// The buffer should have a size that is lower than the MTU of the protocol.
    ///
    /// For example if the MTU is 1400 we sill use a buffer of 1300 bytes to have space for the
    /// protocol headers.
    fn encode<W>(&self, writer: &mut W) -> Result<(), crate::Error>
    where
        // TODO: use embedded-io
        W: std::io::Write;
}

/// Message sent from the device to the server
pub trait ClientMessage: Message {
    /// Response to this message.
    type Response<'a>: Message;
}

/// Initial message in a protocol (DI, TO1, or TO2).
///
/// This message doesn't require authentication.
pub trait InitialMessage: ClientMessage {}

/// Guid is implemented as a 128-bit cryptographically strong random number.
///
/// The Guid type identifies a Device during onboarding, and is replaced each time onboarding is successful in the Transfer Ownership 2 (TO2) protocol.
///
/// ```cddl
/// Guid = bstr .size 16
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Guid(ByteArray<16>);

impl Guid {
    /// Create the new guid from bytes
    pub fn new(bytes: [u8; 16]) -> Self {
        Self(bytes.into())
    }
}

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
pub enum IpAddress {
    /// IP version 4
    Ipv4(Ipv4),
    /// IP version 6
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

impl From<IpAddr> for IpAddress {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(addr) => IpAddress::Ipv4(u32::from(addr).to_be_bytes().into()),
            IpAddr::V6(addr) => IpAddress::Ipv6(u128::from(addr).to_be_bytes().into()),
        }
    }
}

/// ```cddl
/// ip4 = bstr .size 4
/// ```
pub type Ipv4 = ByteArray<4>;

/// ```cddl
/// ip6 = bstr .size 16
/// ```
pub type Ip6 = ByteArray<16>;

/// ```cddl
/// DNSAddress = tstr
/// ```
pub type DnsAddress<'a> = Cow<'a, str>;

/// ```cddl
/// Port = uint16
/// ```
pub type Port = u16;

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
    /// TCP stream
    Tcp = 1,
    /// TLS stream
    Tls = 2,
    /// HTTP messages
    Http = 3,
    /// CoAP messages
    CoAp = 4,
    /// HTTPS messages
    Https = 5,
    /// CoAPS messages
    CoAps = 6,
}

impl TryFrom<u8> for TransportProtocol {
    type Error = crate::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let value = match value {
            1 => TransportProtocol::Tcp,
            2 => TransportProtocol::Tls,
            3 => TransportProtocol::Http,
            4 => TransportProtocol::CoAp,
            5 => TransportProtocol::Https,
            6 => TransportProtocol::CoAps,
            _ => return Err(Error::new(ErrorKind::OutOfRange, "for TransportProtocol")),
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
pub type Nonce = ByteArray<16>;

/// ```cddl
/// NonceTO0Sign = Nonce
/// ```
pub type NonceTo0Sign = Nonce;

/// ```cddl
/// NonceTO1Proof = Nonce
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(transparent)]
pub struct NonceTo1Proof(pub Nonce);

/// ```cddl
/// NonceTO2ProveOV = Nonce
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(transparent)]
pub struct NonceTo2ProveOv(pub Nonce);

/// ```cddl
/// NonceTO2ProveDv = Nonce
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(transparent)]
pub struct NonceTo2ProveDv(pub Nonce);

/// ```cddl
/// NonceTO2SetupDv = Nonce
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(transparent)]
pub struct NonceTo2SetupDv(pub Nonce);

#[cfg(test)]
pub(crate) mod tests {

    use pretty_assertions::assert_eq;

    use super::*;

    pub(crate) fn from_hex(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        assert!(hex.is_ascii());

        hex.as_bytes()
            .chunks_exact(2)
            .map(|str| {
                let str = str::from_utf8(str).expect("should be hex");

                u8::from_str_radix(str, 16).expect("should be hex")
            })
            .collect()
    }

    pub(crate) fn create_guid() -> Guid {
        let guid = from_hex("43bc9e0f731a4e7f947c5d03b0c1e483");

        let array = guid.try_into().expect("should be a uuid");

        Guid::new(array)
    }

    #[test]
    fn guid_roundtrip() {
        let guid = create_guid();

        let mut buf = Vec::new();
        ciborium::into_writer(&guid, &mut buf).unwrap();

        let res: Guid = ciborium::from_reader(buf.as_slice()).unwrap();

        assert_eq!(res, guid);

        insta::assert_binary_snapshot!(".cbor", buf);
    }

    #[test]
    fn guid_deref() {
        let bytes: Vec<u8> = "43bc9e0f731a4e7f947c5d03b0c1e483"
            .as_bytes()
            .chunks_exact(2)
            .rev()
            .map(|str| {
                let str = str::from_utf8(str).expect("should be hex");
                u8::from_str_radix(str, 16).expect("should be hex")
            })
            .collect();

        let array = bytes.clone().try_into().expect("should be a uuid");

        let guid = Guid::new(array);

        assert_eq!(guid.deref().as_slice(), bytes);
    }

    #[test]
    fn guid_display() {
        let guid = create_guid();

        insta::assert_debug_snapshot!(guid);
        insta::assert_snapshot!(guid);
    }

    #[test]
    fn ip_roundtrip_with_std() {
        let cases = [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ];

        for case in cases {
            let ip = IpAddress::from(case);

            let std_ip = IpAddr::from(ip);

            assert_eq!(std_ip, case);
        }
    }

    #[test]
    fn ip_roundtrip() {
        let cases = [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ];

        for case in cases {
            let ip = IpAddress::from(case);

            let mut buf = Vec::new();
            ciborium::into_writer(&ip, &mut buf).unwrap();

            let res: IpAddress = ciborium::from_reader(buf.as_slice()).unwrap();

            assert_eq!(res, ip);

            insta::assert_binary_snapshot!(".cbor", buf);
        }
    }

    #[test]
    fn transport_protocol_roundtrip() {
        let cases = [
            TransportProtocol::Tcp,
            TransportProtocol::Tls,
            TransportProtocol::Http,
            TransportProtocol::CoAp,
            TransportProtocol::Https,
            TransportProtocol::CoAps,
        ];

        for case in cases {
            let mut buf = Vec::new();
            ciborium::into_writer(&case, &mut buf).unwrap();

            let res: TransportProtocol = ciborium::from_reader(buf.as_slice()).unwrap();

            assert_eq!(res, case);

            insta::assert_binary_snapshot!(".cbor", buf);
        }
    }

    #[test]
    fn transport_protocol_error() {
        let err = TransportProtocol::try_from(7u8).unwrap_err();

        assert_eq!(*err.kind(), ErrorKind::OutOfRange);
    }

    #[test]
    fn nonce_roundtrip() {
        let nonce = Nonce::from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

        let mut buf = Vec::new();
        ciborium::into_writer(&nonce, &mut buf).unwrap();

        let res: Nonce = ciborium::from_reader(buf.as_slice()).unwrap();

        assert_eq!(res, nonce);

        insta::assert_binary_snapshot!(".cbor", buf);
    }
}
