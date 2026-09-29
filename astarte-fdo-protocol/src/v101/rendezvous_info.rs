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

//! The RendezvousInfo type indicates the manner and order in which the Device and Owner find the
//! Rendezvous Server.
//!
//! It is configured during manufacturing (e.g., at an ODM), so the manufacturing entity has the
//! choice of which Rendezvous Server(s) to use and how to access it or them.

use std::borrow::Cow;
use std::fmt::{Debug, Display};
use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_bytes::Bytes;

use crate::Error;
use crate::error::ErrorKind;
use crate::utils::{Hex, OneOrMore};

use super::hash_hmac::Hash;
use super::{DnsAddress, IpAddress};

macro_rules! decode_rv_value {
    ($value:expr, $name:literal) => {
        ciborium::from_reader::<_, &[u8]>($value)
            .map_err(|err| {
                #[cfg(feature = "tracing")]
                tracing::error!(error = %err, concat!("couldn't decode ", $name));

                Error::new(ErrorKind::Decode, $name)
            })
    };
}

/// ```cddl
/// RendezvousInfo = [
///     + RendezvousDirective
/// ]
/// ```
pub type RendezvousInfo<'a> = OneOrMore<RendezvousDirective<'a>>;

/// ```cddl
/// RendezvousDirective = [
///     + RendezvousInstr
/// ]
/// ```
pub type RendezvousDirective<'a> = OneOrMore<RendezvousInstr<'a>>;

/// ```cddl
/// RendezvousInstr = [
///     RVVariable,
///     RVValue
/// ]
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct RendezvousInstr<'a> {
    /// Identifies the type to decode for [`rv_value`](Self::rv_value)
    pub rv_variable: RvVariable,
    /// Instruction to contact the Rendezvous Server.
    pub rv_value: RvValue<'a>,
}

impl<'a> RendezvousInstr<'a> {
    /// Attempts to decode the value as an IP address.
    pub fn try_as_ip_address(&self) -> Result<IpAddress, Error> {
        let ip: IpAddress = decode_rv_value!(self.rv_value.as_ref(), "ip address")?;

        Ok(ip)
    }

    /// Attempts to decode the value as a device port.
    pub fn try_as_dev_port(&self) -> Result<u16, Error> {
        let port: u16 = decode_rv_value!(self.rv_value.as_ref(), "device port")?;
        Ok(port)
    }

    /// Attempts to decode the value as an owner port.
    pub fn try_as_owner_port(&self) -> Result<u16, Error> {
        let port: u16 = decode_rv_value!(self.rv_value.as_ref(), "owner port")?;
        Ok(port)
    }

    /// Attempts to decode the value as a DNS address.
    pub fn try_as_dns(&self) -> Result<DnsAddress<'a>, Error> {
        let dns: DnsAddress = decode_rv_value!(self.rv_value.as_ref(), "dns")?;
        Ok(dns)
    }

    /// Attempts to decode the value as a server certificate hash.
    pub fn try_as_sv_cert_hash(&self) -> Result<Hash<'a>, Error> {
        let hash: Hash = decode_rv_value!(self.rv_value.as_ref(), "server cert hash")?;
        Ok(hash)
    }

    /// Attempts to decode the value as a client/CA certificate hash.
    pub fn try_as_cl_cert_hash(&self) -> Result<Hash<'a>, Error> {
        let hash: Hash = decode_rv_value!(self.rv_value.as_ref(), "ca cert hash")?;
        Ok(hash)
    }

    /// Attempts to decode the value into a boolean indicating if user input is needed.
    pub fn try_as_user_input(&self) -> Result<bool, Error> {
        let input: bool = decode_rv_value!(self.rv_value.as_ref(), "needs user input")?;
        Ok(input)
    }

    /// Attempts to decode the value as a WiFi SSID.
    pub fn try_as_wifi_ssid(&self) -> Result<Cow<'a, str>, Error> {
        let ssid: Cow<'a, str> = decode_rv_value!(self.rv_value.as_ref(), "wifi ssid")?;

        Ok(ssid)
    }

    /// Attempts to decode the value as a WiFi password.
    pub fn try_as_wifi_pw(&self) -> Result<Cow<'a, str>, Error> {
        let pw: Cow<'a, str> = decode_rv_value!(self.rv_value.as_ref(), "wifi ssid")?;

        Ok(pw)
    }

    /// Attempts to decode the value as a connection medium.
    pub fn try_as_medium(&self) -> Result<RvMediumValue, Error> {
        let medium: RvMediumValue = decode_rv_value!(self.rv_value.as_ref(), "medium")?;

        Ok(medium)
    }

    /// Attempts to decode the value as a protocol value.
    pub fn try_as_protocol(&self) -> Result<RvProtocolValue, Error> {
        let proto: RvProtocolValue = decode_rv_value!(self.rv_value.as_ref(), "protocol value")?;

        Ok(proto)
    }

    /// Attempts to decode the value as a delay duration.
    pub fn try_as_delaysec(&self) -> Result<Duration, Error> {
        let delay: u32 = decode_rv_value!(self.rv_value.as_ref(), "delay")?;
        let delay = Duration::from_secs(delay.into());

        Ok(delay)
    }
}

impl<'a> Display for RendezvousInstr<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}", self.rv_variable)?;

        match self.rv_variable {
            RvVariable::DevOnly | RvVariable::OwnerOnly => {
                write!(f, "]")
            }
            RvVariable::IPAddress => match self.try_as_ip_address() {
                Ok(ip) => {
                    write!(f, ", {}]", IpAddr::from(ip))
                }
                Err(_) => {
                    write!(f, ", INVALID({})]", Hex::new(&self.rv_value))
                }
            },
            RvVariable::DevPort => match self.try_as_dev_port() {
                Ok(port) => write!(f, ", {}]", port),
                Err(_) => write!(f, ", INVALID({})]", Hex::new(&self.rv_value)),
            },
            RvVariable::OwnerPort => match self.try_as_owner_port() {
                Ok(port) => write!(f, ", {}]", port),
                Err(_) => write!(f, ", INVALID({})]", Hex::new(&self.rv_value)),
            },
            RvVariable::Dns => match self.try_as_dns() {
                Ok(dns) => write!(f, ", {}]", dns),
                Err(_) => write!(f, ", INVALID({})]", Hex::new(&self.rv_value)),
            },
            RvVariable::SvCertHash => match self.try_as_sv_cert_hash() {
                Ok(hash) => write!(f, ", {}]", hash),
                Err(_) => write!(f, ", INVALID({})]", Hex::new(&self.rv_value)),
            },
            RvVariable::ClCertHash => match self.try_as_cl_cert_hash() {
                Ok(hash) => write!(f, ", {}]", hash),
                Err(_) => write!(f, ", INVALID({})]", Hex::new(&self.rv_value)),
            },
            RvVariable::UserInput => match self.try_as_user_input() {
                Ok(input) => write!(f, ", {}]", input),
                Err(_) => write!(f, ", INVALID({})]", Hex::new(&self.rv_value)),
            },
            RvVariable::WifiSsid => match self.try_as_wifi_ssid() {
                Ok(ssid) => write!(f, ", {}]", ssid),
                Err(_) => write!(f, ", INVALID({})]", Hex::new(&self.rv_value)),
            },
            RvVariable::WifiPw => match self.try_as_wifi_pw() {
                Ok(pw) => write!(f, ", {}]", pw),
                Err(_) => write!(f, ", INVALID({})]", Hex::new(&self.rv_value)),
            },
            RvVariable::Medium => match self.try_as_medium() {
                Ok(medium) => write!(f, ", {}]", medium),
                Err(_) => write!(f, ", INVALID({})]", Hex::new(&self.rv_value)),
            },
            RvVariable::Protocol => match self.try_as_protocol() {
                Ok(proto) => write!(f, ", {}]", proto),
                Err(_) => write!(f, ", INVALID({})]", Hex::new(&self.rv_value)),
            },
            RvVariable::Delaysec => match self.try_as_delaysec() {
                Ok(delay) => write!(f, ", {}]", delay.as_secs()),
                Err(_) => write!(f, ", INVALID({})]", Hex::new(&self.rv_value)),
            },
            RvVariable::Bypass | RvVariable::ExtRV => {
                write!(f, ", {}]", Hex::new(&self.rv_value))
            }
        }
    }
}

impl Serialize for RendezvousInstr<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            rv_variable,
            rv_value,
        } = self;

        (rv_variable, rv_value).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RendezvousInstr<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (rv_variable, rv_value) = Deserialize::deserialize(deserializer)?;

        Ok(Self {
            rv_variable,
            rv_value,
        })
    }
}

/// ```cddl
/// RVVariable = uint8
/// $RVVariable = ()
/// RVVariable /= (
///     RVDevOnly     => 0,
///     RVOwnerOnly   => 1,
///     RVIPAddress   => 2,
///     RVDevPort     => 3,
///     RVOwnerPort   => 4,
///     RVDns         => 5,
///     RVSvCertHash  => 6,
///     RVClCertHash  => 7,
///     RVUserInput   => 8,
///     RVWifiSsid    => 9,
///     RVWifiPw      => 10,
///     RVMedium      => 11,
///     RVProtocol    => 12,
///     RVDelaysec    => 13,
///     RVBypass      => 14,
///     RVExtRV       => 15
/// )
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
#[repr(u8)]
pub enum RvVariable {
    /// Device Only
    ///
    /// If the RVDevOnly element appears on the Owner, this instruction is terminated and control proceeds with the next set of instructions.
    DevOnly = 0,
    /// Owner Only
    ///
    /// If the RVOwnerOnly element appears on the Device, this instruction is terminated and control proceeds with the next set of instructions.
    OwnerOnly = 1,
    /// IP address
    IPAddress = 2,
    /// Port, Device
    ///
    /// Based on protocol
    DevPort = 3,
    /// Port, Owner
    ///
    /// Based on protocol
    OwnerPort = 4,
    /// DNS name
    Dns = 5,
    /// TLS Server cert hash
    SvCertHash = 6,
    /// TLS CA cert hash
    ClCertHash = 7,
    /// User input
    UserInput = 8,
    /// SSID
    WifiSsid = 9,
    /// Wireless Password
    WifiPw = 10,
    /// Medium
    Medium = 11,
    /// Protocol
    Protocol = 12,
    /// Delay
    Delaysec = 13,
    /// Bypass
    Bypass = 14,
    /// External RV
    ExtRV = 15,
}

impl Display for RvVariable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DevOnly => write!(f, "RVDevOnly(0)"),
            Self::OwnerOnly => write!(f, "RVOwnerOnly(1)"),
            Self::IPAddress => write!(f, "RVIPAddress(2)"),
            Self::DevPort => write!(f, "RVDevPort(3)"),
            Self::OwnerPort => write!(f, "RVOwnerPort(4)"),
            Self::Dns => write!(f, "RVDns(5)"),
            Self::SvCertHash => write!(f, "RVSvCertHash(6)"),
            Self::ClCertHash => write!(f, "RVClCertHash(7)"),
            Self::UserInput => write!(f, "RVUserInput(8)"),
            Self::WifiSsid => write!(f, "RVWifiSsid(9)"),
            Self::WifiPw => write!(f, "RVWifiPw(10)"),
            Self::Medium => write!(f, "RVMedium(11)"),
            Self::Protocol => write!(f, "RVProtocol(12)"),
            Self::Delaysec => write!(f, "RVDelaysec(13)"),
            Self::Bypass => write!(f, "RVBypass(14)"),
            Self::ExtRV => write!(f, "RVExtRV(15)"),
        }
    }
}

impl TryFrom<u8> for RvVariable {
    type Error = crate::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let value = match value {
            0 => Self::DevOnly,
            1 => Self::OwnerOnly,
            2 => Self::IPAddress,
            3 => Self::DevPort,
            4 => Self::OwnerPort,
            5 => Self::Dns,
            6 => Self::SvCertHash,
            7 => Self::ClCertHash,
            8 => Self::UserInput,
            9 => Self::WifiSsid,
            10 => Self::WifiPw,
            11 => Self::Medium,
            12 => Self::Protocol,
            13 => Self::Delaysec,
            14 => Self::Bypass,
            15 => Self::ExtRV,
            _ => return Err(Error::new(ErrorKind::OutOfRange, "for RVValue")),
        };

        Ok(value)
    }
}

impl From<RvVariable> for u8 {
    fn from(value: RvVariable) -> Self {
        value as u8
    }
}

/// ```cddl
/// RVProtocolValue /= (
///     RVProtRest    => 0,
///     RVProtHttp    => 1,
///     RVProtHttps   => 2,
///     RVProtTcp     => 3,
///     RVProtTls     => 4,
///     RVProtCoapTcp => 5,
///     RVProtCoapUdp => 6
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
#[repr(u8)]
pub enum RvProtocolValue {
    /// first supported protocol from:
    ///
    /// - RVProtHttps
    /// - RVProtHttp
    /// - RVProtCoapUdp
    /// - RVProtCoapTcp
    Rest = 0,
    /// HTTP over TCP
    Http = 1,
    /// HTTP over TLS, if supported
    Https = 2,
    /// bare TCP, if supported
    Tcp = 3,
    /// bare TLS, if supported
    Tls = 4,
    /// CoAP protocol over tcp, if supported
    CoapTcp = 5,
    /// CoAP protocol over UDP, if supported
    CoapUdp = 6,
}

impl Display for RvProtocolValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RvProtocolValue::Rest => write!(f, "Rest(0)"),
            RvProtocolValue::Http => write!(f, "Http(1)"),
            RvProtocolValue::Https => write!(f, "Https(2)"),
            RvProtocolValue::Tcp => write!(f, "Tcp(3)"),
            RvProtocolValue::Tls => write!(f, "Tls(4)"),
            RvProtocolValue::CoapTcp => write!(f, "CoapTcp(5)"),
            RvProtocolValue::CoapUdp => write!(f, "CoapUdp(6)"),
        }
    }
}

impl TryFrom<u8> for RvProtocolValue {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let value = match value {
            0 => RvProtocolValue::Rest,
            1 => RvProtocolValue::Http,
            2 => RvProtocolValue::Https,
            3 => RvProtocolValue::Tcp,
            4 => RvProtocolValue::Tls,
            5 => RvProtocolValue::CoapTcp,
            6 => RvProtocolValue::CoapUdp,
            _ => return Err(Error::new(ErrorKind::OutOfRange, "for RVProtocolValue")),
        };

        Ok(value)
    }
}

impl From<RvProtocolValue> for u8 {
    fn from(value: RvProtocolValue) -> Self {
        value as u8
    }
}

/// Mapped to first through 10th wired Ethernet interfaces. These interfaces may appear with
/// different names in a given platform.
///
/// ```cddl
/// $RVMediumValue /= (
///  RVMedEth0 => 0,
///  RVMedEth1 => 1,
///  RVMedEth2 => 2,
///  RVMedEth3 => 3,
///  RVMedEth4 => 4,
///  RVMedEth5 => 5,
///  RVMedEth6 => 6,
///  RVMedEth7 => 7,
///  RVMedEth8 => 8,
///  RVMedEth9 => 9
/// )
/// ```
///
/// means to try as many wired interfaces as makes sense for this platform, in any order. For
/// example, a device which has one or more wired interfaces that are configured to access the
/// Internet (e.g., “wan0”) might use this configuration to try any of them that has Ethernet link.
///
/// ```cddl
/// $RVMediumValue /= (
///    RVMedEthAll => 20,
/// )
/// ```
///
/// mapped to first through 10th WiFi interfaces. These interfaces may appear with different names
/// in a given platform.
///
/// ```cddl
/// $RVMediumValue /= (
///    RVMedWifi0 => 10,
///    RVMedWifi1 => 11,
///    RVMedWifi2 => 12,
///    RVMedWifi3 => 13,
///    RVMedWifi4 => 14,
///    RVMedWifi5 => 15,
///    RVMedWifi6 => 16,
///    RVMedWifi7 => 17,
///    RVMedWifi8 => 18,
///    RVMedWifi9 => 19
/// )
/// ```
///
/// means to try as many WiFi interfaces as makes sense for this platform, in any order
///
/// ```cddl
/// $RVMediumValue /= (
///    RVMedWifiAll => 21
/// )
/// ```
///
/// Or others device dependent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
#[repr(u8)]
pub enum RvMediumValue {
    /// Ethernet interface n. 0
    Eth0 = 0,
    /// Ethernet interface n. 1
    Eth1 = 1,
    /// Ethernet interface n. 2
    Eth2 = 2,
    /// Ethernet interface n. 3
    Eth3 = 3,
    /// Ethernet interface n. 4
    Eth4 = 4,
    /// Ethernet interface n. 5
    Eth5 = 5,
    /// Ethernet interface n. 6
    Eth6 = 6,
    /// Ethernet interface n. 7
    Eth7 = 7,
    /// Ethernet interface n. 8
    Eth8 = 8,
    /// Ethernet interface n. 9
    Eth9 = 9,
    /// Wifi interface n. 0
    Wifi0 = 10,
    /// Wifi interface n. 1
    Wifi1 = 11,
    /// Wifi interface n. 2
    Wifi2 = 12,
    /// Wifi interface n. 3
    Wifi3 = 13,
    /// Wifi interface n. 4
    Wifi4 = 14,
    /// Wifi interface n. 5
    Wifi5 = 15,
    /// Wifi interface n. 6
    Wifi6 = 16,
    /// Wifi interface n. 7
    Wifi7 = 17,
    /// Wifi interface n. 8
    Wifi8 = 18,
    /// Wifi interface n. 9
    Wifi9 = 19,
    /// As many wired interfaces as makes sense for this platform, in any order.
    EthAll = 20,
    /// As many Wifi interfaces as makes sense for this platform, in any order.
    WifiAll = 21,
}

impl Display for RvMediumValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RvMediumValue::Eth0 => write!(f, "Eth0"),
            RvMediumValue::Eth1 => write!(f, "Eth1"),
            RvMediumValue::Eth2 => write!(f, "Eth2"),
            RvMediumValue::Eth3 => write!(f, "Eth3"),
            RvMediumValue::Eth4 => write!(f, "Eth4"),
            RvMediumValue::Eth5 => write!(f, "Eth5"),
            RvMediumValue::Eth6 => write!(f, "Eth6"),
            RvMediumValue::Eth7 => write!(f, "Eth7"),
            RvMediumValue::Eth8 => write!(f, "Eth8"),
            RvMediumValue::Eth9 => write!(f, "Eth9"),
            RvMediumValue::Wifi0 => write!(f, "Wifi0"),
            RvMediumValue::Wifi1 => write!(f, "Wifi1"),
            RvMediumValue::Wifi2 => write!(f, "Wifi2"),
            RvMediumValue::Wifi3 => write!(f, "Wifi3"),
            RvMediumValue::Wifi4 => write!(f, "Wifi4"),
            RvMediumValue::Wifi5 => write!(f, "Wifi5"),
            RvMediumValue::Wifi6 => write!(f, "Wifi6"),
            RvMediumValue::Wifi7 => write!(f, "Wifi7"),
            RvMediumValue::Wifi8 => write!(f, "Wifi8"),
            RvMediumValue::Wifi9 => write!(f, "Wifi9"),
            RvMediumValue::EthAll => write!(f, "EthAll"),
            RvMediumValue::WifiAll => write!(f, "WifiAll"),
        }
    }
}

impl TryFrom<u8> for RvMediumValue {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let value = match value {
            0 => RvMediumValue::Eth0,
            1 => RvMediumValue::Eth1,
            2 => RvMediumValue::Eth2,
            3 => RvMediumValue::Eth3,
            4 => RvMediumValue::Eth4,
            5 => RvMediumValue::Eth5,
            6 => RvMediumValue::Eth6,
            7 => RvMediumValue::Eth7,
            8 => RvMediumValue::Eth8,
            9 => RvMediumValue::Eth9,
            10 => RvMediumValue::Wifi0,
            11 => RvMediumValue::Wifi1,
            12 => RvMediumValue::Wifi2,
            13 => RvMediumValue::Wifi3,
            14 => RvMediumValue::Wifi4,
            15 => RvMediumValue::Wifi5,
            16 => RvMediumValue::Wifi6,
            17 => RvMediumValue::Wifi7,
            18 => RvMediumValue::Wifi8,
            19 => RvMediumValue::Wifi9,
            20 => RvMediumValue::EthAll,
            21 => RvMediumValue::WifiAll,
            _ => return Err(Error::new(ErrorKind::OutOfRange, "for RVMediumValue")),
        };

        Ok(value)
    }
}

impl From<RvMediumValue> for u8 {
    fn from(value: RvMediumValue) -> Self {
        value as u8
    }
}

/// ```cddl
/// RVValue = bstr .cbor any
/// ```
pub type RvValue<'a> = Cow<'a, Bytes>;

#[cfg(test)]
pub(crate) mod tests {
    use crate::tests::insta_settings;
    use crate::utils::CborBstr;
    use crate::v101::IpAddress;

    use super::*;

    pub(crate) fn create_rv_info() -> RendezvousInfo<'static> {
        RendezvousInfo::new(vec![
            RendezvousDirective::new(vec![RendezvousInstr {
                rv_variable: RvVariable::IPAddress,
                rv_value: CborBstr::new(IpAddress::Ipv4([127, 0, 0, 1].into()))
                    .bytes()
                    .unwrap()
                    .clone(),
            }])
            .unwrap(),
        ])
        .unwrap()
    }

    #[test]
    fn rendezvous_info_roundtrip() {
        let case = create_rv_info();

        let mut buf = Vec::new();
        ciborium::into_writer(&case, &mut buf).unwrap();

        let res: RendezvousInfo = ciborium::from_reader(buf.as_slice()).unwrap();

        assert_eq!(res, case);

        insta_settings!({
            insta::assert_binary_snapshot!(".cbor", buf);
        });
    }

    #[test]
    fn rv_variable_roundtrip() {
        let cases = [
            RvVariable::DevOnly,
            RvVariable::OwnerOnly,
            RvVariable::IPAddress,
            RvVariable::DevPort,
            RvVariable::OwnerPort,
            RvVariable::Dns,
            RvVariable::SvCertHash,
            RvVariable::ClCertHash,
            RvVariable::UserInput,
            RvVariable::WifiSsid,
            RvVariable::WifiPw,
            RvVariable::Medium,
            RvVariable::Protocol,
            RvVariable::Delaysec,
            RvVariable::Bypass,
            RvVariable::ExtRV,
        ];

        for case in cases {
            let mut buf = Vec::new();
            ciborium::into_writer(&case, &mut buf).unwrap();

            let res: RvVariable = ciborium::from_reader(buf.as_slice()).unwrap();

            assert_eq!(res, case);

            insta_settings!({
                insta::assert_binary_snapshot!(".cbor", buf);
            });
        }
    }

    #[test]
    fn rv_variable_err() {
        let err = RvVariable::try_from(16).unwrap_err();

        assert_eq!(*err.kind(), ErrorKind::OutOfRange);
    }

    #[test]
    fn rv_variable_debug() {
        let cases = [
            RvVariable::DevOnly,
            RvVariable::OwnerOnly,
            RvVariable::IPAddress,
            RvVariable::DevPort,
            RvVariable::OwnerPort,
            RvVariable::Dns,
            RvVariable::SvCertHash,
            RvVariable::ClCertHash,
            RvVariable::UserInput,
            RvVariable::WifiSsid,
            RvVariable::WifiPw,
            RvVariable::Medium,
            RvVariable::Protocol,
            RvVariable::Delaysec,
            RvVariable::Bypass,
            RvVariable::ExtRV,
        ];

        insta_settings!({
            for case in cases {
                insta::assert_snapshot!(case);
            }
        });
    }

    #[test]
    fn rv_protocol_value_roundtrip() {
        let cases = [
            RvProtocolValue::Rest,
            RvProtocolValue::Http,
            RvProtocolValue::Https,
            RvProtocolValue::Tcp,
            RvProtocolValue::Tls,
            RvProtocolValue::CoapTcp,
            RvProtocolValue::CoapUdp,
        ];

        insta_settings!({
            for case in cases {
                let mut buf = Vec::new();
                ciborium::into_writer(&case, &mut buf).unwrap();

                let res: RvProtocolValue = ciborium::from_reader(buf.as_slice()).unwrap();

                assert_eq!(res, case);

                insta::assert_binary_snapshot!(".cbor", buf);
            }
        });
    }

    #[test]
    fn rv_protocol_value_err() {
        let err = RvProtocolValue::try_from(7).unwrap_err();

        assert_eq!(*err.kind(), ErrorKind::OutOfRange);
    }

    #[test]
    fn rv_medium_value_roundtrip() {
        let cases = [
            RvMediumValue::Eth0,
            RvMediumValue::Eth1,
            RvMediumValue::Eth2,
            RvMediumValue::Eth3,
            RvMediumValue::Eth4,
            RvMediumValue::Eth5,
            RvMediumValue::Eth6,
            RvMediumValue::Eth7,
            RvMediumValue::Eth8,
            RvMediumValue::Eth9,
            RvMediumValue::Wifi0,
            RvMediumValue::Wifi1,
            RvMediumValue::Wifi2,
            RvMediumValue::Wifi3,
            RvMediumValue::Wifi4,
            RvMediumValue::Wifi5,
            RvMediumValue::Wifi6,
            RvMediumValue::Wifi7,
            RvMediumValue::Wifi8,
            RvMediumValue::Wifi9,
            RvMediumValue::EthAll,
            RvMediumValue::WifiAll,
        ];

        insta_settings!({
            for case in cases {
                let mut buf = Vec::new();
                ciborium::into_writer(&case, &mut buf).unwrap();

                let res: RvMediumValue = ciborium::from_reader(buf.as_slice()).unwrap();

                assert_eq!(res, case);

                insta::assert_binary_snapshot!(".cbor", buf);
            }
        });
    }

    #[test]
    fn rv_medium_value_err() {
        let err = RvMediumValue::try_from(22).unwrap_err();

        assert_eq!(*err.kind(), ErrorKind::OutOfRange);
    }
}
