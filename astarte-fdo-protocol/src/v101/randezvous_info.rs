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
use std::fmt::Debug;
use std::ops::Deref;

use eyre::bail;
use serde::{Deserialize, Serialize};
use serde_bytes::Bytes;

use crate::utils::OneOrMore;

/// ```cddl
/// RendezvousInfo = [
///     + RendezvousDirective
/// ]
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct RendezvousInfo<'a>(OneOrMore<RendezvousDirective<'a>>);

impl<'a> Deref for RendezvousInfo<'a> {
    type Target = Vec<RendezvousDirective<'a>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// ```cddl
/// RendezvousDirective = [
///     + RendezvousInstr
/// ]
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct RendezvousDirective<'a>(OneOrMore<RendezvousInstr<'a>>);

impl<'a> Deref for RendezvousDirective<'a> {
    type Target = Vec<RendezvousInstr<'a>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// ```cddl
/// RendezvousInstr = [
///     RVVariable,
///     RVValue
/// ]
/// ```
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RendezvousInstr<'a> {
    pub(crate) rv_variable: RVVariable,
    pub(crate) rv_value: RVValue<'a>,
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
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
#[repr(u8)]
pub(crate) enum RVVariable {
    RVDevOnly = 0,
    RVOwnerOnly = 1,
    RVIPAddress = 2,
    RVDevPort = 3,
    RVOwnerPort = 4,
    RVDns = 5,
    RVSvCertHash = 6,
    RVClCertHash = 7,
    RVUserInput = 8,
    RVWifiSsid = 9,
    RVWifiPw = 10,
    RVMedium = 11,
    RVProtocol = 12,
    RVDelaysec = 13,
    RVBypass = 14,
    RVExtRV = 15,
}

impl Debug for RVVariable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RVDevOnly => write!(f, "RVDevOnly(0)"),
            Self::RVOwnerOnly => write!(f, "RVOwnerOnly(1)"),
            Self::RVIPAddress => write!(f, "RVIPAddress(2)"),
            Self::RVDevPort => write!(f, "RVDevPort(3)"),
            Self::RVOwnerPort => write!(f, "RVOwnerPort(4)"),
            Self::RVDns => write!(f, "RVDns(5)"),
            Self::RVSvCertHash => write!(f, "RVSvCertHash(6)"),
            Self::RVClCertHash => write!(f, "RVClCertHash(7)"),
            Self::RVUserInput => write!(f, "RVUserInput(8)"),
            Self::RVWifiSsid => write!(f, "RVWifiSsid(9)"),
            Self::RVWifiPw => write!(f, "RVWifiPw(10)"),
            Self::RVMedium => write!(f, "RVMedium(11)"),
            Self::RVProtocol => write!(f, "RVProtocol(12)"),
            Self::RVDelaysec => write!(f, "RVDelaysec(13)"),
            Self::RVBypass => write!(f, "RVBypass(14)"),
            Self::RVExtRV => write!(f, "RVExtRV(15)"),
        }
    }
}

impl TryFrom<u8> for RVVariable {
    type Error = eyre::Report;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let value = match value {
            0 => Self::RVDevOnly,
            1 => Self::RVOwnerOnly,
            2 => Self::RVIPAddress,
            3 => Self::RVDevPort,
            4 => Self::RVOwnerPort,
            5 => Self::RVDns,
            6 => Self::RVSvCertHash,
            7 => Self::RVClCertHash,
            8 => Self::RVUserInput,
            9 => Self::RVWifiSsid,
            10 => Self::RVWifiPw,
            11 => Self::RVMedium,
            12 => Self::RVProtocol,
            13 => Self::RVDelaysec,
            14 => Self::RVBypass,
            15 => Self::RVExtRV,
            _ => bail!("value out of range: {value}"),
        };

        Ok(value)
    }
}

impl From<RVVariable> for u8 {
    fn from(value: RVVariable) -> Self {
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
pub(crate) enum RvProtocolValue {
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

impl TryFrom<u8> for RvProtocolValue {
    type Error = eyre::Report;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let value = match value {
            0 => RvProtocolValue::Rest,
            1 => RvProtocolValue::Http,
            2 => RvProtocolValue::Https,
            3 => RvProtocolValue::Tcp,
            4 => RvProtocolValue::Tls,
            5 => RvProtocolValue::CoapTcp,
            6 => RvProtocolValue::CoapUdp,
            _ => bail!("value out of range: {value}"),
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
pub(crate) enum RvMediumValue {
    RvMedEth0 = 0,
    RvMedEth1 = 1,
    RvMedEth2 = 2,
    RvMedEth3 = 3,
    RvMedEth4 = 4,
    RvMedEth5 = 5,
    RvMedEth6 = 6,
    RvMedEth7 = 7,
    RvMedEth8 = 8,
    RvMedEth9 = 9,
    RvMedWifi0 = 10,
    RvMedWifi1 = 11,
    RvMedWifi2 = 12,
    RvMedWifi3 = 13,
    RvMedWifi4 = 14,
    RvMedWifi5 = 15,
    RvMedWifi6 = 16,
    RvMedWifi7 = 17,
    RvMedWifi8 = 18,
    RvMedWifi9 = 19,
    RvMedEthAll = 20,
    RvMedWifiAll = 21,
}

impl TryFrom<u8> for RvMediumValue {
    type Error = eyre::Report;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let value = match value {
            0 => RvMediumValue::RvMedEth0,
            1 => RvMediumValue::RvMedEth1,
            2 => RvMediumValue::RvMedEth2,
            3 => RvMediumValue::RvMedEth3,
            4 => RvMediumValue::RvMedEth4,
            5 => RvMediumValue::RvMedEth5,
            6 => RvMediumValue::RvMedEth6,
            7 => RvMediumValue::RvMedEth7,
            8 => RvMediumValue::RvMedEth8,
            9 => RvMediumValue::RvMedEth9,
            10 => RvMediumValue::RvMedWifi0,
            11 => RvMediumValue::RvMedWifi1,
            12 => RvMediumValue::RvMedWifi2,
            13 => RvMediumValue::RvMedWifi3,
            14 => RvMediumValue::RvMedWifi4,
            15 => RvMediumValue::RvMedWifi5,
            16 => RvMediumValue::RvMedWifi6,
            17 => RvMediumValue::RvMedWifi7,
            18 => RvMediumValue::RvMedWifi8,
            19 => RvMediumValue::RvMedWifi9,
            20 => RvMediumValue::RvMedEthAll,
            21 => RvMediumValue::RvMedWifiAll,
            _ => bail!("value out of range: {value}"),
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
pub(crate) type RVValue<'a> = Cow<'a, Bytes>;
