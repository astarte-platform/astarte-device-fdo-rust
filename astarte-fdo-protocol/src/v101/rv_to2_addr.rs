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

use serde::{Deserialize, Serialize};

use crate::utils::OneOrMore;

use super::{DnsAddress, IpAddress, Port, TransportProtocol};

/// ```cddl
/// RVTO2Addr = [ + RVTO2AddrEntry ]  ;; (one or more RVTO2AddrEntry)
/// ```
pub(crate) type RvTo2Addr<'a> = OneOrMore<RvTo2AddrEntry<'a>>;

/// ```cddl
/// RVTO2AddrEntry = [
///    RVIP: IPAddress / null,       ;; IP address where Owner is waiting for TO2
///    RVDNS: DNSAddress / null,     ;; DNS address where Owner is waiting for TO2
///    RVPort: Port,                 ;; TCP/UDP port to go with above
///    RVProtocol: TransportProtocol ;; Protocol, to go with above
/// ]
/// ```
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RvTo2AddrEntry<'a> {
    pub(crate) rv_ip: Option<IpAddress>,
    pub(crate) rv_dns: Option<DnsAddress<'a>>,
    pub(crate) rv_port: Port,
    pub(crate) rv_protocol: TransportProtocol,
}

impl Serialize for RvTo2AddrEntry<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            rv_ip,
            rv_dns,
            rv_port,
            rv_protocol,
        } = self;

        (rv_ip, rv_dns, rv_port, rv_protocol).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RvTo2AddrEntry<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (rv_ip, rv_dns, rv_port, rv_protocol) = Deserialize::deserialize(deserializer)?;

        Ok(Self {
            rv_ip,
            rv_dns,
            rv_port,
            rv_protocol,
        })
    }
}
