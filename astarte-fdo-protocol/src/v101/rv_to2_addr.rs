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

//! The RVTO2Addr indicates to the Device how to contact the Owner to run the TO2 protocol.
//!
//! The RVTO2Addr is transmitted by the Owner to the Rendezvous Server during the TO0 protocol, and
//! conveyed to the Device during the TO1 protocol.

use serde::{Deserialize, Serialize};

use crate::utils::OneOrMore;

use super::{DnsAddress, IpAddress, Port, TransportProtocol};

/// ```cddl
/// RVTO2Addr = [ + RVTO2AddrEntry ]  ;; (one or more RVTO2AddrEntry)
/// ```
pub type RvTo2Addr<'a> = OneOrMore<RvTo2AddrEntry<'a>>;

/// ```cddl
/// RVTO2AddrEntry = [
///    RVIP: IPAddress / null,       ;; IP address where Owner is waiting for TO2
///    RVDNS: DNSAddress / null,     ;; DNS address where Owner is waiting for TO2
///    RVPort: Port,                 ;; TCP/UDP port to go with above
///    RVProtocol: TransportProtocol ;; Protocol, to go with above
/// ]
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct RvTo2AddrEntry<'a> {
    pub(crate) rv_ip: Option<IpAddress>,
    pub(crate) rv_dns: Option<DnsAddress<'a>>,
    pub(crate) rv_port: Port,
    pub(crate) rv_protocol: TransportProtocol,
}

impl<'a> RvTo2AddrEntry<'a> {
    /// Return the DNS address
    pub fn rv_dns(&self) -> Option<&DnsAddress<'a>> {
        self.rv_dns.as_ref()
    }

    /// Return the IP address
    pub fn rv_ip(&self) -> Option<&IpAddress> {
        self.rv_ip.as_ref()
    }

    /// Return the Port
    pub fn rv_port(&self) -> u16 {
        self.rv_port
    }

    /// Return the protocol
    pub fn rv_protocol(&self) -> TransportProtocol {
        self.rv_protocol
    }
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

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn rv_to2_addr_roundtrip() {
        let case = RvTo2Addr::new(vec![RvTo2AddrEntry {
            rv_ip: Some(IpAddress::Ipv4([127, 0, 0, 1].into())),
            rv_dns: Some("localhost".into()),
            rv_port: 80,
            rv_protocol: TransportProtocol::Http,
        }])
        .unwrap();

        let mut buf = Vec::new();
        ciborium::into_writer(&case, &mut buf).unwrap();

        let res: RvTo2Addr = ciborium::from_reader(buf.as_slice()).unwrap();

        assert_eq!(res, case);

        insta::assert_binary_snapshot!(".cbor", buf);
    }

    #[test]
    fn rv_to2_addr_entry_getters() {
        let rv_ip = Some(IpAddress::Ipv4([127, 0, 0, 1].into()));
        let rv_dns = Some("localhost".into());
        let rv_port = 80;
        let rv_protocol = TransportProtocol::Http;
        let case = RvTo2AddrEntry {
            rv_ip,
            rv_dns: rv_dns.clone(),
            rv_port,
            rv_protocol,
        };

        assert_eq!(case.rv_ip(), rv_ip.as_ref());
        assert_eq!(case.rv_dns(), rv_dns.as_ref());
        assert_eq!(case.rv_port(), rv_port);
        assert_eq!(case.rv_protocol(), rv_protocol);
    }
}
