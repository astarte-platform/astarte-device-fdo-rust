// This file is part of Astarte.
//
// Copyright 2025, 2026 SECO Mind Srl
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

//! Completes the TO1 protocol.
//!
//! Indicates to the Device ROE that a new Owner is indeed waiting for it, and may be found by
//! connecting to any of the entries in to1dBlobPayload.RVTO2Addr containing network address
//! information.

use std::io::Write;

use coset::{CoseSign1, TaggedCborSerializable};
use serde::{Deserialize, Serialize};

use crate::Error;
use crate::error::ErrorKind;
use crate::v101::hash_hmac::Hash;
use crate::v101::rv_to2_addr::RvTo2Addr;
use crate::v101::{Message, Msgtype};

/// ```cddl
/// TO1.RVRedirect = to1d
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct RvRedirect {
    pub(crate) to1d: CoseSign1,
}

impl RvRedirect {
    /// Returns the to1d signed blob
    pub fn to1d(&self) -> &CoseSign1 {
        &self.to1d
    }

    /// Parses the Rendezvous blob
    pub fn rv_to2_addr(&self) -> Result<To1dBlob<'_>, Error> {
        let payload = self.to1d.payload.as_deref().ok_or(Error::new(
            ErrorKind::Invalid,
            "RvRedirect payload is missing",
        ))?;

        let rv_addr = ciborium::from_reader(payload).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't decode RvRedirect payload");

            Error::new(ErrorKind::Decode, "the RvRedirect payload")
        })?;

        Ok(rv_addr)
    }
}

impl Message for RvRedirect {
    const MSG_TYPE: Msgtype = 33;

    fn decode(buf: &[u8]) -> Result<Self, Error> {
        let to1d = CoseSign1::from_tagged_slice(buf).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't decode RvRedirect");

            Error::new(ErrorKind::Decode, "the RvRedirect")
        })?;

        if to1d.payload.is_none() {
            return Err(Error::new(
                ErrorKind::Invalid,
                "the RvRedirect payload is missing",
            ));
        }

        Ok(Self { to1d })
    }

    fn encode<W>(&self, write: &mut W) -> Result<(), Error>
    where
        W: Write,
    {
        self.to1d
            .clone()
            .to_tagged_vec()
            .map_err(|err| {
                #[cfg(feature = "tracing")]
                tracing::error!(error = %err, "couldn't encode RvRedirect");

                Error::new(ErrorKind::Encode, "the RvRedirect")
            })
            .and_then(|buf| {
                write.write_all(&buf).map_err(|err| {
                    #[cfg(feature = "tracing")]
                    tracing::error!(error = %err, "couldn't write RvRedirect");

                    Error::new(ErrorKind::Write, "the RvRedirect")
                })
            })
    }
}

/// ```cddl
/// to1dBlobPayload = [
///     to1dRV:       RVTO2Addr, ;; choices to access TO2 protocol
///     to1dTo0dHash: Hash       ;; Hash of to0d from same to0 message
/// ]
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct To1dBlob<'a> {
    pub(crate) to1d_rv: RvTo2Addr<'a>,
    pub(crate) to1d_to0d_hash: Hash<'a>,
}

impl<'a> To1dBlob<'a> {
    /// Returns the address.
    pub fn take_to1d_rv(self) -> RvTo2Addr<'a> {
        self.to1d_rv
    }
}

impl Serialize for To1dBlob<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            to1d_rv,
            to1d_to0d_hash,
        } = self;

        (to1d_rv, to1d_to0d_hash).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for To1dBlob<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (to1d_rv, to1d_to0d_hash) = Deserialize::deserialize(deserializer)?;

        Ok(Self {
            to1d_rv,
            to1d_to0d_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use coset::{CoseSign1Builder, HeaderBuilder};
    use pretty_assertions::assert_eq;

    use crate::tests::insta_settings;
    use crate::v101::hash_hmac::tests::create_hash;
    use crate::v101::ownership_voucher::tests::ECC_SIGNATURE;
    use crate::v101::rv_to2_addr::RvTo2AddrEntry;

    use super::*;

    fn create_to1d() -> (To1dBlob<'static>, CoseSign1) {
        let to1d_rv = RvTo2Addr::new(vec![RvTo2AddrEntry {
            rv_ip: None,
            rv_dns: Some("example.com".into()),
            rv_port: 80,
            rv_protocol: crate::v101::TransportProtocol::Http,
        }])
        .unwrap();

        let to1d = To1dBlob {
            to1d_rv,
            to1d_to0d_hash: create_hash(),
        };

        let mut buf = Vec::new();

        ciborium::into_writer(&to1d, &mut buf).unwrap();

        let sign = CoseSign1Builder::new()
            .protected(
                HeaderBuilder::new()
                    .algorithm(coset::iana::Algorithm::PS256)
                    .build(),
            )
            .payload(buf)
            .signature(ECC_SIGNATURE.to_vec())
            .build();

        (to1d, sign)
    }

    #[test]
    fn rv_redirect_roundtrip() {
        let (_to1d, sign) = create_to1d();

        let rv_redirect = RvRedirect { to1d: sign };

        let mut buf = Vec::new();

        rv_redirect.encode(&mut buf).unwrap();

        let mut res = RvRedirect::decode(&buf).unwrap();

        res.to1d.protected.original_data.take();

        assert_eq!(res, rv_redirect);

        insta_settings!({
            insta::assert_binary_snapshot!(".cbor", buf);
        });
    }

    #[test]
    fn rv_redirect_to1d() {
        let (to1d, sign) = create_to1d();

        let rv_redirect = RvRedirect { to1d: sign.clone() };

        let res = rv_redirect.to1d();

        assert_eq!(*res, sign);

        let res = rv_redirect.rv_to2_addr().unwrap();

        assert_eq!(res, to1d);

        let res = res.take_to1d_rv();

        assert_eq!(res, to1d.to1d_rv);
    }
}
