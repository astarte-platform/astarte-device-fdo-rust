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

//! Proves validity of device identity to the Rendezvous Server.
//!
//! For the Device seeking its owner, and indicates its GUID.

use std::io::Write;

use coset::{CoseSign1, TaggedCborSerializable};

use crate::error::ErrorKind;
use crate::v101::{ClientMessage, Message, Msgtype};
use crate::Error;

use super::rv_redirect::RvRedirect;

/// ```cddl
/// TO1.ProveToRV = EAToken
/// $$EATPayloadBase //= (
///     EAT-NONCE: NonceTO1Proof
/// )
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct ProveToRv {
    pub(crate) ea_token: CoseSign1,
}

impl ProveToRv {
    /// Create a ProveToRv from an EAT
    pub fn new(ea_token: CoseSign1) -> Self {
        Self { ea_token }
    }
}

impl Message for ProveToRv {
    const MSG_TYPE: Msgtype = 32;

    fn decode(buf: &[u8]) -> Result<Self, Error> {
        // TODO: probably some validation is required here
        CoseSign1::from_tagged_slice(buf)
            .map(|ea_token| Self { ea_token })
            .map_err(|err| {
                #[cfg(feature = "tracing")]
                tracing::error!(error = %err, "couldn't decode TO1.ProveToRv");

                Error::new(ErrorKind::Decode, "the TO1.ProveToRv")
            })
    }

    fn encode<W>(&self, write: &mut W) -> Result<(), Error>
    where
        W: Write,
    {
        // TODO: coset requires allocations
        self.ea_token
            .clone()
            .to_tagged_vec()
            .map_err(|err| {
                #[cfg(feature = "tracing")]
                tracing::error!(error = %err, "couldn't encode TO1.ProveToRv");

                Error::new(ErrorKind::Encode, "the TO1.ProveToRv")
            })
            .and_then(|buf| {
                write.write_all(&buf).map_err(|err| {
                    #[cfg(feature = "tracing")]
                    tracing::error!(error = %err, "couldn't write TO1.ProveToRv");

                    Error::new(ErrorKind::Write, "the TO1.ProveToRv")
                })
            })
    }
}

impl ClientMessage for ProveToRv {
    type Response<'a> = RvRedirect;
}

#[cfg(test)]
mod tests {
    use ciborium::Value;
    use coset::{CoseSign1Builder, HeaderBuilder};
    use pretty_assertions::assert_eq;

    use crate::v101::ownership_voucher::tests::ECC_SIGNATURE;

    use super::*;

    #[test]
    fn prove_to_rv_roundtrip() {
        let mut buf = Vec::new();

        ciborium::into_writer(&Value::Bytes([0, 1, 2, 3, 4].to_vec()), &mut buf).unwrap();

        let ea_token = CoseSign1Builder::new()
            .protected(
                HeaderBuilder::new()
                    .algorithm(coset::iana::Algorithm::PS256)
                    .build(),
            )
            .payload(buf)
            .signature(ECC_SIGNATURE.to_vec())
            .build();

        let prove_to_rv = ProveToRv::new(ea_token);

        let mut buf = Vec::new();

        prove_to_rv.encode(&mut buf).unwrap();

        let mut res = ProveToRv::decode(&buf).unwrap();
        res.ea_token.protected.original_data.take();

        assert_eq!(res, prove_to_rv);

        insta::assert_binary_snapshot!(".cbor", buf);
    }
}
