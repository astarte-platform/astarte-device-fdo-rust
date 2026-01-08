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

//! Prove Device, Type 64
//!
//! From Device to Owner Onboarding Service
//!
//! Message Format:
//!
//! ```cddl
//! TO2.ProveDevice = EAToken
//! $$EATPayloadBase //= (
//!     EAT-NONCE: NonceTO2ProveDv
//! )
//! TO2ProveDevicePayload = [
//!     xBKeyExchange
//! ]
//! $EATUnprotectedHeaders /= (
//!     EUPHNonce: NonceTO2SetupDv ;; NonceTO2SetupDv is used in TO2.SetupDevice and TO2.Done2
//! )
//! $EATPayloads /= (
//!     TO2ProveDevicePayload
//! )
//! ```
//!
//! Proves the provenance of the Device to the new owner, using the entity attestation token based
//! on the challenge NonceTO2ProveDv sent as TO2.ProveOVHdr.UnprotectedHeaders.CUPHNonce. The
//! signature is verified using the device certificate chain contained in the Ownership Voucher. If
//! the signature cannot be verified, or fails to verify, the connection is terminated with an error
//! message.
//!
//! Subsequent message bodies are protected for confidentiality and integrity.

use std::io::Write;

use coset::TaggedCborSerializable;

use crate::error::ErrorKind;
use crate::v101::eat_signature::EaToken;
use crate::v101::{ClientMessage, Message, Msgtype};
use crate::Error;

use super::setup_device::SetupDevice;

/// ```cddl
/// TO2.ProveDevice = EAToken
/// $$EATPayloadBase //= (
///     EAT-NONCE: NonceTO2ProveDv
/// )
/// TO2ProveDevicePayload = [
///     xBKeyExchange
/// ]
/// $EATUnprotectedHeaders /= (
///     EUPHNonce: NonceTO2SetupDv ;; NonceTO2SetupDv is used in TO2.SetupDevice and TO2.Done2
/// )
/// $EATPayloads /= (
///     TO2ProveDevicePayload
/// )
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct ProveDevice {
    pub(crate) sign: EaToken,
}

impl ProveDevice {
    /// Create the prove device with the EAT
    pub fn new(sign: EaToken) -> Self {
        Self { sign }
    }
}

impl Message for ProveDevice {
    const MSG_TYPE: Msgtype = 64;

    fn decode(buf: &[u8]) -> Result<Self, Error> {
        EaToken::from_tagged_slice(buf)
            .map(|sign| ProveDevice { sign })
            .map_err(|err| {
                #[cfg(feature = "tracing")]
                tracing::error!(error = %err, "couldn't decode TO2.ProveDevice");

                Error::new(ErrorKind::Decode, "couldn't decode TO2.ProveDevice")
            })
    }

    fn encode<W>(&self, writer: &mut W) -> Result<(), Error>
    where
        W: Write,
    {
        self.sign
            .clone()
            .to_tagged_vec()
            .map_err(|err| {
                #[cfg(feature = "tracing")]
                tracing::error!(error = %err, "couldn't encode TO2.ProveDevice");

                Error::new(ErrorKind::Encode, "couldn't encode TO2.ProveDevice")
            })
            .and_then(|v| {
                writer.write_all(v.as_slice()).map_err(|err| {
                    #[cfg(feature = "tracing")]
                    tracing::error!(error = %err, "couldn't write TO2.ProveDevice");

                    Error::new(ErrorKind::Write, "couldn't write TO2.ProveDevice")
                })
            })
    }
}

impl ClientMessage for ProveDevice {
    type Response<'a> = SetupDevice;
}

#[cfg(test)]
mod tests {
    use ciborium::Value;
    use coset::{CoseSign1Builder, HeaderBuilder};
    use pretty_assertions::assert_eq;

    use crate::v101::ownership_voucher::tests::ECC_SIGNATURE;

    use super::*;

    #[test]
    fn prove_device_roundtrip() {
        let mut buf = Vec::new();

        ciborium::into_writer(&Value::Bytes(b"eat token".to_vec()), &mut buf).unwrap();

        let sign = CoseSign1Builder::new()
            .protected(
                HeaderBuilder::new()
                    .algorithm(coset::iana::Algorithm::PS256)
                    .build(),
            )
            .payload(buf)
            .signature(ECC_SIGNATURE.to_vec())
            .build();

        let info = ProveDevice::new(sign);

        let mut buf = Vec::new();

        info.encode(&mut buf).unwrap();

        let mut res = ProveDevice::decode(&buf).unwrap();
        res.sign.protected.original_data.take();

        assert_eq!(res, info);

        insta::assert_binary_snapshot!(".cbor", buf);
    }
}
