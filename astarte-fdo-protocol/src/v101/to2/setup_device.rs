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

//! Setup Device, Type 65
//!
//! From Owner Onboarding Service to Device ROE
//!
//! Message Format - after decryption and verification:
//!
//! ```cddl
//! TO2.SetupDevice = CoseSignature
//! TO2SetupDevicePayload = [
//!     RendezvousInfo, ;; RendezvousInfo replacement
//!     Guid,           ;; GUID replacement
//!     NonceTO2SetupDv,         ;; proves freshness of signature
//!     Owner2Key       ;; Replacement for Owner key
//! ]
//! Owner2Key = PublicKey
//!
//! $COSEPayloads /= (
//!     TO2SetupDevicePayload
//! )
//! ```
//!
//! This message prepares for ownership transfer, where the credentials previously used to take over
//! the device are replaced, based on the new credentials downloaded from the Owner Onboarding
//! Service. These credentials were: previously programmed by the DI protocol; programmed using
//! another technique from the DI protocol; or previously updated by this message.

use std::io::Write;

use coset::{CoseSign1, TaggedCborSerializable};
use serde::{Deserialize, Serialize};

use crate::error::ErrorKind;
use crate::v101::public_key::PublicKey;
use crate::v101::rendezvous_info::RendezvousInfo;
use crate::v101::{Guid, Message, Msgtype, NonceTo2SetupDv};
use crate::Error;

/// ```cddl
/// ;; This message replaces previous FIDO Device Onboard credentials with new ones
/// ;; Note that this signature is signed with a new (Owner2) key
/// ;; which is transmitted in this same message.
/// ;; The entire message is also verified by the integrity of the
/// ;; transmission medium.
/// TO2.SetupDevice = CoseSignature
/// TO2SetupDevicePayload = [
///     RendezvousInfo, ;; RendezvousInfo replacement
///     Guid,           ;; GUID replacement
///     NonceTO2SetupDv,         ;; proves freshness of signature
///     Owner2Key       ;; Replacement for Owner key
/// ]
/// Owner2Key = PublicKey
///
/// $COSEPayloads /= (
///     TO2SetupDevicePayload
/// )
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct SetupDevice {
    pub(crate) sign: CoseSign1,
}

impl SetupDevice {
    /// Return the Cose signature
    pub fn sign(&self) -> &CoseSign1 {
        &self.sign
    }

    /// Decodes the COSE payload.
    pub fn payload(&self) -> Result<SetupDevicePayload<'static>, Error> {
        let payload = self.sign.payload.as_deref().ok_or(Error::new(
            ErrorKind::Invalid,
            "the TO2.SetupDevice payload is missing",
        ))?;

        ciborium::from_reader(payload).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error =%err, "couldn't decode TO2.SetupDevice payload");

            Error::new(ErrorKind::Decode, "the TO2.SetupDevice payload")
        })
    }
}

impl Message for SetupDevice {
    const MSG_TYPE: Msgtype = 65;

    fn decode(buf: &[u8]) -> Result<Self, Error> {
        let sign = CoseSign1::from_tagged_slice(buf).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error =%err, "couldn't decode TO2.SetupDevice");

            Error::new(ErrorKind::Decode, "the TO2.SetupDevice")
        })?;

        if sign.payload.is_none() {
            return Err(Error::new(
                ErrorKind::Invalid,
                "the TO2.SetupDevice payload is missing",
            ));
        }

        Ok(SetupDevice { sign })
    }

    fn encode<W>(&self, write: &mut W) -> Result<(), Error>
    where
        W: Write,
    {
        self.sign
            .clone()
            .to_tagged_vec()
            .map_err(|err| {
                #[cfg(feature = "tracing")]
                tracing::error!(error =%err, "couldn't encode TO2.SetupDevice");

                Error::new(ErrorKind::Encode, "the TO2.SetupDevice")
            })
            .and_then(|buf| {
                write.write_all(&buf).map_err(|err| {
                    #[cfg(feature = "tracing")]
                    tracing::error!(error =%err, "couldn't write TO2.SetupDevice");

                    Error::new(ErrorKind::Write, "the TO2.SetupDevice")
                })
            })
    }
}

/// ```cddl
/// TO2SetupDevicePayload = [
///     RendezvousInfo, ;; RendezvousInfo replacement
///     Guid,           ;; GUID replacement
///     NonceTO2SetupDv,         ;; proves freshness of signature
///     Owner2Key       ;; Replacement for Owner key
/// ]
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct SetupDevicePayload<'a> {
    pub(crate) rendezvous_info: RendezvousInfo<'a>,
    pub(crate) guid: Guid,
    pub(crate) nonce_to2_setup_dv: NonceTo2SetupDv,
    pub(crate) owner_2_key: PublicKey<'a>,
}

impl<'a> SetupDevicePayload<'a> {
    /// Return the owner replacement key
    pub fn ow_pubkey(&self) -> &PublicKey<'a> {
        &self.owner_2_key
    }

    /// Return the setup device Nonce
    pub fn nonce(&self) -> &NonceTo2SetupDv {
        &self.nonce_to2_setup_dv
    }
}

impl Serialize for SetupDevicePayload<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            rendezvous_info,
            guid,
            nonce_to2_setup_dv,
            owner_2_key,
        } = self;

        (rendezvous_info, guid, nonce_to2_setup_dv, owner_2_key).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SetupDevicePayload<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (rendezvous_info, guid, nonce_to2_setup_dv, owner_2_key) =
            Deserialize::deserialize(deserializer)?;

        Ok(Self {
            rendezvous_info,
            guid,
            nonce_to2_setup_dv,
            owner_2_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
    use pretty_assertions::assert_eq;

    use crate::v101::ownership_voucher::tests::ECC_SIGNATURE;
    use crate::v101::public_key::tests::PUB_KEY_ECC;
    use crate::v101::public_key::{PkBody, PkEnc, PkType};
    use crate::v101::rendezvous_info::{RendezvousDirective, RendezvousInstr};
    use crate::v101::tests::create_guid;
    use crate::v101::Nonce;

    use super::*;

    fn create_setup_device(payload: SetupDevicePayload) -> SetupDevice {
        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf).unwrap();

        let sign = CoseSign1Builder::new()
            .protected(
                HeaderBuilder::new()
                    .algorithm(coset::iana::Algorithm::PS256)
                    .build(),
            )
            .payload(buf)
            .signature(ECC_SIGNATURE.to_vec())
            .build();

        SetupDevice { sign }
    }

    fn create_setup_device_payload() -> SetupDevicePayload<'static> {
        let nonce = Nonce::from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let pub_k = PublicKey {
            pk_type: PkType::Secp256R1,
            pk_enc: PkEnc::X509,
            pk_body: PkBody::X509(Cow::Borrowed(serde_bytes::Bytes::new(PUB_KEY_ECC))),
        };
        let instr = RendezvousInstr {
            rv_variable: crate::v101::rendezvous_info::RvVariable::DevOnly,
            rv_value: Cow::Owned(serde_bytes::ByteBuf::from(
                ciborium::Value::Bool(true).to_vec().unwrap(),
            )),
        };
        let rendezvous_info =
            RendezvousInfo::new(vec![RendezvousDirective::new(vec![instr]).unwrap()]).unwrap();

        SetupDevicePayload {
            rendezvous_info,
            guid: create_guid(),
            nonce_to2_setup_dv: NonceTo2SetupDv(nonce),
            owner_2_key: pub_k,
        }
    }

    #[test]
    fn setup_device_roundtrip() {
        let payload = create_setup_device_payload();
        let setup = create_setup_device(payload);

        let mut buf = Vec::new();

        setup.encode(&mut buf).unwrap();

        let mut res = SetupDevice::decode(&buf).unwrap();
        res.sign.protected.original_data.take();

        assert_eq!(res, setup);

        insta::assert_binary_snapshot!(".cbor", buf);
    }

    #[test]
    fn setup_device_methods() {
        let payload = create_setup_device_payload();
        let setup = create_setup_device(payload.clone());

        assert_eq!(*setup.sign(), setup.sign);

        assert_eq!(setup.payload().unwrap(), payload);
    }
}
