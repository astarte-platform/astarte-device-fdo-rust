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

//! Device Initialize Protocol (DI)
//!
//! The protocol’s function is to embed the ownership and manufacturing credentials into the newly
//! created device’s ROE. This prepares the device and establishes the first in a chain for creating
//! an Ownership Voucher with which to transfer ownership of the device.

use std::borrow::Cow;

use astarte_fdo_protocol::error::ErrorKind;
use astarte_fdo_protocol::v101::device_credentials::DeviceCredential;
use astarte_fdo_protocol::v101::di::app_start::AppStart;
use astarte_fdo_protocol::v101::di::custom::MfgInfo;
use astarte_fdo_protocol::v101::di::done::Done;
use astarte_fdo_protocol::v101::di::set_credentials::SetCredentials;
use astarte_fdo_protocol::v101::di::set_hmac::SetHmac;
use astarte_fdo_protocol::v101::hash_hmac::{HMac, Hash};
use astarte_fdo_protocol::v101::PROTOCOL_VERSION;
use astarte_fdo_protocol::Error;
use coset::{CoseEncrypt0, TaggedCborSerializable};
use reqwest::header::HeaderValue;
use serde_bytes::ByteBuf;
use tracing::{debug, error, info};

use crate::client::{Client, NeedsAuth};
use crate::crypto::Crypto;
use crate::storage::Storage;
use crate::Ctx;

pub(crate) const DEVICE_CREDS: &str = "device_creds.cbor";

/// Di protocol.
pub struct Di<T, A = HeaderValue> {
    client: Client<A>,
    state: T,
}

impl<'a> Di<Start<'a>, NeedsAuth> {
    /// Create the client to start the Di protocol
    pub async fn create<C, S>(
        ctx: &mut Ctx<'_, C, S>,
        client: Client<NeedsAuth>,
        model_no: &'a str,
        serial_no: &'a str,
    ) -> Result<Self, Error>
    where
        C: Crypto,
    {
        let csr = ctx.crypto.csr(model_no).await?;

        let device_mfg_info = MfgInfo::new(
            ctx.crypto.pk_type(),
            C::PK_ENC,
            Cow::Owned(csr.into()),
            serial_no.into(),
            model_no.into(),
        );

        Ok(Self {
            client,
            state: Start {
                device_info: AppStart::new(device_mfg_info),
            },
        })
    }

    /// Create the device credentials
    pub async fn create_credentials<C, S>(
        self,
        ctx: &mut Ctx<'_, C, S>,
    ) -> Result<DeviceCredential<'static>, Error>
    where
        C: Crypto,
        S: Storage,
    {
        debug!(device_info = ?self.state.device_info);

        if let Some(done) = Self::read_existing(ctx).await? {
            return Ok(done);
        }

        debug!("credentials not found, running device initialization");

        let set_creds = self.run().await?;

        let set_hmac = set_creds.run(ctx).await?;

        let dc = set_hmac.run(ctx).await?;

        Ok(dc)
    }

    /// Reads the existing credentials if they exists.
    pub async fn read_existing<C, S>(
        ctx: &mut Ctx<'_, C, S>,
    ) -> Result<Option<DeviceCredential<'static>>, Error>
    where
        S: Storage,
    {
        let Some(creds) = ctx.storage.read(DEVICE_CREDS).await? else {
            return Ok(None);
        };

        let device_credentials: DeviceCredential =
            ciborium::from_reader(std::io::Cursor::new(creds)).map_err(|err| {
                error!(error = %err, "couldn't decode device credentials");

                Error::new(ErrorKind::Decode, "device credentials")
            })?;

        info!("retrieved existing device credentials");

        Ok(Some(device_credentials))
    }
}

/// Start state of the FDO protocol
pub struct Start<'a> {
    device_info: AppStart<'a, MfgInfo<'a>>,
}

impl<'a> Di<Start<'a>, NeedsAuth> {
    async fn run(mut self) -> Result<Di<Credentials>, Error> {
        let (set_creds, auth) = self.client.init(&self.state.device_info).await?;

        info!("DI.AppStart successful");

        Ok(Di {
            client: self.client.set_auth(auth),
            state: Credentials::new(set_creds),
        })
    }
}

pub(crate) struct Credentials {
    creds: SetCredentials<'static>,
}
impl Credentials {
    fn new(set_creds: SetCredentials<'static>) -> Self {
        Self { creds: set_creds }
    }
}

impl Di<Credentials> {
    async fn run<C, S>(mut self, ctx: &mut Ctx<'_, C, S>) -> Result<Di<Hmac>, Error>
    where
        C: Crypto,
    {
        let hash = self.owner_key_hash(ctx)?;

        let hmac_secret = ctx.crypto.hmac_secret().await?;

        let hmac = self.ov_header_hmac(ctx, &hmac_secret).await?;

        let ov_header = self.state.creds.ov_header;

        info!(guid = %ov_header.ov_guid);

        let tagged_vec = hmac_secret.to_tagged_vec().map_err(|err| {
            error!(error = %err, "couldn't encode hamc secret");

            Error::new(ErrorKind::Encode, "hamc secret")
        })?;

        let device_creds = DeviceCredential {
            dc_active: true,
            dc_prot_ver: PROTOCOL_VERSION,
            dc_hmac_secret: Cow::Owned(ByteBuf::from(tagged_vec)),
            dc_device_info: ov_header.ov_device_info.clone(),
            dc_guid: ov_header.ov_guid,
            dc_rv_info: ov_header.ov_rv_info.clone(),
            dc_pub_key_hash: hash,
        };

        info!("DI.SetCredentials successful");

        Ok(Di {
            client: self.client,
            state: Hmac {
                hmac: SetHmac { hmac },
                device_creds,
            },
        })
    }

    fn owner_key_hash<C, S>(&mut self, ctx: &mut Ctx<'_, C, S>) -> Result<Hash<'static>, Error>
    where
        C: Crypto,
    {
        let mut buf = Vec::new();

        ciborium::into_writer(&self.state.creds.ov_header.ov_pub_key, &mut buf).map_err(|err| {
            error!(error = %err, "couldn't encode ov public key");

            Error::new(ErrorKind::Encode, "ov public key")
        })?;

        let dc_pub_key_hash = ctx.crypto.hash(&buf)?;

        Ok(dc_pub_key_hash)
    }

    async fn ov_header_hmac<C, S>(
        &mut self,
        ctx: &mut Ctx<'_, C, S>,
        hmac_secret: &CoseEncrypt0,
    ) -> Result<HMac<'static>, Error>
    where
        C: Crypto,
    {
        let data = self.state.creds.ov_header.bytes()?;

        let hmac = ctx.crypto.hmac(hmac_secret, data).await?;

        Ok(hmac)
    }
}

pub(crate) struct Hmac {
    hmac: SetHmac<'static>,
    device_creds: DeviceCredential<'static>,
}

impl Di<Hmac> {
    async fn run<C, S>(
        mut self,
        ctx: &mut Ctx<'_, C, S>,
    ) -> Result<DeviceCredential<'static>, Error>
    where
        S: Storage,
    {
        let Done {} = self.client.send_msg(&self.state.hmac).await?;

        info!("DI.SetMac successfully");

        // TODO: separate store credentials
        let mut buf = Vec::new();
        ciborium::into_writer(&self.state.device_creds, &mut buf).map_err(|err| {
            error!(error = %err, "couldn't encode device credentials");

            Error::new(ErrorKind::Encode, "device credentials")
        })?;

        ctx.storage.write(DEVICE_CREDS, &buf).await?;

        info!("DI.Done successfully");

        Ok(self.state.device_creds)
    }
}
