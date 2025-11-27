// This file is part of Astarte.
//
// Copyright 2025 SECO Mind Srl
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

//! Modules to read Service Info

use std::borrow::Cow;

use astarte_fdo_protocol::error::ErrorKind;
use astarte_fdo_protocol::v101::service_info::{ServiceInfo, ServiceInfoKv};
use astarte_fdo_protocol::Error;
use serde::{Deserialize, Serialize, Serializer};
use tracing::{debug, error, warn};
use url::Url;

/// Astarte service info.
///
///
/// The `astarte` module is sent from the server to the device to permit communication with astarte.
///
/// | Module name        | Disposition | CBOR type                       | Meaning / Action                                                                                               |
/// | ------------------ | ----------- | ------------------------------- | -------------------------------------------------------------------------------------------------------------- |
/// | astarte:active     | Required    | bool (True)                     | Indicates the module is active.                                                                                |
/// | astarte:realm      | Required    | tstr                            | Owner's Astarte realm the device belongs too. (e.g. test)                                                      |
/// | astarte:secret     | Required    | tstr                            | Credential secret to create a X509 Certificate to use for mTLS to comunicate with the MQTT broker.              |
/// | astarte:baseurl    | Required    | tstr                            | Base URL for the where Astarte Pairing API can be found to. (e.g. `http://api.astarte.localhost)                |
/// | astarte:deviceid   | Required    | tstr                            | ID of the device in Astarte, this can be generated starting from the `devmod:sn` (e.g. 2TBn-jNESuuHamE2Zo1anA) |
/// | astarte:nummodules | Required    | uint                            | See `devmod:nummodules`                                                                                        |
/// | astarte:modules    | Required    | [uint, uint, tstr1, tstr2, ...] | See `devmod:modules`                                                                                           |
#[derive(Debug, Clone, PartialEq)]
pub struct AstarteMod<'a> {
    /// Owner's Astarte realm the device belongs too. (e.g. `test`)
    pub realm: Cow<'a, str>,
    /// Credential secret to create a X509 Certificate to use for mTLS to comunicate with the MQTT broker.
    pub secret: Cow<'a, str>,
    /// Base URL for the where Astarte Pairing API can be found to. (e.g. http://api.astarte.localhost)
    pub base_url: Cow<'a, str>,
    /// ID of the device in Astarte, this can be generated starting from the `devmod:sn` (e.g. 2TBn-jNESuuHamE2Zo1anA)
    pub device_id: Cow<'a, str>,
}

impl Serialize for AstarteMod<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let Self {
            realm,
            secret,
            base_url,
            device_id,
        } = self;

        (realm, secret, base_url, device_id).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AstarteMod<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (realm, secret, base_url, device_id) = Deserialize::deserialize(deserializer)?;

        Ok(Self {
            realm,
            secret,
            base_url,
            device_id,
        })
    }
}

/// Builder for the [`AstarteMod`]
#[derive(Default)]
pub(crate) struct AstarteModBuilder<'a> {
    active: Option<bool>,
    realm: Option<Cow<'a, str>>,
    secret: Option<Cow<'a, str>>,
    base_url: Option<Cow<'a, str>>,
    device_id: Option<Cow<'a, str>>,
}

impl<'a> AstarteModBuilder<'a> {
    /// Reads multiple ServiceInfo
    pub(crate) fn read(&mut self, iter: ServiceInfo<'a>) -> Result<(), Error> {
        let iter = iter.into_iter().filter(|i| {
            let is_astarte = i.key().starts_with("astarte:");

            if !is_astarte {
                debug!(key = i.key(), "skipping non astarte key");
            }

            is_astarte
        });

        for info in iter {
            match info.key() {
                "astarte:active" => self.active(info)?,
                "astarte:realm" => self.realm(info)?,
                "astarte:secret" => self.secret(info)?,
                "astarte:baseurl" => self.base_url(info)?,
                "astarte:deviceid" => self.device_id(info)?,
                key => {
                    warn!(key, "unhandled astarte mod key")
                }
            }
        }

        Ok(())
    }

    pub(crate) fn build(self) -> Result<AstarteMod<'a>, Error> {
        if self.active != Some(true) {
            error!("active flag is unset");
        }

        if self.realm.is_none() {
            error!("realm is unsetset");
        }

        if self.secret.is_none() {
            error!("secret is unsetset");
        }

        if self.base_url.is_none() {
            error!("base_url is not set");
        }

        if self.device_id.is_none() {
            error!("device is not set");
        }

        self.build_astarte().ok_or(Error::new(
            ErrorKind::Invalid,
            "astarte service info module",
        ))
    }

    fn build_astarte(self) -> Option<AstarteMod<'a>> {
        if self.active != Some(true) {
            return None;
        }

        Some(AstarteMod {
            realm: self.realm?,
            secret: self.secret?,
            base_url: self.base_url?,
            device_id: self.device_id?,
        })
    }

    fn active(&mut self, info: ServiceInfoKv<'a>) -> Result<(), Error> {
        debug_assert_eq!(info.key(), "astarte:active");

        let active = info.value::<bool>()?;

        if self.active.replace(active).is_some_and(|old| old != active) {
            return Err(Error::new(
                ErrorKind::Invalid,
                "service info active replaced",
            ));
        }

        Ok(())
    }

    fn realm(&mut self, info: ServiceInfoKv<'a>) -> Result<(), Error> {
        debug_assert_eq!(info.key(), "astarte:realm");

        let realm = info.value::<Cow<'a, str>>()?;

        if let Some(old) = self.realm.replace(realm) {
            error!(%old, "multiple astarte realms");

            return Err(Error::new(
                ErrorKind::Invalid,
                "service info realm replaced",
            ));
        }

        Ok(())
    }

    fn secret(&mut self, info: ServiceInfoKv<'a>) -> Result<(), Error> {
        debug_assert_eq!(info.key(), "astarte:secret");

        let secret = info.value::<Cow<'a, str>>()?;

        if let Some(old) = self.secret.replace(secret) {
            error!(%old, "multiple astarte secrets");

            return Err(Error::new(
                ErrorKind::Invalid,
                "service info secret replaced",
            ));
        }

        Ok(())
    }

    fn base_url(&mut self, info: ServiceInfoKv<'a>) -> Result<(), Error> {
        debug_assert_eq!(info.key(), "astarte:baseurl");

        let base_url = info.value::<Cow<'a, str>>()?;

        debug_assert!(Url::parse(&base_url).is_ok());

        if let Some(old) = self.base_url.replace(base_url) {
            error!(%old, "multiple astarte base urls");

            return Err(Error::new(
                ErrorKind::Invalid,
                "service info base url replaced",
            ));
        }

        Ok(())
    }

    fn device_id(&mut self, info: ServiceInfoKv<'a>) -> Result<(), Error> {
        debug_assert_eq!(info.key(), "astarte:deviceid");

        let device_id = info.value::<Cow<'a, str>>()?;

        if let Some(old) = self.device_id.replace(device_id) {
            error!(%old, "multiple astarte device id");

            return Err(Error::new(
                ErrorKind::Invalid,
                "service info device id replaced",
            ));
        }

        Ok(())
    }
}
