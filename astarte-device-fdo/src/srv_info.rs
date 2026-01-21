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

//! Modules to read Service Info

use std::borrow::Cow;

use astarte_fdo_protocol::Error;
use astarte_fdo_protocol::error::ErrorKind;
use astarte_fdo_protocol::v101::service_info::ServiceInfoKv;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize, Serializer};
use tracing::{error, trace, warn};
use url::Url;

/// Decodes the service info into a value used by the Device.
pub trait ServiceInfoDecode<'a> {
    /// The decoder that will consume and parse the service info.
    type Output: Serialize + DeserializeOwned + Sized;

    /// Decodes a single [`ServiceInfoKv`].
    fn reset(&mut self) -> Result<(), Error>;

    /// Decodes a single [`ServiceInfoKv`].
    fn decode(&mut self, service_info: &ServiceInfoKv<'a>) -> Result<(), Error>;

    /// Consume self and validates and returns the value.
    fn finalize(&mut self) -> Result<Self::Output, Error>;
}

/// Skips the service info.
///
/// Used as a default implementation for [`ServiceInfoDecode`].
#[derive(Debug, Default)]
pub struct SkipServiceInfo {}

impl<'a> ServiceInfoDecode<'a> for SkipServiceInfo {
    type Output = ();

    fn decode(&mut self, service_info: &ServiceInfoKv<'a>) -> Result<(), Error> {
        trace!(key = %service_info.key());

        Ok(())
    }

    fn finalize(&mut self) -> Result<Self::Output, Error> {
        Ok(())
    }

    fn reset(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

/// Astarte service info.
///
///
/// The `astarte` module is sent from the server to the device to permit communication with astarte.
///
/// | Module name        | Disposition | CBOR type                       | Meaning / Action                                                                                               |
/// | ------------------ | ----------- | ------------------------------- | -------------------------------------------------------------------------------------------------------------- |
/// | astarte:active     | Required    | bool (True)                     | Indicates the module is active.                                                                                |
/// | astarte:realm      | Required    | tstr                            | Owner's Astarte realm the device belongs too. (e.g. test)                                                      |
/// | astarte:secret     | Required    | tstr                            | Credential secret to create a X509 Certificate to use for mTLS to comunicate with the MQTT broker.             |
/// | astarte:baseurl    | Required    | tstr                            | Base URL for the where Astarte Pairing API can be found to. (e.g. `http://api.astarte.localhost`)              |
/// | astarte:deviceid   | Required    | tstr                            | ID of the device in Astarte, this can be generated starting from the `devmod:sn` (e.g. 2TBn-jNESuuHamE2Zo1anA) |
/// | astarte:nummodules | Required    | uint                            | See `devmod:nummodules`                                                                                        |
/// | astarte:modules    | Required    | [uint, uint, tstr1, tstr2, ...] | See `devmod:modules`                                                                                           |
#[derive(Debug, Clone, PartialEq)]
pub struct AstarteMod<'a> {
    /// Owner's Astarte realm the device belongs too. (e.g. `test`)
    pub realm: Cow<'a, str>,
    /// Credential secret to create a X509 Certificate to use for mTLS to comunicate with the MQTT broker.
    pub secret: Cow<'a, str>,
    /// Base URL for the where Astarte Pairing API can be found to. (e.g. `http://api.astarte.localhost`)
    pub base_url: Cow<'a, str>,
    /// ID of the device in Astarte, this can be generated starting from the `devmod:sn` (e.g. 2TBn-jNESuuHamE2Zo1anA)
    pub device_id: Cow<'a, str>,
}

impl<'a> AstarteMod<'a> {
    /// Returns the Astarte mod builder
    pub fn builder() -> AstarteModBuilder<'a> {
        AstarteModBuilder::default()
    }
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
pub struct AstarteModBuilder<'a> {
    active: Option<bool>,
    realm: Option<Cow<'a, str>>,
    secret: Option<Cow<'a, str>>,
    base_url: Option<Cow<'a, str>>,
    device_id: Option<Cow<'a, str>>,
}

impl<'a> AstarteModBuilder<'a> {
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

    fn active(&mut self, info: &ServiceInfoKv<'a>) -> Result<(), Error> {
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

    fn realm(&mut self, info: &ServiceInfoKv<'a>) -> Result<(), Error> {
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

    fn secret(&mut self, info: &ServiceInfoKv<'a>) -> Result<(), Error> {
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

    fn base_url(&mut self, info: &ServiceInfoKv<'a>) -> Result<(), Error> {
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

    fn device_id(&mut self, info: &ServiceInfoKv<'a>) -> Result<(), Error> {
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

impl<'a> ServiceInfoDecode<'a> for AstarteModBuilder<'a> {
    type Output = AstarteMod<'a>;

    fn decode(&mut self, service_info: &ServiceInfoKv<'a>) -> Result<(), Error> {
        let is_astarte = service_info.key().starts_with("astarte:");

        if !is_astarte {
            trace!(key = service_info.key(), "skipping non astarte key");

            return Ok(());
        }

        match service_info.key() {
            "astarte:active" => self.active(service_info)?,
            "astarte:realm" => self.realm(service_info)?,
            "astarte:secret" => self.secret(service_info)?,
            "astarte:baseurl" => self.base_url(service_info)?,
            "astarte:deviceid" => self.device_id(service_info)?,
            key => {
                warn!(key, "unhandled astarte mod key")
            }
        }

        Ok(())
    }

    fn finalize(&mut self) -> Result<Self::Output, Error> {
        let this = std::mem::take(self);

        this.build()
    }

    fn reset(&mut self) -> Result<(), Error> {
        let Self {
            active,
            realm,
            secret,
            base_url,
            device_id,
        } = self;

        active.take();
        realm.take();
        secret.take();
        base_url.take();
        device_id.take();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use coset::CborSerializable;
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn should_decode_astarte_service_info() {
        let active = ciborium::Value::Bool(true).to_vec().unwrap();
        let realm = ciborium::Value::Text("realm".to_string()).to_vec().unwrap();
        let secret = ciborium::Value::Text("secret".to_string())
            .to_vec()
            .unwrap();
        let baseurl = ciborium::Value::Text("http://api.astarte.localhost".to_string())
            .to_vec()
            .unwrap();
        let deviceid = ciborium::Value::Text("P_5k8T1SQ3KHgpFoDFozmA".to_string())
            .to_vec()
            .unwrap();

        let service_info = [
            ServiceInfoKv::new("astarte:active", &active),
            ServiceInfoKv::new("astarte:realm", &realm),
            ServiceInfoKv::new("astarte:secret", &secret),
            ServiceInfoKv::new("astarte:baseurl", &baseurl),
            ServiceInfoKv::new("astarte:deviceid", &deviceid),
        ];

        let mut builder = AstarteMod::builder();

        for i in service_info.iter() {
            builder.decode(i).unwrap();
        }

        let module = builder.finalize().unwrap();

        let exp = AstarteMod {
            realm: "realm".into(),
            secret: "secret".into(),
            base_url: "http://api.astarte.localhost".into(),
            device_id: "P_5k8T1SQ3KHgpFoDFozmA".into(),
        };
        assert_eq!(module, exp);
    }
}
