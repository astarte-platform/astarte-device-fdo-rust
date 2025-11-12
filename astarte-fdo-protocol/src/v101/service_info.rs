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

use serde::{Deserialize, Serialize};

use crate::utils::CborBstr;

pub(crate) type ServiceInfo<'a> = Vec<ServiceInfoKv<'a>>;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ServiceInfoKv<'a> {
    pub(crate) service_info_key: Cow<'a, str>,
    // TODO: make generic
    pub(crate) service_info_val: CborBstr<'a, ciborium::Value>,
}

impl Serialize for ServiceInfoKv<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            service_info_key,
            service_info_val,
        } = self;

        (service_info_key, service_info_val).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ServiceInfoKv<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (service_info_key, service_info_val) = Deserialize::deserialize(deserializer)?;

        Ok(Self {
            service_info_key,
            service_info_val,
        })
    }
}
