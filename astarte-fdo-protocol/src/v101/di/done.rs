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

use std::io::Write;

use serde::{Deserialize, Serialize};

use crate::error::ErrorKind;
use crate::v101::{Message, Msgtype};
use crate::Error;

/// Indicates successful completion of the DI protocol.
///
/// ```cddl
/// DI.Done = [] ;; empty message
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Done;

impl Serialize for Done {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {} = self;

        const EMPTY: [ciborium::Value; 0] = [];

        EMPTY.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Done {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let []: [ciborium::Value; 0] = Deserialize::deserialize(deserializer)?;

        Ok(Self {})
    }
}

impl Message for Done {
    const MSG_TYPE: Msgtype = 13;

    fn decode(buf: &[u8]) -> Result<Self, Error> {
        let this = ciborium::from_reader(buf).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't decode DI.Done");

            Error::new(ErrorKind::Decode, "the DI.Done")
        })?;

        Ok(this)
    }

    fn encode<W>(&self, write: &mut W) -> Result<(), Error>
    where
        W: Write,
    {
        ciborium::into_writer(self, write).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't encode DI.Done");

            Error::new(ErrorKind::Encode, "the DI.Done")
        })
    }
}
