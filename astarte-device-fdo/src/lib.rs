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

#![warn(missing_docs, rustdoc::missing_crate_level_docs)]

//! FIDO Device Onboarding protocol implementation

pub mod client;
pub mod crypto;
pub mod storage;

pub mod di;
pub mod to1;
pub mod to2;

pub use astarte_fdo_protocol;
pub use rustls;
pub use url;

pub use self::crypto::Crypto;
pub use self::storage::Storage;

/// Context for the FDO protocol
#[derive(Debug)]
pub struct Ctx<'a, C, S> {
    crypto: &'a mut C,
    storage: &'a mut S,
    tls: rustls::ClientConfig,
}

impl<'a, C, S> Ctx<'a, C, S> {
    /// Creates a new context.
    pub fn new(crypto: &'a mut C, storage: &'a mut S, tls: rustls::ClientConfig) -> Self
    where
        C: Crypto,
        S: Storage,
    {
        Self {
            crypto,
            storage,
            tls,
        }
    }

    /// Returns the TLS config
    pub fn tls(&self) -> &rustls::ClientConfig {
        &self.tls
    }
}
