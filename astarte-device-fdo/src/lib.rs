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
// TODO: remove
#![allow(dead_code)]

//! FIDO Device Onboarding protocol implementation

pub mod client;
pub mod crypto;
pub mod storage;

pub mod di;

#[derive(Debug)]
struct Ctx<'a, C, S> {
    crypto: &'a mut C,
    storage: &'a mut S,
}
