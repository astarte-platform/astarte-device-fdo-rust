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

//! Transfer Ownership Protocol 1 (TO1).
//!
//! Transfer Ownership Protocol 1 (TO1) finishes the rendezvous started between the New Owner and
//! the Rendezvous Server in the Transfer Ownership Protocol 0 (TO0). In this protocol, the Device
//! ROE communicates with the Rendezvous Server and obtains the IP addressing info for the
//! prospective new Owner. Then the Device may establish trust with the new Owner by connecting to
//! it, using the TO2 Protocol.

pub mod hello_rv;
pub mod hello_rv_ack;
pub mod prove_to_rv;
pub mod rv_redirect;
