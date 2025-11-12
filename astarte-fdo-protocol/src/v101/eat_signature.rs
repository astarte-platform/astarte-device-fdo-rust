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

//! EAT signatures are used for entity attestation of Devices.

/// ```cddl
/// ;; This is a COSE_Sign1 object:
/// EAToken = #6.18(EATokenBase)
///
/// EATokenBase  = [
///    protected:   bytes .cbor $EATProtectedHeaders,
///    unprotected: $EATUnprotectedHeaders
///    payload:     bytes .cbor EATPayloadBaseMap
///    signature:   bstr
/// ]
/// EATPayloadBaseMap = { EATPayloadBase }
/// $$EATPayloadBase //= (
///     EAT-FDO => $EATPayloads,
///     EAT-NONCE => Nonce,
///     EAT-UEID  => EAT-GUID,
///     EATOtherClaims
/// )
/// ;; EAT claim tags, defined in EAT spec or IANA, see appendix
/// ;; EAT-NONCE
/// ;; EAT-UEID
///
/// ;; FIDO Device Onboard specific EAT claim tag, see appendix
/// ;;EAT-FDO
/// ;;EATMAROEPrefix
/// ;;EUPHNonce
///
/// ;; EAT GUID is a EAT-UEID with the first byte
/// ;; as EAT-RAND and subsequent bytes containing
/// ;; the FIDO Device Onboard GUID
/// EAT-GUID = bstr .size 17
/// EAT-RAND = 1
///
/// ;; Use the socket/plug feature of CBOR here.
/// $$EATProtectedHeaders //= ()
/// $$EATUnprotectedHeaders //= (
///     EATMAROEPrefix: MAROEPrefix
/// )
/// $EATPayloads /= ()
/// ```
pub type EaToken = coset::CoseSign1;

/// ```cddl
/// EAT-NONCE      = 10 ;; iana assignment
/// ```
pub const EAT_NONCE: i64 = 10;

/// ```cddl
/// EAT-UEID       = 256 ;; iana assignment
/// ```
pub const EAT_UEID: i64 = 256;

/// ```cddl
/// EAT-FDO        = -257 ;; iana assignment
/// ```
pub const EAT_FDO: i64 = -257;

/// ```cddl
/// EATMAROEPrefix = -258 ;; iana assignment
/// ```
pub const EATMAROE_PREFIX: i64 = -258;

/// ```cddl
/// EUPHNonce      = -259 ;; iana assignment
/// ```
pub const EUPH_NONCE: i64 = -259;
