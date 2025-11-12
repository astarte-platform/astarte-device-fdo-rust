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

//! Error returned by the protocol.
//!
//! The error message is a “catch-all” whenever processing cannot continue. This includes protocol
//! errors and any trust or security violations.

use std::borrow::Cow;
use std::fmt::Display;
use std::io::Write;

use serde::{Deserialize, Serialize};

use crate::error::ErrorKind;

use super::{Message, Msgtype};

/// The error message indicates that the previous protocol message could not be processed.
// TODO: send error on client errors
#[derive(Debug, Clone, PartialEq)]
pub struct ErrorMessage<'a> {
    // Error code
    e_m_error_code: u16,
    // Message ID (type) of the previous message
    e_m_prev_msg_id: u8,
    // Error string
    e_m_error_str: Cow<'a, str>,
    // UTC timestamp
    // TODO: parse the timestamp
    e_m_error_ts: Option<Timestamp<'a>>,
    // Unique id associated with this request
    e_m_error_c_i_d: Option<u128>,
}

impl<'a> ErrorMessage<'a> {
    /// Creates a new error.
    pub fn new(
        e_m_error_code: ErrorCode,
        e_m_prev_msg_id: u8,
        e_m_error_str: Cow<'a, str>,
        e_m_error_ts: Option<Timestamp<'a>>,
        e_m_error_c_i_d: Option<u128>,
    ) -> Self {
        Self {
            e_m_error_code: e_m_error_code.into(),
            e_m_prev_msg_id,
            e_m_error_str,
            e_m_error_ts,
            e_m_error_c_i_d,
        }
    }

    /// Returns the error code as a number.
    pub fn error_code(&self) -> u16 {
        self.e_m_error_code
    }

    /// Returns the code if it's a known error code.
    pub fn known_code(&self) -> Option<ErrorCode> {
        let code = match self.e_m_error_code {
            1 => ErrorCode::InvalidJwtToken,
            2 => ErrorCode::InvalidOwnershipVoucher,
            3 => ErrorCode::InvalidOwnerSignBody,
            4 => ErrorCode::InvalidIpAddress,
            5 => ErrorCode::InvalidGuid,
            6 => ErrorCode::ResourceNotFound,
            100 => ErrorCode::MessageBodyError,
            101 => ErrorCode::InvalidMessageError,
            102 => ErrorCode::CredReuseError,
            500 => ErrorCode::InternalServerError,
            _ => return None,
        };

        Some(code)
    }
}

impl Display for ErrorMessage<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(code) = self.known_code() {
            write!(f, "error_code: {code}")?;
        } else {
            write!(f, "error_code: {}", self.e_m_error_code)?;
        }

        write!(
            f,
            ", prev_msg_id : {}, error_str: {:?}, error_ts: {:?}, c_i_d: {:?}",
            self.e_m_prev_msg_id, self.e_m_error_str, self.e_m_error_ts, self.e_m_error_c_i_d
        )
    }
}

impl Serialize for ErrorMessage<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            e_m_error_code,
            e_m_prev_msg_id,
            e_m_error_str,
            e_m_error_ts,
            e_m_error_c_i_d,
        } = self;

        let e_m_error_ts = e_m_error_ts.as_ref().map(ciborium::tag::Required::<_, 6>);

        (
            e_m_error_code,
            e_m_prev_msg_id,
            e_m_error_str,
            e_m_error_ts,
            e_m_error_c_i_d,
        )
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ErrorMessage<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (e_m_error_code, e_m_prev_msg_id, e_m_error_str, e_m_error_ts, e_m_error_c_i_d) =
            Deserialize::deserialize(deserializer)?;

        let e_m_error_ts: Option<ciborium::tag::Accepted<Timestamp, 6>> = e_m_error_ts;

        Ok(Self {
            e_m_error_code,
            e_m_prev_msg_id,
            e_m_error_str,
            e_m_error_ts: e_m_error_ts.map(|t| t.0),
            e_m_error_c_i_d,
        })
    }
}

impl Message for ErrorMessage<'_> {
    const MSG_TYPE: Msgtype = 255;

    fn decode(buf: &[u8]) -> Result<Self, crate::Error> {
        ciborium::from_reader(buf).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't decode the ErrorMessage");

            crate::Error::new(ErrorKind::Decode, "the ErrorMessage")
        })
    }

    fn encode<W>(&self, write: &mut W) -> Result<(), crate::Error>
    where
        W: Write,
    {
        ciborium::into_writer(self, write).map_err(|err| {
            #[cfg(feature = "tracing")]
            tracing::error!(error = %err, "couldn't encode the ErrorMessage");

            crate::Error::new(ErrorKind::Encode, "the ErrorMessage")
        })
    }
}

/// The “EMErrorCode” in the ErrorMessage is an error code.
///
/// Please see each variant for detailed information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum ErrorCode {
    /// JWT token is missing or invalid.
    ///
    /// Each token has its own validity period, server rejects expired tokens. Server failed to
    /// parse JWT token or JWT signature did not verify correctly. The JWT token refers to the token
    /// mentioned in section 4.3 (which is not required by protocol to be a JWT token). The
    /// error message applies to non-JWT tokens, as well.
    ///
    /// ## Generated by Message
    ///
    /// - DI.SetHMAC
    /// - TO0.OwnerSign
    /// - TO1.ProveToRV
    /// - TO2.GetOVNextEntry
    /// - TO2.ProveDevice
    /// - TO2.NextDeviceServiceInfo
    /// - TO2.Done
    InvalidJwtToken = 1,
    /// Ownership Voucher is invalid: One of Ownership Voucher verification checks has failed.
    ///
    /// Precise information is not returned to the client but saved only in service logs.
    ///
    /// ## Generated by Message
    ///
    /// - TO0.OwnerSign
    InvalidOwnershipVoucher = 2,
    /// Verification of signature of owner message failed.
    ///
    /// TO0.OwnerSign message is signed by the final owner (using key signed by the last Ownership
    /// Voucher entry). This error is returned in case that signature is invalid.
    ///
    /// ## Generated by Message
    ///
    /// - TO0.OwnerSign
    InvalidOwnerSignBody = 3,
    /// IP address is invalid.
    ///
    /// Bytes that are provided in the request do not represent a valid IPv4/IPv6 address.
    ///
    /// ## Generated by Message
    ///
    /// - TO0.OwnerSign
    InvalidIpAddress = 4,
    /// GUID is invalid.
    ///
    /// Bytes that are provided in the request do not represent a proper GUID.
    ///
    /// ## Generated by Message
    ///
    /// - TO0.OwnerSign
    InvalidGuid = 5,
    /// The owner connection info for GUID is not found.
    ///
    /// TO0 Protocol wasn’t properly executed for the specified GUID or information that was stored
    /// in database has expired and/or has been removed.
    ///
    /// ## Generated by Message
    ///
    /// - TO1.HelloRV
    /// - TO2.HelloDevice
    ResourceNotFound = 6,
    /// Message Body is structurally unsound: JSON parse error, or valid JSON, but is not mapping to
    /// the expected Secure Device Onboard type (see 4.6)
    ///
    /// ## Generated by Message
    ///
    /// - DI.AppStart
    /// - DI.SetHMAC
    /// - TO0.Hello
    /// - TO0.OwnerSign
    /// - TO1.HelloRV
    /// - TO1.ProveToRV
    /// - TO2.HelloDevice
    /// - TO2.GetOVNextEntry
    /// - TO2.ProveDevice
    /// - TO2.NextDeviceServiceInfo
    /// - TO2.GetNextOwnerServiceInfo
    /// - TO2.Done
    MessageBodyError = 100,
    /// Message structurally sound, but failed validation tests.
    ///
    /// The nonce didn’t match, signature didn’t verify, hash, or mac didn’t verify, index out of
    /// bounds, etc...
    ///
    /// ## Generated by Message
    ///
    ///  - TO0.OwnerSign
    ///  - TO1.HelloRV
    ///  - TO1.ProveToRV
    ///  - TO2.HelloDevice
    ///  - TO2.GetOVNextEntry
    ///  - TO2.ProveDevice
    ///  - TO2.NextDeviceServiceInfo
    ///  - TO2.GetNextOwnerServiceInfo
    InvalidMessageError = 101,
    /// Credential reuse rejected.
    ///
    /// ## Generated by Message
    ///
    /// - TO2.SetupDevice
    CredReuseError = 102,
    /// Something went wrong which couldn’t be classified otherwise.
    ///
    /// (This was chosen to match the HTTP 500 error code.)
    ///
    /// ## Generated by Message
    ///
    /// - DI.AppStart
    /// - DI.SetHMAC
    /// - TO0.Hello
    /// - TO0.OwnerSign
    /// - TO1.HelloRV
    /// - TO1.ProveToRV
    /// - TO2.HelloDevice
    /// - TO2.GetOVNextEntry
    /// - TO2.ProveDevice
    /// - TO2.NextDeviceServiceInfo
    /// - TO2.GetNextOwnerServiceInfo
    /// - TO2.Done
    InternalServerError = 500,
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorCode::InvalidJwtToken => write!(f, "INVALID_JWT_TOKEN"),
            ErrorCode::InvalidOwnershipVoucher => write!(f, "INVALID_OWNERSHIP_VOUCHER"),
            ErrorCode::InvalidOwnerSignBody => write!(f, "INVALID_OWNER_SIGN_BODY"),
            ErrorCode::InvalidIpAddress => write!(f, "INVALID_IP_ADDRESS"),
            ErrorCode::InvalidGuid => write!(f, "INVALID_GUID"),
            ErrorCode::ResourceNotFound => write!(f, "RESOURCE_NOT_FOUND"),
            ErrorCode::MessageBodyError => write!(f, "MESSAGE_BODY_ERROR"),
            ErrorCode::InvalidMessageError => write!(f, "INVALID_MESSAGE_ERROR"),
            ErrorCode::CredReuseError => write!(f, "CRED_REUSE_ERROR"),
            ErrorCode::InternalServerError => write!(f, "INTERNAL_SERVER_ERROR"),
        }
    }
}

impl From<ErrorCode> for u16 {
    fn from(value: ErrorCode) -> Self {
        value as u16
    }
}

/// Timestamp  of an [`ErrorMessage`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Timestamp<'a> {
    /// Utc date time string
    UtcStr(Cow<'a, str>),
    /// Utc date time integer.
    ///
    /// Seconds from 1970-01-01T00:00:00Z.
    UtcInt(u64),
    /// Local date time.
    ///
    /// Seconds from 1970-01-01.
    ///
    /// The TIMET choice is intended to remove the UTC restriction and allow a Device-local time value to be used.
    TimeT(u64),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_message_roundtrip() {
        let error_msg = ErrorMessage::new(
            ErrorCode::InternalServerError,
            60,
            "some error".into(),
            None,
            None,
        );

        let mut buf = Vec::new();
        error_msg.encode(&mut buf).unwrap();

        let res = ErrorMessage::decode(&buf).unwrap();

        assert_eq!(res, error_msg);

        insta::assert_binary_snapshot!(".cbor", buf);
    }

    #[test]
    fn error_message_display() {
        let error_msg = ErrorMessage::new(
            ErrorCode::InternalServerError,
            60,
            "some error".into(),
            None,
            None,
        );

        insta::assert_snapshot!(error_msg);
        insta::assert_debug_snapshot!(error_msg);

        let error_msg = ErrorMessage {
            e_m_error_code: 9000,
            e_m_prev_msg_id: 60,
            e_m_error_str: "some error".into(),
            e_m_error_ts: None,
            e_m_error_c_i_d: None,
        };

        insta::assert_snapshot!(error_msg);
        insta::assert_debug_snapshot!(error_msg);
    }

    #[test]
    fn error_message_known_code_roundtrip() {
        let error_codes = [
            ErrorCode::InvalidJwtToken,
            ErrorCode::InvalidOwnershipVoucher,
            ErrorCode::InvalidOwnerSignBody,
            ErrorCode::InvalidIpAddress,
            ErrorCode::InvalidGuid,
            ErrorCode::ResourceNotFound,
            ErrorCode::MessageBodyError,
            ErrorCode::InvalidMessageError,
            ErrorCode::CredReuseError,
            ErrorCode::InternalServerError,
        ];

        for code in error_codes {
            let error_msg = ErrorMessage::new(code, 60, "some error".into(), None, None);

            assert_eq!(error_msg.known_code(), Some(code));

            let value = u16::from(code);

            assert_eq!(value, error_msg.error_code());
        }
    }

    #[test]
    fn error_code_display() {
        let error_codes = [
            ErrorCode::InvalidJwtToken,
            ErrorCode::InvalidOwnershipVoucher,
            ErrorCode::InvalidOwnerSignBody,
            ErrorCode::InvalidIpAddress,
            ErrorCode::InvalidGuid,
            ErrorCode::ResourceNotFound,
            ErrorCode::MessageBodyError,
            ErrorCode::InvalidMessageError,
            ErrorCode::CredReuseError,
            ErrorCode::InternalServerError,
        ]
        .map(|e| e.to_string())
        .join("\n");

        insta::assert_snapshot!(error_codes);
    }
}
