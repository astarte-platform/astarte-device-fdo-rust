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
use std::fmt::Display;

use serde::{Deserialize, Serialize};

use super::{Message, Msgtype};

#[derive(Debug, Clone)]
pub(crate) struct ErrorMessage<'a> {
    // Error code
    e_m_error_code: u16,
    // Message ID (type) of the previous message
    e_m_prev_msg_id: u8,
    // Error string
    e_m_error_str: Cow<'a, str>,
    // UTC timestamp
    e_m_error_ts: ciborium::Value,
    // Unique id associated with this request
    e_m_error_c_i_d: Option<u64>,
}

impl<'a> ErrorMessage<'a> {
    pub(crate) fn new(
        e_m_error_code: ErrorCode,
        e_m_prev_msg_id: u8,
        e_m_error_str: Cow<'a, str>,
        e_m_error_ts: ciborium::Value,
        e_m_error_c_i_d: Option<u64>,
    ) -> Self {
        Self {
            e_m_error_code: e_m_error_code.into(),
            e_m_prev_msg_id,
            e_m_error_str,
            e_m_error_ts,
            e_m_error_c_i_d,
        }
    }

    pub(crate) fn known_code(&self) -> Option<ErrorCode> {
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

        Ok(Self {
            e_m_error_code,
            e_m_prev_msg_id,
            e_m_error_str,
            e_m_error_ts,
            e_m_error_c_i_d,
        })
    }
}

impl Message for ErrorMessage<'_> {
    const MSG_TYPE: Msgtype = 255;

    fn decode(buf: &[u8]) -> eyre::Result<Self> {
        let this = ciborium::from_reader(buf)?;

        Ok(this)
    }

    fn encode(&self) -> eyre::Result<Vec<u8>> {
        let mut buf = Vec::new();

        ciborium::into_writer(self, &mut buf)?;

        Ok(buf)
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub(crate) enum ErrorCode {
    InvalidJwtToken = 1,
    InvalidOwnershipVoucher = 2,
    InvalidOwnerSignBody = 3,
    InvalidIpAddress = 4,
    InvalidGuid = 5,
    ResourceNotFound = 6,
    MessageBodyError = 100,
    InvalidMessageError = 101,
    CredReuseError = 102,
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
