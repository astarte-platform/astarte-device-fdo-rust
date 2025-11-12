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

//! Error returned by the library.

use std::fmt::Display;

/// Error for the protocol
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    ctx: &'static str,
}

impl Error {
    pub(crate) const fn new(kind: ErrorKind, ctx: &'static str) -> Self {
        Self { kind, ctx }
    }

    /// Returns the kind of error.
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.kind, self.ctx)
    }
}

impl std::error::Error for Error {}

/// Operation for which the [`Error`] was generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Couldn't encode data.
    Encode,
    /// Couldn't decode data.
    Decode,
    /// A value is out of range.
    OutOfRange,
    /// A value is invalid.
    Invalid,
    /// Couldn't write data.
    Write,
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorKind::Encode => write!(f, "couldn't encode"),
            ErrorKind::Decode => write!(f, "couldn't decode"),
            ErrorKind::OutOfRange => write!(f, "value out of range"),
            ErrorKind::Invalid => write!(f, "invalid value"),
            ErrorKind::Write => write!(f, "couldn't write"),
        }
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn error_display() {
        let error = Error::new(ErrorKind::Encode, "the message");

        insta::assert_snapshot!(error);
    }

    #[test]
    fn error_kind() {
        let kind = ErrorKind::Encode;

        let error = Error::new(kind, "the message");

        assert_eq!(*error.kind(), kind);
    }

    #[test]
    fn error_code_display() {
        let codes = [
            ErrorKind::Encode,
            ErrorKind::Decode,
            ErrorKind::OutOfRange,
            ErrorKind::Invalid,
            ErrorKind::Write,
        ]
        .map(|t| t.to_string())
        .join("\n");

        insta::assert_snapshot!(codes);
    }
}
