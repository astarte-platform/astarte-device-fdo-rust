// This file is part of Astarte.
//
// Copyright 2026 SECO Mind Srl
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

//! Configure the retry for the client.

use std::future::Future;

use astarte_fdo_protocol::Error;
use http::status::StatusCode;
use pin_project_lite::pin_project;
use tracing::{info, warn};

use crate::time::{add_random_jitter, DEFAULT_DELAY};

use super::MESSAGE_TYPE_HEADER;

// Retries with a delay.
#[derive(Debug, Clone)]
pub(crate) struct HttpRetry {
    count: u8,
    retries: u8,
}

impl HttpRetry {
    pub(crate) fn new() -> Self {
        Self {
            retries: 3,
            count: 0,
        }
    }

    fn should_retry_code(resp: &reqwest::Response) -> bool {
        Self::is_actual_internal_error(resp)
            || matches!(
                resp.status(),
                StatusCode::REQUEST_TIMEOUT
                    | StatusCode::CONFLICT
                    | StatusCode::TOO_MANY_REQUESTS
                    | StatusCode::BAD_GATEWAY
                    | StatusCode::GATEWAY_TIMEOUT
            )
    }

    fn is_actual_internal_error(resp: &reqwest::Response) -> bool {
        resp.status() == StatusCode::INTERNAL_SERVER_ERROR
            && resp.headers().contains_key(MESSAGE_TYPE_HEADER)
    }

    pub(crate) fn retry(
        &mut self,
        result: &Result<reqwest::Response, Error>,
    ) -> Option<HttpRetryFuture> {
        if let Ok(resp) = result.as_ref() {
            if !Self::should_retry_code(resp) {
                self.count = 0;

                return None;
            }
        }

        if self.count >= self.retries {
            warn!("max retry reached");

            self.count = 0;

            return None;
        }

        info!("retrying http request {}/{}", self.count, self.retries);

        Some(self.create_retry())
    }

    fn create_retry(&mut self) -> HttpRetryFuture {
        self.count += 1;

        // TODO: RetryAfter header?
        let duration = add_random_jitter(DEFAULT_DELAY);

        HttpRetryFuture {
            timeout: tokio::time::sleep(duration),
        }
    }
}

pin_project! {
    pub(crate) struct HttpRetryFuture {
        #[pin]
        timeout: tokio::time::Sleep,
    }
}

impl Future for HttpRetryFuture {
    type Output = ();

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();

        this.timeout.poll(cx)
    }
}
