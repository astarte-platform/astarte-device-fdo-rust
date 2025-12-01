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

use std::time::Duration;

use tracing::warn;

pub(crate) const DEFAULT_DELAY: Duration = Duration::from_secs(120);

/// Creates a delay by adding a random 25% more or less to it.
pub(crate) fn add_random_jitter(mut delay: Duration) -> Duration {
    // Delay of 2 minutes if any operation failes
    const DEFAULT_RANGE: i64 = DEFAULT_DELAY.as_millis().div_euclid(100).saturating_mul(25) as i64;

    // Use millis to produce a non empty range when approximating (secs/100)
    // random range up to 25%
    let add = i64::try_from(delay.as_millis().div_euclid(100).saturating_mul(25))
        .ok()
        .filter(|value| *value != 0)
        .unwrap_or_else(|| {
            warn!("invalid delay using default");

            delay = DEFAULT_DELAY;

            DEFAULT_RANGE
        });

    let range = -add..=add;

    let value = rand::random_range(range);

    let add = Duration::from_millis(value.unsigned_abs());

    if value.is_negative() {
        delay - add
    } else {
        delay + add
    }
}
