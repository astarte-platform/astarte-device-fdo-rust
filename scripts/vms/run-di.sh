#!/usr/bin/env bash

# This file is part of Astarte.
#
# Copyright 2025, 2026 SECO Mind Srl
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

set -exEuo pipefail

# Trap -e errors
trap 'echo "Exit status $? at line $LINENO from: $BASH_COMMAND"' ERR

cargo build --package e2e-test --features tpm

rsync ./target/debug/e2e-test 192.168.122.140:./e2e-test
ssh 192.168.122.140 env RUST_LOG="${RUST_LOG:-info}" ./e2e-test \
    use-tpm di --manufacturing-url="http://192.168.122.1:8038" --export-guid ./fdo-guid.txt

scp 192.168.122.140:./fdo-guid.txt "$FDO_DEVICE_GUID"
