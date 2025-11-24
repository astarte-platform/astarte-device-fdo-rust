#!/usr/bin/env bash

# This file is part of Astarte.
#
# Copyright 2025 SECO Mind Srl
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
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

mf_info='[
  {"dns":"localhost","device_port":"8041","owner_port":"8041","protocol":"http","ip":"127.0.0.1","delay_seconds":10},
  {"device_port":"8041","owner_port":"8041","protocol":"http","ip":"192.168.122.1","delay_seconds":10}
]'
ow_info='[
  {"dns":"localhost","port":"8043","protocol":"http","ip":"127.0.0.1","delay_seconds":10},
  {"port":"8043","protocol":"http","ip":"192.168.122.1","delay_seconds":10}
]'

try_curl() {
    curl --fail --location --retry 3 --retry-delay 2 --retry-connrefused "$@"
}

# Tries to update or create the info
send_req() {
    try_curl --request PUT "$1" --header 'Content-Type: text/plain' --data-raw "$2" ||
        try_curl --request POST "$1" --header 'Content-Type: text/plain' --data-raw "$2"
}

send_req 'http://localhost:8038/api/v1/rvinfo' "$mf_info"
send_req 'http://localhost:8043/api/v1/owner/redirect' "$ow_info"
