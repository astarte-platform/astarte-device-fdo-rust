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

GUID=${GUID:-$1}

if [[ -z $GUID ]]; then
    echo "guid is unset"
    exit 1
fi

voucherdir="$FDODIR"/ov/ownervoucher

mkdir -p "$voucherdir"

curl --fail -v "http://localhost:8038/api/v1/vouchers/${GUID}" >"$voucherdir/$GUID"
curl --fail -X POST 'http://localhost:8043/api/v1/owner/vouchers' --data-binary "@$voucherdir/$GUID"

curl --fail --location --request GET "http://localhost:8043/api/v1/to0/${GUID}"
curl --fail --location --request GET "http://localhost:8043/api/v1/to0/${GUID}"
curl --fail --location --request GET "http://localhost:8043/api/v1/to0/${GUID}"
