#!/usr/bin/env bash

# This file is part of Astarte.
#
# Copyright 2025, 2026 SECO Mind Srl
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

if [ -z "${1:-}" ]; then
    GUID=$(cat "$FDO_DEVICE_GUID")
else
    GUID=$1
fi

if [[ -z $GUID ]]; then
    echo "guid is unset"
    exit 1
fi

voucherdir="$FDODIR/ov/ownervoucher"

mkdir -p "$voucherdir"

curl --fail -v "http://localhost:8038/api/v1/vouchers/${GUID}" --output "$voucherdir/$GUID"

# Extend the voucher
cargo run -- tool ov-extend \
    --in-format der --alg secp256r1 \
    --current-ow-priv "$FDODIR/certs/intermediate.key" \
    --next-ow-cert "$FDODIR/certs/owner.crt" \
    --voucher "$FDODIR/ov/ownervoucher/$GUID" \
    --output "$FDODIR/ov/ownervoucher/$GUID-extended"

curl --fail --request POST 'http://localhost:8043/api/v1/owner/vouchers' --data-binary "@$voucherdir/$GUID-extended"
