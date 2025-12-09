#!/usr/bin/env bash

# This file is part of Astarte.
#
# Copyright 2025 SECO Mind Srl
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

curl --fail -v "$BOARD_MAN/api/v1/vouchers/${GUID}" --output "$voucherdir/$GUID"

voucher=$(cat "$voucherdir/$GUID")
private_key=$(
    openssl ec -in .tmp/fdo/certs/owner.key -inform der -out - -outform pem
)

json=$(
    jq --null-input \
        --arg voucher "$voucher" \
        --arg key "$private_key" \
        '{"data":{"ownership_voucher":$voucher,"private_key":$key}}'
)



curl --fail \
    --header "Authorization: Bearer $BOARD_REALM_TOKEN" \
    --request POST "$BOARD_API/pairing/v1/$BOARD_REALM/ownership" \
    --json "$json"
