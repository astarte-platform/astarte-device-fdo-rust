#!/usr/bin/env bash

# This file is part of Astarte.
#
# Copyright 2026 SECO Mind Srl
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

export ASTARTE_API_URL="${ASTARTE_API_URL:-https://api.autotest.astarte-platform.org}"
export RENDEZVOUS_HOST=${RENDEZVOUS_HOST:-rendezvous.localhost}
export FDODIR='./.tmp/fdo'
export FDO_DEVICE_GUID="$FDODIR/device_guid.txt"

./scripts/astarte/healthy.sh
./scripts/common/try-curl.sh "$RENDEZVOUS_HOST/health"

# Generate the keys
./scripts/go-fdo/setup.sh

# Upload key to astarte
# You need to use an astartectl context for to generate this token
astarte_token=$(astartectl utils gen-jwt all-realm-apis)
okey_pem=$(
    openssl ec -in $FDODIR/certs/owner.key -inform der -out - -outform pem
)
json=$(
    jq --null-input \
        --arg key_data "$okey_pem" \
        --arg key_name "test" \
        '{
            "data": {
                "action": "upload",
                "key_name": $key_name,
                "key_data": $key_data,
                "key_algorithm": "ecdsa-p256"
            }
        }'
)

if ! ./scripts/common/try-curl.sh \
    --header "Authorization: Bearer $astarte_token" \
    --request GET "$ASTARTE_API_URL/pairing/v1/test/fdo/owner_keys" |
    jq --exit-status '.es256 | any(. == "test")'; then

    ./scripts/common/try-curl.sh \
        --header "Authorization: Bearer $astarte_token" \
        --request POST "$ASTARTE_API_URL/pairing/v1/test/fdo/owner_keys" \
        --json "$json"
fi

# Start the Manufacturing Server
if ! podman container exists fdo-manufacturer; then
    podman run --rm -d \
        --name fdo-manufacturer \
        --network host \
        --user 0:0 \
        -v "$FDODIR":/tmp/fdo:z \
        docker.io/astarte/go-fdo-server:ade68cda47-20251128@sha256:84a9ddb4653df09b95fb82e2c78f7b0d1b34d732ca85527cb79ee9256746ac2a \
        manufacturing 0.0.0.0:8038 \
        --log-level=debug \
        --db-type=sqlite --db-dsn "file:/tmp/fdo/db/manufacturer.db" \
        --manufacturing-key /tmp/fdo/certs/manufacturer.key \
        --owner-cert /tmp/fdo/certs/owner.crt \
        --device-ca-cert /tmp/fdo/certs/device_ca.crt \
        --device-ca-key /tmp/fdo/certs/device_ca.key
fi

mf_info=$(printf '[
  {
      "dns": "%s",
      "device_port":"80",
      "owner_port":"80",
      "protocol":"http",
      "delay_seconds":10
  }
]' "$RENDEZVOUS_HOST")

./scripts/common/try-curl.sh -X POST 'http://localhost:8038/api/v1/rvinfo' --json "$mf_info" ||
    ./scripts/common/try-curl.sh -X PUT 'http://localhost:8038/api/v1/rvinfo' --json "$mf_info"

###
# DI part of the protocol
#

cargo e2e-test plain-fs di --export-guid "$FDO_DEVICE_GUID"

GUID=$(
    curl --fail-with-body http://localhost:8038/api/v1/vouchers |
        jq --exit-status --raw-output '. | sort_by(.updated_at) | last | .guid'
)

if [[ -z $GUID ]]; then
    echo "GUID is unset"
    exit 1
fi

###
# TO0 part of the protocol
#

# Download the voucher
voucherdir="$FDODIR/ov/ownervoucher"

mkdir -p "$voucherdir"

./scripts/common/try-curl.sh "http://localhost:8038/api/v1/vouchers/${GUID}" --output "$voucherdir/$GUID"

voucher=$(cat "$voucherdir/$GUID")

json=$(
    jq --null-input \
        --arg ownership_voucher "$voucher" \
        '{
            "data": {
                "ownership_voucher": $ownership_voucher,
                "key_name": "test",
                "key_algorithm": "ecdsa-p256"
            }
         }'
)

./scripts/common/try-curl.sh \
    --header "Authorization: Bearer $astarte_token" \
    --request POST "$ASTARTE_API_URL/pairing/v1/test/fdo/ownership_vouchers" \
    --json "$json"

###
# TO1 and TO2 part of the protocol
#
cargo e2e-test plain-fs to --astarte-mod
