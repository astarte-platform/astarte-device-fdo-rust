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

if ! $CONTAINER container inspect fdo-rendezvous; then
    # Rendezvous Server
    $CONTAINER run --rm -d \
        --name fdo-rendezvous \
        --network host \
        --user 0:0 \
        -v "$FDODIR":/tmp/fdo:z \
        localhost/go-fdo-server:latest \
        --log-level=debug rendezvous 0.0.0.0:8041 \
        --db-type sqlite --db-dsn "file:/tmp/fdo/db/rendezvous.db"
fi

if ! $CONTAINER container inspect fdo-manufacturer; then
    # Manufacturing Server
    $CONTAINER run --rm -d \
        --name fdo-manufacturer \
        --network host \
        --user 0:0 \
        -v "$FDODIR":/tmp/fdo:z \
        localhost/go-fdo-server:latest \
        --log-level=debug manufacturing 0.0.0.0:8038 \
        --db-type=sqlite --db-dsn "file:/tmp/fdo/db/manufacturer.db" \
        --manufacturing-key /tmp/fdo/certs/manufacturer.key \
        --owner-cert /tmp/fdo/certs/owner.crt \
        --device-ca-cert /tmp/fdo/certs/device_ca.crt \
        --device-ca-key /tmp/fdo/certs/device_ca.key
fi

if ! $CONTAINER container inspect fdo-owner; then
    # Owner Server
    $CONTAINER run --rm -d \
        --name fdo-owner \
        --network host \
        --user 0:0 \
        -v "$FDODIR":/tmp/fdo:z \
        localhost/go-fdo-server:latest \
        --log-level=debug owner 0.0.0.0:8043 \
        --db-type=sqlite --db-dsn "file:/tmp/fdo/db/owner.db" \
        --owner-key /tmp/fdo/certs/owner.key \
        --device-ca-cert /tmp/fdo/certs/device_ca.crt
fi
