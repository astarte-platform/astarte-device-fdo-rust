#!/usr/bin/env bash

set -exEuo pipefail

# Trap -e errors
trap 'echo "Exit status $? at line $LINENO from: $BASH_COMMAND"' ERR

# Rendezvous Server
$CONTAINER run --rm -d \
    --name fdo-rendezvous \
    --network host \
    --user 0:0 \
    -v "$FDODIR":/tmp/fdo:z \
    go-fdo-server:latest \
    --log-level=debug rendezvous 0.0.0.0:8041 \
    --db-type sqlite --db-dsn "file:/tmp/fdo/db/rendezvous.db"

# Manufacturing Server
$CONTAINER run --rm -d \
    --name fdo-manufacturer \
    --network host \
    --user 0:0 \
    -v "$FDODIR":/tmp/fdo:z \
    go-fdo-server:latest \
    --log-level=debug manufacturing 0.0.0.0:8038 \
    --db-type=sqlite --db-dsn "file:/tmp/fdo/db/manufacturer.db" \
    --manufacturing-key /tmp/fdo/certs/manufacturer.key \
    --owner-cert /tmp/fdo/certs/owner.crt \
    --device-ca-cert /tmp/fdo/certs/device_ca.crt \
    --device-ca-key /tmp/fdo/certs/device_ca.key

# Owner Server
$CONTAINER run --rm -d \
    --name fdo-owner \
    --network host \
    --user 0:0 \
    -v "$FDODIR":/tmp/fdo:z \
    go-fdo-server:latest \
    --log-level=debug owner 0.0.0.0:8043 \
    --db-type=sqlite --db-dsn "file:/tmp/fdo/db/owner.db" \
    --owner-key /tmp/fdo/certs/owner.key \
    --device-ca-cert /tmp/fdo/certs/device_ca.crt
