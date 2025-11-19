#!/usr/bin/env bash

set -exEuo pipefail

# Trap -e errors
trap 'echo "Exit status $? at line $LINENO from: $BASH_COMMAND"' ERR

$CONTAINER run --rm -it \
    --name fdo-client \
    --network host \
    --user 0:0 \
    -v "$FDODIR":/tmp/fdo:z \
    go-fdo-client:latest \
    "$@"
