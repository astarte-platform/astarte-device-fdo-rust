#!/usr/bin/env bash

set -exEuo pipefail

# Trap -e errors
trap 'echo "Exit status $? at line $LINENO from: $BASH_COMMAND"' ERR

pushd ./go-fdo-server

$CONTAINER build -t go-fdo-server:latest .

popd

pushd ./go-fdo-client

$CONTAINER build -t go-fdo-client:latest .

popd
