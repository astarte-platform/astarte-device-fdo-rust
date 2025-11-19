#!/usr/bin/env bash

set -exEuo pipefail

# Trap -e errors
trap 'echo "Exit status $? at line $LINENO from: $BASH_COMMAND"' ERR

cargo build

# TODO: fix
scp ./target/debug/client root@192.168.122.140:/tmp/client
ssh root@192.168.122.140 env RUST_LOG="${RUST_LOG:-info}" /tmp/client use-tpm
