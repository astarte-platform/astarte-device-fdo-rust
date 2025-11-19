#!/usr/bin/env bash

set -exEuo pipefail

# Trap -e errors
trap 'echo "Exit status $? at line $LINENO from: $BASH_COMMAND"' ERR

out=.tmp/sysroot/

mkdir -p "$out"

out=$(realpath $out)

cd containers/tpm2-tss-build

$CONTAINER build --tag dev-tpm2-tss-build:latest .
$CONTAINER run --rm --volume "$out:$out:z" --env "PREFIX=$out" dev-tpm2-tss-build:latest
