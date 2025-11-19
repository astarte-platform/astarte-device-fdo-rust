#!/usr/bin/env bash

set -exEuo pipefail

# Trap -e errors
trap 'echo "Exit status $? at line $LINENO from: $BASH_COMMAND"' ERR

dir=.tmp/repos/

mkdir -p "$dir"

if [ ! -d .tmp/go-fdo-server/ ]; then
    git clone https://github.com/fido-device-onboard/go-fdo-server.git "$dir/go-fdo-server"
fi
if [ ! -d .tmp/go-fdo-client/ ]; then
    git clone https://github.com/fido-device-onboard/go-fdo-client.git "$dir/go-fdo-client"
fi

pushd "$dir/go-fdo-server/"
git fetch
git checkout 01a7aa7be9f58f17ad40242380e3e92b169bc307
popd

pushd "$dir/go-fdo-client/"
git fetch
git checkout 21cb545547f06f77cba3aad2aa45fc1d1eeee781
popd
