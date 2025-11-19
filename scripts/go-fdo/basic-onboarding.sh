#!/usr/bin/env bash

set -exEuo pipefail

# Trap -e errors
trap 'echo "Exit status $? at line $LINENO from: $BASH_COMMAND"' ERR

./scripts/go-fdo/go-fdo-client.sh device-init 'http://localhost:8038' \
    --device-info gotest \
    --key ec256 \
    --debug \
    --blob /tmp/fdo/cred.bin

GUID=$(./scripts/go-fdo/go-fdo-client.sh print --blob /tmp/fdo/cred.bin | grep -oE '[0-9a-fA-F]{32}' | head -n1)
echo "GUID=${GUID}"

./scripts/send-to0.sh "$GUID"

./scripts/go-fdo/go-fdo-client.sh onboard --key ec256 --kex ECDH256 --debug --blob /tmp/fdo/cred.bin |
    tee "$FDODIR"/client-onboard.log

grep -F 'FIDO Device Onboard Complete' "$FDODIR"/client-onboard.log >/dev/null &&
    echo 'Onboarding OK'
