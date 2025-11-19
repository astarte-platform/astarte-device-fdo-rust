#!/usr/bin/env bash

set -exEuo pipefail

# Trap -e errors
trap 'echo "Exit status $? at line $LINENO from: $BASH_COMMAND"' ERR

GUID=${GUID:-$1}

if [[ -z $GUID ]]; then
    echo "guid is unset"
    exit 1
fi

voucherdir="$FDODIR"/ov/ownervoucher

mkdir -p "$voucherdir"

curl --fail -v "http://localhost:8038/api/v1/vouchers/${GUID}" >"$voucherdir/$GUID"
curl --fail -X POST 'http://localhost:8043/api/v1/owner/vouchers' --data-binary "@$voucherdir/$GUID"

curl --fail --location --request GET "http://localhost:8043/api/v1/to0/${GUID}"
curl --fail --location --request GET "http://localhost:8043/api/v1/to0/${GUID}"
curl --fail --location --request GET "http://localhost:8043/api/v1/to0/${GUID}"
