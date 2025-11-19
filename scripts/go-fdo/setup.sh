#!/usr/bin/env bash

set -exEuo pipefail

# Trap -e errors
trap 'echo "Exit status $? at line $LINENO from: $BASH_COMMAND"' ERR

mkdir -p "$FDODIR"/{certs,db,files}

# Manufacturer key (DER format)
openssl ecparam -name prime256v1 -genkey -out "$FDODIR"/certs/manufacturer.key -outform der

# Manufacturer certificate (PEM format)
openssl req -x509 -key "$FDODIR"/certs/manufacturer.key -keyform der \
    -out "$FDODIR"/certs/manufacturer.crt -days 365 \
    -subj "/C=US/O=Example/CN=Manufacturer"

# Device CA key (DER format)
openssl ecparam -name prime256v1 -genkey -out "$FDODIR"/certs/device_ca.key -outform der

# Device CA certificate (PEM format)
openssl req -x509 -key "$FDODIR"/certs/device_ca.key -keyform der \
    -out "$FDODIR"/certs/device_ca.crt -days 365 \
    -subj "/C=US/O=Example/CN=Device CA"

# Owner key (DER format)
openssl ecparam -name prime256v1 -genkey -out "$FDODIR"/certs/owner.key -outform der

# Owner certificate (PEM format)
openssl req -x509 -key "$FDODIR"/certs/owner.key -keyform der \
    -out "$FDODIR"/certs/owner.crt -days 365 \
    -subj "/C=US/O=Example/CN=Owner"

# Make files readable and writable by your user
chmod -R u+rwX "$FDODIR"
