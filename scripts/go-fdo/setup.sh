#!/usr/bin/env bash

set -exEuo pipefail

# Trap -e errors
trap 'echo "Exit status $? at line $LINENO from: $BASH_COMMAND"' ERR

mkdir -p "$FDODIR"/{certs,db,files}

# Manufacturer key (DER format)
if [ ! -f "$FDODIR"/certs/manufacturer.key ]; then
    openssl ecparam -name prime256v1 -genkey -out "$FDODIR"/certs/manufacturer.key -outform der
fi

# Manufacturer certificate (PEM format)
if [ ! -f "$FDODIR"/certs/manufacturer.crt ]; then
    openssl req -x509 -key "$FDODIR"/certs/manufacturer.key -keyform der \
        -out "$FDODIR"/certs/manufacturer.crt -days 365 \
        -subj "/C=US/O=Example/CN=Manufacturer"
fi

# Device CA key (DER format)
if [ ! -f "$FDODIR"/certs/device_ca.key ]; then
    openssl ecparam -name prime256v1 -genkey -out "$FDODIR"/certs/device_ca.key -outform der
fi

# Device CA certificate (PEM format)
if [ ! -f "$FDODIR"/certs/device_ca.crt ]; then
    openssl req -x509 -key "$FDODIR"/certs/device_ca.key -keyform der \
        -out "$FDODIR"/certs/device_ca.crt -days 365 \
        -subj "/C=US/O=Example/CN=Device CA"
fi

# Owner key (DER format)
if [ ! -f "$FDODIR"/certs/owner.key ]; then
    openssl ecparam -name prime256v1 -genkey -out "$FDODIR"/certs/owner.key -outform der
fi

# Owner certificate (PEM format)
if [ ! -f "$FDODIR"/certs/owner.crt ]; then
    openssl req -x509 -key "$FDODIR"/certs/owner.key -keyform der \
        -out "$FDODIR"/certs/owner.crt -days 365 \
        -subj "/C=US/O=Example/CN=Owner"
fi

# Make files readable and writable by your user
chmod -R u+rwX "$FDODIR"
