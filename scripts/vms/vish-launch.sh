#!/usr/bin/env bash

set -exEuo pipefail

# Trap -e errors
trap 'echo "Exit status $? at line $LINENO from: $BASH_COMMAND"' ERR

mkdir -p .tmp/vm/

echo passwd >.tmp/vm/passwordfile
ssh-add -L >.tmp/vm/id_ecc.pub

configs=(
    "<host mac='52:54:00:00:00:14' name='cloudtest' ip='192.168.122.140' />"
)

for cfg in "${configs[@]}"; do
    sudo virsh net-update default modify ip-dhcp-host "$cfg" --live --config ||
        sudo virsh net-update default add ip-dhcp-host "$cfg" --live --config
done

virt-install --import --name cloudtest \
    --memory 2048 --network bridge=virbr0,mac=52:54:00:00:00:14 \
    --os-variant detect=on,name=fedora-unknown \
    --cloud-init root-password-file=./.tmp/vm/passwordfile,root-ssh-key=./.tmp/vm/id_ecc.pub \
    --disk=size=10,backing_store="$HOME/vms/fedora-cloud.qcow2" \
    --tpm emulator
