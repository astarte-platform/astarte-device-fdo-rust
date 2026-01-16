#!/usr/bin/env bash

# This file is part of Astarte.
#
# Copyright 2025, 2026 SECO Mind Srl
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

set -exEuo pipefail

# Trap -e errors
trap 'echo "Exit status $? at line $LINENO from: $BASH_COMMAND"' ERR

mkdir -p .tmp/vm/

tmp=$(mktemp -d)

key=$(ssh-add -L)

echo "$key" >"$tmp/ssh"

touch "$tmp/meta-data"
touch "$tmp/network-config"

cat >"$tmp/user-data" <<EOF
#cloud-config
password: passwd
chpasswd:
  expire: False
ssh_pwauth: True
ssh_authorized_keys:
  - $key
users:
  - default
  - name: $USER
    password: passwd
    chpasswd:
      expire: False
    ssh_authorized_keys:
      - $key
    primary_group: foobar
    groups: adm,wheel,systemd-journal,tss
EOF

ssh-keygen -R 192.168.122.140

virt-install --import --name cloudtest \
    --memory 2048 --network bridge=virbr0,mac=52:54:00:00:00:14 --graphics none \
    --os-variant fedora41 \
    --cloud-init "user-data=$tmp/user-data,meta-data=$tmp/meta-data,network-config=$tmp/network-config" \
    --disk=size=10,backing_store="$HOME/vms/fedora-tpm-disk.qcow2" \
    --tpm emulator
