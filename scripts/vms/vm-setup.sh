#!/usr/bin/env bash

# This file is part of Astarte.
#
# Copyright 2025 SECO Mind Srl
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

out=$HOME/vms/fedora-tpm-disk.qcow2

if [ ! -f "$out" ]; then
    curl --location --fail --output "$out" \
        https://download.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2
fi

configs=(
    "<host mac='52:54:00:00:00:14' name='cloudtest' ip='192.168.122.140' />"
)

for cfg in "${configs[@]}"; do
    sudo virsh net-update default modify ip-dhcp-host "$cfg" --live --config ||
        sudo virsh net-update default add ip-dhcp-host "$cfg" --live --config
done
