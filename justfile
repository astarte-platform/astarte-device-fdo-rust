# This file is part of Astarte.
#
# Copyright 2025, 2026 SECO Mind Srl
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# Secure shell
set shell := ['bash', '-euo', 'pipefail', '-c']
# Allow `which`
set unstable

# Get the container runtime
export CONTAINER := if which("podman") != "" {
    "podman"
} else if which("docker") != "" {
    "docker"
} else if which("podman-remote") != "" {
    "podman-remote"
} else {
    error("no container runtime")
}
# FDO directory
export FDODIR := "./.tmp/fdo"
export FDO_DEVICE_GUID := "./.tmp/fdo/device_guid.txt"
export REPOS := "./.tmp/repos"
export CONTAINER_CACHE := "./.tmp/cache/containers"

export GO_SERVER_REF := "f6242900a7388523d85ce32f873e9fd76cf2618a"

# Print this help message
help:
    just --list

# Starts the server and run the full FDO
setup: go-server-setup

# Starts the server and run the full FDO
run: go-server-run client-run

# Build the tpm2-tss
build-tpm2-tss:
    ./scripts/tpm/build-tpm2-tss.sh

# Clean
clean: go-server-stop
    -./scripts/vms/vish-destroy.sh
    -rm -rvf "$FDODIR"
    -rm -rvf "./.tmp/fdo-astarte"

###
# Rust client
#

# Runs the full fdo protocol
[group('client')]
client-run: client-di go-server-to0 client-to

# Runs the example di
[group('client')]
client-di:
    cargo e2e-test plain-fs di --export-guid "$FDO_DEVICE_GUID"

# Runs the example Transfer Ownership
[group('client')]
client-to:
    cargo e2e-test plain-fs to

# Shows the device credentials
[group('client')]
client-inspect:
    cargo e2e-test plain-fs inspect

####
# Go server and client setup
#

# Setups the go-server
[group('server')]
go-server-setup: go-server-clone go-server-build go-server-keys

# Run all the go-server configuration
[group('server')]
go-server-run: go-server-start go-server-create-rv-info

# Initialize the fdo files and container
[group('server')]
go-server-clone:
    ./scripts/go-fdo/clone.sh \
        https://github.com/fido-device-onboard/go-fdo-server.git \
        go-fdo-server "$GO_SERVER_REF"

# Builds the go containers
[group('server')]
go-server-build:
    ./scripts/go-fdo/build.sh go-fdo-server "$GO_SERVER_REF"

# Creates the keys for the server
[group('server')]
go-server-keys:
    ./scripts/go-fdo/setup.sh

# Run the go servers
[group('server')]
go-server-serve:
    ./scripts/go-fdo/serve.sh

# Stop the servers
[group('server')]
go-server-stop:
    -$CONTAINER stop fdo-rendezvous
    -$CONTAINER stop fdo-manufacturer
    -$CONTAINER stop fdo-owner

# Check health of servers
[group('server')]
go-server-health:
    curl --fail --retry 3 --retry-delay 2 --retry-connrefused http://localhost:8041/health  # Rendezvous
    curl --fail --retry 3 --retry-delay 2 --retry-connrefused http://localhost:8038/health  # Manufacturing
    curl --fail --retry 3 --retry-delay 2 --retry-connrefused http://localhost:8043/health  # Owner

# Run the go servers and checks the health
[group('server')]
go-server-start: go-server-serve go-server-health

# Create the rendezvous data data
[group('server')]
go-server-create-rv-info:
    ./scripts/go-fdo/create-rv-info.sh

# Check the rendezvous information
[group('server')]
go-server-get-rv-info:
    curl --fail --location --request GET 'http://localhost:8038/api/v1/rvinfo' | jq
    curl --fail --location --request GET 'http://localhost:8043/api/v1/owner/redirect' | jq


# Sends the Manufacturing voucher to the owner TO0
[group('server')]
go-server-to0:
    ./scripts/go-fdo/send-to0.sh

# Use the go client to do all the FDO
[group('server')]
go-client-basic-onboarding:
    ./scripts/go-fdo/clone.sh \
        https://github.com/fido-device-onboard/go-fdo-client.git \
        go-fdo-client \
        21cb545547f06f77cba3aad2aa45fc1d1eeee781
    ./scripts/go-fdo/build.sh go-fdo-client 21cb545547f06f77cba3aad2aa45fc1d1eeee781
    ./scripts/go-fdo/basic-onboarding.sh

#
# VM with TPM support
#

# Launch the VM
[group('vm')]
vm-setup:
    ./scripts/vms/vm-setup.sh

# Launch the VM
[group('vm')]
vm-launch:
    ./scripts/vms/vish-launch.sh

# Runs FDO in a VM with a TPM
[group('vm')]
vm-run: go-server-run vm-client-run

# SSH into the VM and runs the client
[group('vm')]
vm-client-run: vm-client-di go-server-to0 vm-client-to

# SSH into the VM and runs the example
[group('vm')]
vm-client-di:
    ./scripts/vms/run-di.sh

# SSH into the VM and runs the example
[group('vm')]
vm-client-to:
    ./scripts/vms/run-to.sh

# Launch the VM
[group('vm')]
vm-clean:
    ./scripts/vms/vish-destroy.sh
