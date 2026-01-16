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
} else {
    error("no container runtime")
}
# FDO directory
export FDODIR := "./.tmp/fdo"
export REPOS := "./.tmp/repos"
export CONTAINER_CACHE := "./.tmp/cache/containers"

export GO_SERVER_REF := "01a7aa7be9f58f17ad40242380e3e92b169bc307"

# Print this help message
help:
    just --list

# Runs the example di
client-di:
    cd client && cargo run -- plain-fs di

# Runs the example Transfer Ownership
client-to:
    cd client && cargo run -- plain-fs to

# Shows the device credentials
client-inspect:
    cd client && cargo run -- plain-fs inspect

# Build the tpm2-tss
build-tpm2-tss:
    ./scripts/tpm/build-tpm2-tss.sh

# Clean
clean:
    -$CONTAINER stop fdo-rendezvous
    -$CONTAINER stop fdo-manufacturer
    -$CONTAINER stop fdo-owner
    -./scripts/vms/vish-destroy.sh
    -rm -rf "$FDODIR"

####
# Go server and client setup
#

# Initialize the fdo files and container
go-server-clone:
    ./scripts/go-fdo/clone.sh \
        https://github.com/fido-device-onboard/go-fdo-server.git \
        go-fdo-server "$GO_SERVER_REF"

# Builds the go containers
go-server-build:
    ./scripts/go-fdo/build.sh go-fdo-server "$GO_SERVER_REF"

# Run the go servers
go-server-run:
    ./scripts/go-fdo/setup.sh
    ./scripts/go-fdo/serve.sh

# Check health of servers
go-server-health:
    curl --fail --retry 3 --retry-delay 2 --retry-connrefused http://localhost:8041/health  # Rendezvous
    curl --fail --retry 3 --retry-delay 2 --retry-connrefused http://localhost:8038/health  # Manufacturing
    curl --fail --retry 3 --retry-delay 2 --retry-connrefused http://localhost:8043/health  # Owner

# Run the go servers and checks the health
go-server-start: go-server-run go-server-health

# Run all the go-server configuration
go-server-all: go-server-clone go-server-build go-server-start go-data-create

# Create the rendezvous data data
go-data-create:
    curl --fail --location --request POST 'http://localhost:8038/api/v1/rvinfo' --header 'Content-Type: text/plain' --data-raw '[{"dns":"localhost","device_port":"8041","owner_port":"8041","protocol":"http","ip":"127.0.0.1"}]'
    curl --fail --location --request POST 'http://localhost:8043/api/v1/owner/redirect' --header 'Content-Type: text/plain' --data-raw '[{"dns":"localhost","port":"8043","protocol":"http","ip":"127.0.0.1"}]'

# Check the rendezvous information
go-data-info:
    curl --fail --location --request GET 'http://localhost:8038/api/v1/rvinfo' | jq
    curl --fail --location --request GET 'http://localhost:8043/api/v1/owner/redirect' | jq


# Sends the Manufacturing voucher to the owner TO0
go-send-to0 guid:
    ./scripts/go-fdo/send-to0.sh "{{ guid }}"

# Use the go client to do all the FDO
go-basic-onboarding:
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
vm-launch:
    ./scripts/vms/vish-destroy.sh

# SSH into the VM and runs the example
vm-run:
    ./scripts/run-on-vm.sh
