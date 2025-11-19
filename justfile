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
    -./scripts/vish-destroy.sh
    -rm -rf "$FDODIR"

####
# Go server and client setup
#

# Initialize the fdo files and container
go-server-setup:
    ./scripts/go-fdo/clone.sh
    ./scripts/go-fdo/build.sh

# Run the go servers
go-server-run:
    ./scripts/go-fdo/setup.sh
    ./scripts/go-fdo/serve.sh

# Check health of servers
go-health:
    curl --fail http://localhost:8041/health  # Rendezvous
    curl --fail http://localhost:8038/health  # Manufacturing
    curl --fail http://localhost:8043/health  # Owner

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
