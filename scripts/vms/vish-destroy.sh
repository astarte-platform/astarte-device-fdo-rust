#!/usr/bin/env bash

set -exEuo pipefail

# Trap -e errors
trap 'echo "Exit status $? at line $LINENO from: $BASH_COMMAND"' ERR

virsh destroy cloudtest || true
virsh undefine --remove-all-storage cloudtest || true
