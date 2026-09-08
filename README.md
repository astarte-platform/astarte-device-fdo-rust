<!--
This file is part of Astarte.

Copyright 2025, 2026 SECO Mind Srl

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
-->

# astarte-device-fdo-rust

Implementation on the FIDO Device Onboarding protocol FDO:

<https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-PS-v1.1-20220419/FIDO-Device-Onboard-PS-v1.1-20220419.html>

## Run

To test the example you can run:

```sh
just setup
just run
```

## Using the `fdo-cli`

In the `e2e-test` crate we implement a CLI to perform the device on-boarding.

To use it you will need to setup all the required servers as a pre-requisite: manufacturing,
rendezvous, and owner.

The cli works in two steps, the first for the Device Initialization where it will create an
ownership voucher for the device.

```sh
cargo run -- palin-fs di \
  --storage <DIR>
  --manufacturing-url <MANUFACTURING_URL> \
  --export-guid <EXPORT_GUID>
```

Then, when the device has completed the DI, you can fetch the ownership voucher and uploaded it to
your owner server to start the TO0 protocol. To complete the FDO protocol on the device, you will
then run:

```sh
cargo run -- palin-fs to \
  --storage <DIR> \
  --astarte-mod=true \
  --json
```

This will print the Astarte information as a JSON to connect and send data to Astarte with the
following shape:

```json
{
  "base_url": "http://api.astarte.localhost",
  "realm": "test",
  "device_id": "Xojzk32TQxmw0zYzL4lA1w",
  "secret": "SECRET",
}
```
