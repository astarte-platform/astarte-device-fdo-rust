// This file is part of Astarte.
//
// Copyright 2025 SECO Mind Srl
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! Key derivation function as specified in the protocol.

use astarte_fdo_protocol::error::ErrorKind;
use astarte_fdo_protocol::Error;
use tracing::error;

/// KDF in Counter Mode
///
/// This code is ported from aws_lc and the NIST specification
///
/// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf
pub(crate) fn kdf<const R: u8, const L_BYTES: u8, const L: usize>(
    alg: aws_lc_rs::hmac::Algorithm,
    // K_IN
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    // K_OUT
    output: &mut [u8; L],
) -> Result<(), Error> {
    let k_in = aws_lc_rs::hmac::Key::new(alg, secret);

    let h_out_bytes = u64::try_from(alg.digest_algorithm().output_len).map_err(|err| {
        error!(error = %err, "coudln't get alg output len");

        Error::new(ErrorKind::OutOfRange, "alg")
    })?;
    // NOTE: Do not know where size max comes from
    // if output.len() > SIZE_MAX.saturating_sub(alg.digest_algorithm().output_len) {
    //     return None;
    // }

    if h_out_bytes == 0 {
        // TODO: error this
        return Err(Error::new(ErrorKind::Invalid, "output len"));
    }

    // Convert to bits string
    let l_bits = L
        .checked_mul(8)
        .ok_or(Error::new(ErrorKind::OutOfRange, "overflow"))?
        .to_be_bytes();
    let l_be_idx = l_bits.len().saturating_sub(L_BYTES.into());
    let l_bits = &l_bits[l_be_idx..];
    // Exponent
    let r = u32::from(R);

    // NIST.SP.800-108r1-upd1: Step 1:
    // Determine how many output chunks are required to produce the requested
    // output length |out_len|. This determines how many times the variant compute
    // function will be called to output key material.
    let n: u64 = u64::try_from(L)
        .map_err(|err| {
            error!(error = %err, "couldn't get L");

            Error::new(ErrorKind::OutOfRange, "L")
        })?
        .div_ceil(h_out_bytes);

    // NIST.SP.800-108r1-upd1: Step 2:
    // Verify that the number of output chunks does not exceed R bits.
    if n > 2u64.pow(r).saturating_sub(1) {
        return Err(Error::new(ErrorKind::OutOfRange, "n too big"));
    }

    // Biggest size SHA256 is 64
    let mut written = 0;
    for i in 1..=n {
        let i_bits = i.to_be_bytes();
        let i_be_idx = i_bits.len().saturating_sub(R.into());
        let i_bits = &i_bits[i_be_idx..];

        // NIST.SP.800-108r1-upd1: Step 4a:
        // K(i) := PRF(K_IN, [i]_2 || Label || 0x00 || Context || [L]_2)
        let mut prf_k_in = aws_lc_rs::hmac::Context::with_key(&k_in);
        prf_k_in.update(i_bits);
        prf_k_in.update(label);
        prf_k_in.update(&[0x00]);
        prf_k_in.update(context);
        prf_k_in.update(l_bits);
        let out_k_in = prf_k_in.sign();

        // NIST.SP.800-108r1-upd1: Step 4b, Step 5
        // result := result || K(i)
        // Ensure that we only copy |out_len| bytes in total from all chunks.
        let rem = L.saturating_sub(written);
        let buf = &out_k_in.as_ref()[..rem];
        output[written..].copy_from_slice(buf);

        written += buf.len();
    }

    Ok(())
}
