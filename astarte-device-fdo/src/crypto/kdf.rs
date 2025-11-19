// This file is part of Astarte.
//
// Copyright 2025, 2026 SECO Mind Srl
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

use std::ops::RangeInclusive;

use astarte_fdo_protocol::error::ErrorKind;
use astarte_fdo_protocol::Error;

/// Trait to make the KDF generic over the type of the counter parameters.
///
/// This is done so we can use the actual counter type (u8 and u16) for all the operations and
/// conversions.
trait KdfParam<const N: usize>: TryFrom<usize> {
    fn to_be_bytes(self) -> [u8; N];

    fn range(self) -> RangeInclusive<Self>
    where
        RangeInclusive<Self>: Iterator<Item = Self>;
}

impl KdfParam<1> for u8 {
    fn to_be_bytes(self) -> [u8; 1] {
        self.to_be_bytes()
    }

    fn range(self) -> RangeInclusive<Self> {
        RangeInclusive::new(1, self)
    }
}

impl KdfParam<2> for u16 {
    fn to_be_bytes(self) -> [u8; 2] {
        self.to_be_bytes()
    }

    fn range(self) -> RangeInclusive<Self> {
        RangeInclusive::new(1, self)
    }
}

pub(crate) fn kdf_ru8_lu16<const L: usize>(
    alg: aws_lc_rs::hmac::Algorithm,
    // K_IN
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    // K_OUT
    output: &mut [u8; L],
) -> Result<(), Error> {
    kdf_impl::<u8, u16, 1, 2, L>(alg, secret, label, context, output)
}

/// KDF in Counter Mode
///
/// This code is ported from aws_lc and the NIST specification, but we need to use an R = 1 for the
/// FDO Key Derivation function, while aws-lc uses R=4 (u32 counter)
///
/// All the const generics are for bytes instead of bits, to make it easier when indexing slices.
///
/// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf
fn kdf_impl<RParam, LParam, const R_BYTES: usize, const L_BYTES: usize, const L: usize>(
    alg: aws_lc_rs::hmac::Algorithm,
    // K_IN
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    // K_OUT
    output: &mut [u8; L],
) -> Result<(), Error>
// NOTE: we use the trait bounds to simplify the conversion code to big endian and validate the
//       size of the parameters
where
    RParam: KdfParam<R_BYTES>,
    LParam: KdfParam<L_BYTES>,
    RangeInclusive<RParam>: Iterator<Item = RParam>,
{
    // r – An integer (1 ≤ r ≤ 32) hat indicates the length of the binary encoding of the counter i
    debug_assert!((1..=4).contains(&core::mem::size_of::<RParam>()));

    let k_in = aws_lc_rs::hmac::Key::new(alg, secret);

    // This value should only be
    let h_out_bytes: usize = alg.digest_algorithm().output_len;

    if h_out_bytes == 0 {
        return Err(Error::new(ErrorKind::Invalid, "digest output len"));
    }

    // Convert to bits string
    let l_counter: LParam = L
        .checked_mul(8)
        .and_then(|l_bits| LParam::try_from(l_bits).ok())
        .ok_or(Error::new(
            ErrorKind::OutOfRange,
            "output len cannot fit in counter type ",
        ))?;
    let l_bits = l_counter.to_be_bytes();

    // NIST.SP.800-108r1-upd1: Step 1:
    // Determine how many output chunks are required to produce the requested
    // output length |out_len|. This determines how many times the variant compute
    // function will be called to output key material.
    //
    // NIST.SP.800-108r1-upd1: Step 2:
    // Verify that the number of output chunks does not exceed R bits.
    let n = RParam::try_from(L.div_ceil(h_out_bytes)).map_err(|_| {
        Error::new(
            ErrorKind::OutOfRange,
            "iterations cannot be fitted in counter type",
        )
    })?;

    // Biggest size SHA256 is 64
    let mut written = 0;
    for i in n.range() {
        let i_bits = i.to_be_bytes();

        // NIST.SP.800-108r1-upd1: Step 4a:
        // K(i) := PRF(K_IN, [i]_2 || Label || 0x00 || Context || [L]_2)
        let mut prf_k_in = aws_lc_rs::hmac::Context::with_key(&k_in);
        prf_k_in.update(&i_bits);
        prf_k_in.update(label);
        prf_k_in.update(&[0x00]);
        prf_k_in.update(context);
        prf_k_in.update(&l_bits);
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
