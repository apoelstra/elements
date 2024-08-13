use core::mem;
use elements::confidential;
use elements::hashes::Hash;

use super::{Generate, Sampled, Seeder};

impl Generate for confidential::Value {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        match s.extract_u8()? {
            255 => Some(Sampled::single(confidential::Value::Null)),
            x if x < 64 => Generate::sample_then_map(s, confidential::Value::Explicit),
            _ => Generate::sample_then_map(s, confidential::Value::Confidential),
        }
    }
}

impl Generate for confidential::Nonce {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        match s.extract_u8()? {
            255 => Some(Sampled::single(confidential::Nonce::Null)),
            x if x < 64 => Generate::sample_then_map(s, confidential::Nonce::Explicit),
            _ => Generate::sample_then_map(s, confidential::Nonce::Confidential),
        }
    }
}

impl Generate for elements::hashes::sha256::Midstate {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        Generate::sample_then_map(s, elements::hashes::sha256::Midstate::from_byte_array)
    }
}

impl Generate for elements::AssetId {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        Generate::sample_then_map(s, elements::AssetId::from_inner)
    }
}

impl Generate for confidential::Asset {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        match s.extract_u8()? {
            255 => Some(Sampled::single(confidential::Asset::Null)),
            x if x < 64 => Generate::sample_then_map(s, confidential::Asset::Explicit),
            _ => Generate::sample_then_map(s, confidential::Asset::Confidential),
        }
    }
}

impl Generate for elements::secp256k1_zkp::Tweak {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        loop {
            let bytes = Generate::sample(s)?;
            if let Ok(t) = elements::secp256k1_zkp::Tweak::from_inner(bytes.data) {
                return Some(Sampled::single(t));
            }
        }
    }
}

impl Generate for elements::AssetIssuance {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        let amount: Sampled<confidential::Value> = Generate::sample(s)?;
        let inflation_keys: Sampled<confidential::Value> = Generate::sample(s)?;
        let is_null = amount.data.is_null() && inflation_keys.data.is_null();
        let asset_blinding_nonce = if !is_null {
            Generate::sample(s)?.data
        } else {
            Default::default()
        };
        let asset_entropy = if !is_null {
            Generate::sample(s)?.data
        } else {
            Default::default()
        };

        Some(Sampled {
            data: elements::AssetIssuance {
                amount: amount.data,
                inflation_keys: inflation_keys.data,
                asset_blinding_nonce,
                asset_entropy,
            },
            size: amount.size + inflation_keys.size + 64,
        })
    }
}

impl Generate for elements::OutPoint {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        let control = s.extract_u8()?;

        let ret;
        if control == 0 {
            ret = elements::OutPoint::default(); // coinbase
        } else {
            let txid = if control & 2 == 0 {
                elements::Txid::from_byte_array([0xab; 32])
            } else {
                elements::Txid::from_byte_array([0xcd; 32])
            };
            let pegin_mask = control & 0x80 == 0x80; // FIXME cannot generate pegins
            let issuance_mask = control & 0x40 == 0x40;

            let pegin_mask = false;
            let vout = ((u32::from(control) & 0x3f) >> 2)
                + 0x40000000 * u32::from(pegin_mask)
                + 0x80000000 * u32::from(issuance_mask);
            ret = elements::OutPoint { txid, vout };
        }
        Some(Sampled::single(ret))
    }
}

impl Generate for elements::Script {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        use elements::opcodes::all::*;

        // FIXME have a small fixed set of templates here
        let control = u8::sample(s)?.into_data();
        if control & 0x80 == 0 {
            Vec::<u8>::sample_then_map(s, elements::Script::from)
        } else {
            let mut builder = elements::script::Builder::new()
                .push_opcode(OP_RETURN);
            for _ in 0..control & 0x3f {
                builder = match u8::sample(s)?.into_data() {
                    0 => builder.push_opcode(OP_PUSHBYTES_0),
                    1 => builder.push_opcode(OP_PUSHNUM_1),
                    2 => builder.push_opcode(OP_PUSHNUM_2),
                    3 => builder.push_opcode(OP_PUSHNUM_3),
                    4 => builder.push_opcode(OP_PUSHNUM_4),
                    5 => builder.push_opcode(OP_PUSHNUM_5),
                    6 => builder.push_opcode(OP_PUSHNUM_6),
                    7 => builder.push_opcode(OP_PUSHNUM_7),
                    8 => builder.push_opcode(OP_PUSHNUM_8),
                    9 => builder.push_opcode(OP_PUSHNUM_9),
                    10 => builder.push_opcode(OP_PUSHNUM_10),
                    11 => builder.push_opcode(OP_PUSHNUM_11),
                    12 => builder.push_opcode(OP_PUSHNUM_12),
                    13 => builder.push_opcode(OP_PUSHNUM_13),
                    14 => builder.push_opcode(OP_PUSHNUM_14),
                    15 => builder.push_opcode(OP_PUSHNUM_15),
                    16 => builder.push_opcode(OP_PUSHNUM_16),
                    17 => builder.push_opcode(OP_PUSHNUM_NEG1),
                    18 => builder.push_opcode(OP_RESERVED),
                    19 => builder.push_opcode(OP_NOP), // first non-push opcode
                    20 => builder.push_opcode(OP_RETURN), // also a non-push opcode
                    x @ 20..=94 => {
                        // All lengths from 1 to 75 (0 is covered above in PUSHBYTES_0)
                        let len = x - 19;
                        let sl = vec![0xcd, len];
                        builder.push_slice(&sl)
                    }
                    x @ 95.. => {
                        // Lengths from 4 up to 104684 which will push us into PUSHBYTES4 territory
                        let len = 4 * (x - 94) * (x - 94);
                        let sl = vec![0xcd, len];
                        builder.push_slice(&sl)
                    }
                }

            }

            let mut data = builder.into_script();
            if control & 0x40 == 0 {
                // Randomly chop script in half which should result in broken
                // pushes (going off the end of the script), which is important
                // to test.
                let mut v = data.into_bytes();
                v.truncate(v.len() / 2);
                data = elements::Script::from(v);
            }
            Some(Sampled {
                size: data.len(),
                data,
            })
        }
    }
}

impl Generate for elements::Sequence {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        u32::sample_then_map(s, elements::Sequence::from_consensus)
    }
}

impl Generate for elements::LockTime {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        u32::sample_then_map(s, elements::LockTime::from_consensus)
    }
}

impl Generate for elements::secp256k1_zkp::RangeProof {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        let mut ret = Vec::with_capacity(1024);
        // The rules for rangeproofs are that `secp256k1_rangeproof_getheader_impl` in
        // the secp256k1-zkp source code need to pass. We go a few steps further and
        // make sure that the proof length is consistent with the header. But we do
        // not try to check that the ecoded curvepoints are valid and certainly don't
        // try to make the rangeproof pass verification (which would be impossible
        // without extra input anyway).
        //
        // The format of the header is:
        //  * byte 0:
        //    * MSB 0: must be 0
        //    * bit 1: has_nz_range
        //    * bit 2: has_minimum_value
        //    * bit 3-8: if has_nz_range, base-10 exponent (max 18), otherwise unconstrained[*]
        //  * byte 1: if has_nz_range, mantissa (max 64) (max value is UINT64_MAX>>(64-mantissa))
        //  * byte 2-9: if has_minimum_value, min value in LE
        //
        // [*] "unconstrained" in that a signer can set them to any value; but none of these
        //     values can be malleated by a 3rd party since the whole header is signed by the
        //     rangeproof.

        let control = s.extract_u8()?;
        let has_nz_range = control & 1 == 1;
        let minimum_value = if control & 2 == 2 {
            Some(u64::sample(s)?.data)
        } else {
            None
        };

        ret.push(u8::from(has_nz_range) * 64 + u8::from(minimum_value.is_some()) * 32);
        let mantissa;
        let maximum_value;
        if has_nz_range {
            mantissa = 1 + s.extract_u8()? % 64;

            let mut max_value = u64::MAX >> (64 - mantissa);
            let mut max_exponent = 0;
            while max_value.checked_mul(10).is_some() {
                max_value *= 10;
                max_exponent += 1;
            }
            maximum_value = max_value;

            let exponent = if max_exponent == 0 {
                0
            } else {
                s.extract_u8()? % max_exponent
            };
            ret[0] |= exponent;
            ret.push(mantissa - 1);
        } else {
            maximum_value = 0;
            mantissa = 0;
        }

        if let Some(mut minimum_value) = minimum_value {
            if minimum_value.checked_add(maximum_value).is_none() {
                if maximum_value == u64::MAX {
                    minimum_value = 0;
                } else {
                    minimum_value %= u64::MAX - maximum_value;
                }
            }

            ret.push((minimum_value >> 56) as u8); // cast ok, truncation expected
            ret.push((minimum_value >> 48) as u8); // cast ok, truncation expected
            ret.push((minimum_value >> 40) as u8); // cast ok, truncation expected
            ret.push((minimum_value >> 32) as u8); // cast ok, truncation expected
            ret.push((minimum_value >> 24) as u8); // cast ok, truncation expected
            ret.push((minimum_value >> 16) as u8); // cast ok, truncation expected
            ret.push((minimum_value >> 8) as u8); // cast ok, truncation expected
            ret.push((minimum_value) as u8); // cast ok, truncation expected
        }

        let mut npub = 1usize;
        let mut rings = 1usize;
        if mantissa != 0 {
            rings = usize::from(mantissa) >> 1;
            npub = rings << 2;
            if mantissa & 1 == 1 {
                npub += 2;
                rings += 1;
            }
        }

        let mut rng_byte = 10;
        for _ in 0..32 * (npub + rings - 1) + 32 + ((rings + 6) >> 3) {
            ret.push(rng_byte);
            rng_byte = rng_byte.wrapping_mul(17).wrapping_add(23);
        }

        Some(Sampled {
            data: elements::secp256k1_zkp::RangeProof::from_slice(&ret).unwrap(),
            size: ret.len(),
        })
    }
}

impl Generate for elements::secp256k1_zkp::SurjectionProof {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        let mut ret = Vec::with_capacity(1024);
        // The rules for surjectionproofs are simpler than those for rangeproofs.

        // The first two bytes are the total number of inputs. The parser allows
        // this to be 0 though the verifier will not. We forbid 0 because it
        // simplifies our life a bit and no on-chain transaction can have 0
        // since every surjection proof gets verified.
        let n_inputs = match s.extract_u8()? {
            255 => {
                // map 255 to 256
                ret.push(0);
                ret.push(1);
                256usize
            }
            x => {
                // map everything else to x + 1
                ret.push(x);
                ret.push(0);
                x.into()
            }
        };
        let n_inputs: usize = n_inputs.into();
        // Then we have a bitmap of set bits
        for _ in 0..(n_inputs + 7) / 8 {
            ret.push(s.extract_u8()?);
        }
        if n_inputs % 8 != 0 {
            let padding_mask = (1 << (n_inputs % 8)) - 1;
            ret[2 + (n_inputs + 7) / 8 - 1] &= padding_mask;
        }
        // Then we have the signature data, which is a series of scalars that are only
        // limited by the need to be in-range, which they will be with overwhelming
        // probability if we just stuff them with random bits.
        let signature_len = 32
            + 32 * (0..(n_inputs + 7) / 8)
                .map(|i| ret[2 + i].count_ones() as usize) // cast ok, value is obviously in [0, 7]
                .sum::<usize>();

        let mut rng_byte = 3;
        for _ in 0..signature_len {
            ret.push(rng_byte);
            rng_byte = rng_byte.wrapping_mul(13).wrapping_add(29);
        }

        Some(Sampled {
            data: elements::secp256k1_zkp::SurjectionProof::from_slice(&ret).unwrap(),
            size: ret.len(),
        })
    }
}

impl Generate for elements::TxInWitness {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        let f1 = Generate::sample(s)?;
        let f2 = Generate::sample(s)?;
        let f3 = Generate::sample(s)?;
        let f4 = Generate::sample(s)?;

        // pegin witness is a vec<vec<u8>> but should be awell formed pegin
        Some(Sampled {
            data: elements::TxInWitness {
                amount_rangeproof: f1.data,
                inflation_keys_rangeproof: f2.data,
                pegin_witness: f3.data,
                script_witness: f4.data,
            },
            size: f1.size + f2.size + f3.size + f4.size,
        })
    }
}

impl Generate for elements::TxIn {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        let mut outpoint = elements::OutPoint::sample(s)?;
        let is_pegin;
        let is_issuance;
        if outpoint.data.vout == 0xffffffff {
            is_pegin = false;
            is_issuance = false;
        } else {
            is_pegin = false; // FIXME need to generate valid pegins to pass IsValidPeginWitness
                              //is_pegin = outpoint.vout & (1 << 30) != 0;
            is_issuance = outpoint.data.vout & (1 << 31) != 0;
            outpoint.data.vout &= 0x3fffffff;
        }

        let f4 = Generate::sample(s)?;
        let f5 = Generate::sample(s)?;
        let f6 = Generate::sample(s)?;
        Some(Sampled {
            data: elements::TxIn {
                is_pegin,
                asset_issuance: if is_issuance {
                    Generate::sample(s)?.data
                } else {
                    elements::AssetIssuance::null()
                },
                previous_output: outpoint.data,
                script_sig: f4.data,
                sequence: f5.data,
                witness: f6.data,
            },
            size: mem::size_of::<bool>()
                + mem::size_of::<bool>()
                + mem::size_of::<elements::AssetIssuance>()
                + mem::size_of::<elements::OutPoint>()
                + f4.size
                + f5.size
                + f6.size,
        })
    }
}

impl Generate for elements::TxOutWitness {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        let f1 = Generate::sample(s)?;
        let f2 = Generate::sample(s)?;
        Some(Sampled {
            data: elements::TxOutWitness {
                rangeproof: f1.data,
                surjection_proof: f2.data,
            },
            size: f1.size + f2.size,
        })
    }
}

impl Generate for elements::TxOut {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        let f1 = Generate::sample(s)?;
        let f2 = Generate::sample(s)?;
        let f3 = Generate::sample(s)?;
        let f4 = Generate::sample(s)?;
        let f5 = Generate::sample(s)?;
        Some(Sampled {
            data: elements::TxOut {
                asset: f1.data,
                nonce: f2.data,
                value: f3.data,
                script_pubkey: f4.data,
                witness: f5.data,
            },
            size: f1.size + f2.size + f3.size + f4.size + f5.size,
        })
    }
}

impl Generate for elements::Transaction {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        // control:
        //    bit 1:   version (2 or 3)
        //    bit 2-3: locktime (4 values)
        //    bit 4:   # of inputs (1-2)
        //    bit 5-6: most be 0
        //    bit 7-8: must be 0
        // Total 64 distinct values for locktime, version, # inputs, # outputs.
        let control = s.extract_u8()?;

        if control & 0xf0 != 0 {
            return None;
        }

        let n_inputs = 1 + if control & 0x08 == 0 { 1 } else { 2 };
        let mut input = Vec::with_capacity(n_inputs);
        for _ in 0..n_inputs {
            input.push(Generate::sample(s)?.data);
        }

        let n_outputs = 4;
        let mut output = Vec::with_capacity(n_outputs);
        for _ in 0..n_outputs {
            output.push(Generate::sample(s)?.data);
        }

        Some(Sampled::single(elements::Transaction {
            version: if control & 0x01 == 0 { 2 } else { 3 },
            lock_time: elements::LockTime::from_consensus(match control & 0x06 {
                0 => 0,
                2 => 499_999,
                4 => 500_000,
                6 => u32::MAX,
                _ => unreachable!(),
            }),
            input,
            output,
        }))
    }
}
