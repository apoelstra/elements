// Elements / Simplicity Data Generator for Fuzzers
// Written in 2024 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

use std::sync::Arc;

use simplicity::Cmr;
use simplicity::dag::{DagLike as _, NoSharing};
use simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use simplicity::types::{self, CompleteBound};
use simplicity::Value;

use crate::Seeder;

#[allow(dead_code)]
pub fn value_for_type<S: Seeder>(s: &mut S, ty: &types::Final) -> Value {
    let mut bits = s.bit_iter();

    let mut val_stack = vec![];
    for ty in ty.post_order_iter::<NoSharing>() {
        if ty.node.is_unit() {
            val_stack.push(Value::unit())
        } else if ty.node.as_product().is_some() {
            let right = val_stack.pop().unwrap();
            let left = val_stack.pop().unwrap();
            val_stack.push(Value::product(left, right))
        } else if let CompleteBound::Sum(lty, rty) = ty.node.bound() {
            // We read the exact value from the fuzz input, but if it runs out,
            // we just use `false` and basically fill the rest of the value with
            // zeros.
            let right = val_stack.pop().unwrap();
            let left = val_stack.pop().unwrap();
            if bits.next().unwrap_or(false) {
                val_stack.push(Value::right(Arc::clone(lty), right));
            } else {
                val_stack.push(Value::left(left, Arc::clone(rty)));
            }
        } else {
            unreachable!("types must be units, sums or products");
        }
    }
    assert_eq!(val_stack.len(), 1);
    let ret = val_stack.pop().unwrap();
    //println!("Generated value for type width {}", ret.len());
    //assert_eq!(ret.len(), ty.bit_width());
    ret
}

#[allow(dead_code)]
pub fn simplicity_taproot_commitment<C: elements::secp256k1_zkp::Verification>(
    secp: &elements::secp256k1_zkp::Secp256k1<C>,
    control_block: &mut elements::taproot::ControlBlock,
    program_cmr: simplicity::Cmr,
) -> elements::schnorr::TweakedPublicKey {
    use elements::hashes::{Hash, HashEngine};
    use elements::secp256k1_zkp::Scalar;
    use elements::taproot::{TapLeafHash, TapNodeHash, TapTweakHash};

    // compute the script hash
    let mut eng = TapLeafHash::engine();
    eng.input(&[0xbe, 0x20]);
    eng.input(&program_cmr.to_byte_array());
    let leaf_hash = TapLeafHash::from_engine(eng);
    // Initially the curr_hash is the leaf hash
    let mut curr_hash = TapNodeHash::from_byte_array(leaf_hash.to_byte_array());
    // Verify the proof
    for elem in control_block.merkle_branch.as_inner() {
        let mut eng = TapNodeHash::engine();
        if curr_hash.as_byte_array() < elem.as_byte_array() {
            eng.input(curr_hash.as_ref());
            eng.input(elem.as_ref());
        } else {
            eng.input(elem.as_ref());
            eng.input(curr_hash.as_ref());
        }
        // Recalculate the curr hash as parent hash
        curr_hash = TapNodeHash::from_engine(eng);
    }
    // compute the taptweak
    let tweak = TapTweakHash::from_key_and_tweak(control_block.internal_key, Some(curr_hash));
    let tweak = Scalar::from_be_bytes(tweak.to_byte_array()).expect("hash value greater than curve order");

    // Update the control block with the parity and return the output key
    let (output_key, parity) = control_block.internal_key.add_tweak(secp, &tweak).unwrap();
    control_block.output_key_parity = parity;
    elements::schnorr::TweakedPublicKey::new(output_key)
}

#[allow(dead_code)]
pub fn dummy_elements_env() -> ElementsEnv<std::sync::Arc<elements::Transaction>> {
    dummy_with(elements::LockTime::ZERO, elements::Sequence::MAX)
}

#[allow(dead_code)]
fn dummy_with(lock_time: elements::LockTime, sequence: elements::Sequence) -> ElementsEnv<std::sync::Arc<elements::Transaction>> {
    use elements::AssetIssuance;
    use elements::confidential;
    use elements::taproot::ControlBlock;
    use simplicity::hashes::Hash;

    let ctrl_blk: [u8; 33] = [
        0xc0, 0xeb, 0x04, 0xb6, 0x8e, 0x9a, 0x26, 0xd1, 0x16, 0x04, 0x6c, 0x76, 0xe8, 0xff,
        0x47, 0x33, 0x2f, 0xb7, 0x1d, 0xda, 0x90, 0xff, 0x4b, 0xef, 0x53, 0x70, 0xf2, 0x52,
        0x26, 0xd3, 0xbc, 0x09, 0xfc,
    ];

    ElementsEnv::new(
        std::sync::Arc::new(elements::Transaction {
            version: 2,
            lock_time,
            // Enable locktime in dummy txin
            input: vec![elements::TxIn {
                previous_output: elements::OutPoint::default(),
                is_pegin: false,
                script_sig: elements::Script::new(),
                sequence,
                asset_issuance: AssetIssuance::default(),
                witness: elements::TxInWitness::default(),
            }],
            output: Vec::default(),
        }),
        vec![ElementsUtxo {
            script_pubkey: elements::Script::new(),
            asset: confidential::Asset::Null,
            value: confidential::Value::Null,
        }],
        0,
        Cmr::from_byte_array([0; 32]),
        ControlBlock::from_slice(&ctrl_blk).unwrap(),
        None,
        elements::BlockHash::all_zeros(),
    )
}
