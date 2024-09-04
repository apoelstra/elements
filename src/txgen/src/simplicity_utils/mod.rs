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

use simplicity::dag::{DagLike as _, NoSharing};
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
