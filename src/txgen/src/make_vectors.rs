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

//! Test vector generator.
//!
//! Attempts to exhaustively generate a list of transactions with interesting properties.

use txgen::Generate;
use txgen::TestTransaction;

fn main() {
    let all_txs = TestTransaction::all();
    println!("total: {}", all_txs.len());

    let mut bytes = vec![];

    loop {
        bytes.push(0);
        if let Some(samp) = elements::Transaction::sample(&mut &bytes[..]) {
            let _ = samp.into_data();
            println!("Sampled len {} {:?}", bytes.len(), bytes);
            //            println!("{:?}", tx);
            return;
        }
        if bytes.len() % 1000 == 0 {
            println!("len {}", bytes.len());
        }
    }
}
