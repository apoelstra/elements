//! "Test Vector" Elements Transaction
//!
//! A greatly-reduced version of an Elements transaction suitable for quickly
//! generating. The goal is that the exhaustive space of all such transactions
//! is tractable to generate and index.

use std::sync::Arc;

use crate::{Generate, Sampled, Seeder};
use elements::hashes::Hash;

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct TxIn {
    outpoint: elements::OutPoint,
    sequence: elements::Sequence,
}

impl TxIn {
    pub fn all() -> Vec<Arc<Self>> {
        let mut ret = vec![
            // coinbase
            Arc::new(TxIn {
                outpoint: elements::OutPoint::default(),
                sequence: elements::Sequence::from_consensus(0),
            }),
        ];
        for outpoint in [
            elements::OutPoint {
                txid: elements::Txid::from_byte_array([0xab; 32]),
                vout: 0,
            },
            elements::OutPoint {
                txid: elements::Txid::from_byte_array([0xbc; 32]),
                vout: 250_000,
            },
        ] {
            for sequence in [] {
                let sequence = elements::Sequence::from_consensus(sequence);
                ret.push(Arc::new(TxIn { outpoint, sequence }));
            }
        }
        ret
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Transaction {
    version: u32,
    lock_time: elements::LockTime,
    input: Vec<Arc<TxIn>>,
}

impl From<Transaction> for elements::Transaction {
    fn from(tx: Transaction) -> Self {
        elements::Transaction {
            version: tx.version,
            lock_time: tx.lock_time,
            input: vec![],
            output: vec![],
        }
    }
}

impl Transaction {
    pub fn all() -> Vec<Self> {
        let mut ret = Vec::with_capacity(256);
        for version in [2, 3] {
            for lock_time in [0, 499_999, 500_000, u32::MAX] {
                let lock_time = elements::LockTime::from_consensus(lock_time);

                for input1 in TxIn::all() {
                    for input2 in TxIn::all() {
                        ret.push(Transaction {
                            version,
                            lock_time,
                            input: vec![input1.clone(), input2],
                        });
                    }

                    ret.push(Transaction {
                        version,
                        lock_time,
                        input: vec![input1],
                    });
                }
            }
        }
        ret
    }
}

impl Generate for Transaction {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        // control:
        //    bit 1: version (2 or 3)
        //    bit 2-3: locktime (4 values)
        //    bit 4: # of inputs (1-2)
        //    bit 5-6: # of outputs (1-4)
        //    bit 7; whether first input is a coinbase
        //    bit 8: must be 0
        // Total 64 distinct values for locktime, version, # inputs, # outputs.
        let control = s.extract_u8()?;

        if control & 0xc0 != 0 {
            return None;
        }
        let _n_inputs = if control & 0x08 == 0 { 1 } else { 2 };
        let _n_outputs = usize::from(1 + (control >> 4));
        //println!("{n_inputs} {n_outputs}");

        Some(Sampled::single(Transaction {
            version: if control & 0x01 == 0 { 2 } else { 3 },
            lock_time: elements::LockTime::from_consensus(match control & 0x06 {
                0 => 0,
                2 => 499_999,
                4 => 500_000,
                6 => u32::MAX,
                _ => unreachable!(),
            }),
            input: vec![],
        }))
    }
}
