/// Pregenerated key tables.
///
/// When generating public keys (and related types) we do a single precomp where
/// we parse a bunch of keys. This is a mildly expensive operation as it
/// involves a square root in the secp field.
///
/// Using precomputed points also lets us choose points where we know the
/// discrete log, which may come in handy in the future, and it saves on fuzzer
/// entropy.
use elements::secp256k1_zkp::{Generator, PedersenCommitment, PublicKey};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Once,
};

use crate::{Generate, Sampled, Seeder};

const N_KEYS: usize = 4;
#[rustfmt::skip]
static KEY_BYTES: [[u8; 32]; N_KEYS] = [
    // lowest valid x coord
    [
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1,
    ],
    // highest valid x coord
    [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2c,
    ],
    // generator G
    [
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
        0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
        0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
        0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    ],
    // 1/2 generatorG
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x3b, 0x78, 0xce, 0x56, 0x3f,
        0x89, 0xa0, 0xed, 0x94, 0x14, 0xf5, 0xaa, 0x28,
        0xad, 0x0d, 0x96, 0xd6, 0x79, 0x5f, 0x9c, 0x63,
    ],
];

const KEY_IDX: AtomicUsize = AtomicUsize::new(0);

macro_rules! impl_pregen_table {
    ($ty:ty, $init_name:ident, $arr_name:ident, $prefix:expr) => {
        static mut $arr_name: [Option<$ty>; N_KEYS] = [None; N_KEYS];
        static $init_name: Once = Once::new();

        impl Generate for $ty {
            fn sample<S: Seeder>(_: &mut S) -> Option<Sampled<Self>> {
                // SAFETY: I basically copied this from the `Once` docs
                unsafe {
                    $init_name.call_once(|| {
                        let mut key_bytes = [0; 33];
                        for i in 0..N_KEYS {
                            key_bytes[0] = $prefix + (i & 1) as u8;
                            key_bytes[1..].copy_from_slice(&KEY_BYTES[i]);
                            $arr_name[i] = Some(<$ty>::from_slice(&key_bytes).unwrap());
                        }
                    });

                    let key_idx = KEY_IDX.fetch_add(1, Ordering::Acquire);
                    Some(Sampled {
                        data: $arr_name[key_idx % N_KEYS].unwrap(),
                        size: 32,
                    })
                }
            }
        }
    };
}

impl_pregen_table!(PublicKey, PUBKEYS, INIT_PUBKEYS, 2);
impl_pregen_table!(PedersenCommitment, COMMITMENTS, INIT_COMMITMENTS, 8);
impl_pregen_table!(Generator, GENERATORS, INIT_GENERATORS, 10);
