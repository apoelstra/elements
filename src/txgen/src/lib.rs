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

mod generate;
mod seeder;
mod simplicity_utils;

pub use elements;
pub use generate::{Generate, Sampled, TestTransaction};
pub use seeder::Seeder;
pub use simplicity;

use std::sync::Arc;

pub struct SeedData {
    tx_data: Vec<u8>,
    prog_data: Vec<u8>,
    wit_data: Vec<u8>,
    cmr: [u8; 32],
    amr: [u8; 32],
}

/// Constructor/allocator for a new set of seed data.
///
/// # Safety
///
/// `data` must point to a contiguous sequence of initialized bytes of length
/// at least `len`, which lives until after `seed_data_delete` is called on
/// the pointer.
#[no_mangle]
pub extern "C" fn seed_data_new() -> *mut SeedData {
    let new = Box::new(SeedData {
        tx_data: vec![],
        prog_data: vec![],
        wit_data: vec![],
        cmr: [0; 32],
        amr: [0; 32],
    });
    Box::into_raw(new)
}

/// Destructor/deallocator for a set of seed data.
///
/// # Safety
///
/// `data` must point to a live set of seed data, and must not be used again
/// after this function is called.
#[no_mangle]
pub unsafe extern "C" fn seed_data_delete(
    data: *mut SeedData
) {
    let _ = Box::from_raw(data);
}

/// Accessor for a pointer to the raw tx data.
#[no_mangle]
pub extern "C" fn seed_data_tx_data(data: &SeedData) -> *const u8 {
    data.tx_data.as_ptr()
}

/// Accessor for the length of the raw tx data.
#[no_mangle]
pub extern "C" fn seed_data_tx_len(data: &SeedData) -> usize {
    data.tx_data.len()
}

/// Accessor for a pointer to the raw program data.
#[no_mangle]
pub extern "C" fn seed_data_prog_data(data: &SeedData) -> *const u8 {
    data.prog_data.as_ptr()
}

/// Accessor for the length of the raw program data.
#[no_mangle]
pub extern "C" fn seed_data_prog_len(data: &SeedData) -> usize {
    data.prog_data.len()
}

/// Accessor for a pointer to the raw witness data.
#[no_mangle]
pub extern "C" fn seed_data_wit_data(data: &SeedData) -> *const u8 {
    data.wit_data.as_ptr()
}

/// Accessor for the length of the raw witness data.
#[no_mangle]
pub extern "C" fn seed_data_wit_len(data: &SeedData) -> usize {
    data.wit_data.len()
}

/// Accessor for a pointer to the CMR of the program
#[no_mangle]
pub extern "C" fn seed_data_cmr(data: &SeedData) -> *const u8 {
    data.cmr.as_ptr()
}

/// Accessor for a pointer to the AMR of the program
#[no_mangle]
pub extern "C" fn seed_data_amr(data: &SeedData) -> *const u8 {
    data.amr.as_ptr()
}


/*
#[no_mangle]
pub unsafe extern "C" fn tx_from_seed(
    data: *const u8,
    len: usize,
    ret_data: *mut *const u8,
    ret_size: *mut usize,
) -> bool {
    if ret_data.is_null() {
        return false;
    }

    let mut data = core::slice::from_raw_parts(data, len);
    let v = match elements::Transaction::sample(&mut data) {
        Some(tx) => elements::encode::serialize(tx.data()),
        None => return false,
    };

    *ret_size = v.len();
    *ret_data = Box::into_raw(v.into_boxed_slice()) as *mut u8;
    true
}
*/

#[no_mangle]
pub unsafe extern "C" fn seed_data_read_tx(
    seed_data: &mut SeedData,
    input_data: *const u8,
    input_len: usize,
) -> usize {
    let input_data = core::slice::from_raw_parts(input_data, input_len);
    let mut cursor = std::io::Cursor::new(input_data);
    match elements::Transaction::sample(&mut cursor) {
        Some(tx) => seed_data.tx_data = elements::encode::serialize(tx.data()),
        None => return 0,
    };
    cursor.position() as usize
}

#[no_mangle]
pub unsafe extern "C" fn seed_data_read_program(
    seed_data: &mut SeedData,
    input_data: *const u8,
    input_len: usize,
) -> usize {
    let input_data = core::slice::from_raw_parts(input_data, input_len);
    let mut cursor = std::io::Cursor::new(input_data);

    //use elements::hex::ToHex;
    //println!();
    //println!("seed [{:3}b]: {}", data.len(), data.to_hex());

    match Arc::<simplicity::RedeemNode<simplicity::jet::Elements>>::sample(&mut cursor) {
        Some(prog) => {
            let prog = prog.into_data();

            seed_data.cmr.copy_from_slice(&prog.cmr().to_byte_array());
            seed_data.amr.copy_from_slice(&prog.amr().to_byte_array());
            //println!("{}",prog);

            seed_data.prog_data.clear();
            let mut prog_iter = simplicity::BitWriter::new(&mut seed_data.prog_data);
            let mut wit_iter = simplicity::BitWriter::new(&mut seed_data.wit_data);
            prog.encode(&mut prog_iter, &mut wit_iter).unwrap()
        }
        None => return 0,
    };
    //println!("prog [{:3}b]: {}", v.len(), v.to_hex());
    cursor.position() as usize
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c_api() {
        let input = [0xab; 100];

        let data = seed_data_new();
        unsafe {
            seed_data_read_program(&mut *data, input.as_ptr(), input.len());

            let prog_bytes = core::slice::from_raw_parts(
                seed_data_prog_data(&*data),
                seed_data_prog_len(&*data),
            );
            let wit_bytes = core::slice::from_raw_parts(
                seed_data_wit_data(&*data),
                seed_data_wit_len(&*data),
            );

            assert!(
                simplicity::RedeemNode::<simplicity::jet::Elements>::decode(
                    prog_bytes.into(),
                    wit_bytes.into(),
                ).is_ok()
            );
            seed_data_delete(&mut *data);
        }
    }
}

