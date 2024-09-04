#![no_main]

use txgen::*;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
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
});
