fn do_test(mut data: &[u8]) {
    use txgen::Generate;

    let mut tx: txgen::elements::Transaction = match Generate::sample(&mut data) {
        Some(gen) => gen.into_data(),
        None => return,
    };

    tx.output.push(Default::default());
    let ser = txgen::elements::encode::serialize(&tx);
    let deser: txgen::elements::Transaction = txgen::elements::encode::deserialize(&ser).unwrap();

    if tx.input.iter().any(|inp| inp.is_coinbase())
        && ser.len() < 3000
        && tx.input.iter().any(|inp| inp.has_issuance())
        && tx
            .input
            .iter()
            .any(|inp| !inp.has_issuance() && !inp.is_coinbase())
        && tx
            .output
            .iter()
            .any(|out| out.value.is_confidential() && out.asset.is_confidential())
        && tx
            .output
            .iter()
            .any(|out| out.value.is_confidential() && !out.asset.is_confidential())
        && tx
            .output
            .iter()
            .any(|out| !out.value.is_confidential() && out.asset.is_confidential())
        && tx
            .output
            .iter()
            .any(|out| !out.value.is_confidential() && !out.asset.is_confidential())
    {
        /*
        use elements::hex::ToHex;
        println!("{}", ser.to_hex());

        panic!("stop");
        */
    }
    assert_eq!(deser, tx);
}

fn main() {
    loop {
        honggfuzz::fuzz!(|data| {
            do_test(data);
        });
    }
}

#[cfg(test)]
mod tests {
    fn extend_vec_from_hex(hex: &str, out: &mut Vec<u8>) {
        let mut b = 0;
        for (idx, c) in hex.as_bytes().iter().enumerate() {
            b <<= 4;
            match *c {
                b'A'..=b'F' => b |= c - b'A' + 10,
                b'a'..=b'f' => b |= c - b'a' + 10,
                b'0'..=b'9' => b |= c - b'0',
                _ => panic!("Bad hex"),
            }
            if (idx & 1) == 1 {
                out.push(b);
                b = 0;
            }
        }
    }

    #[test]
    fn duplicate_crash() {
        let mut a = Vec::new();
        extend_vec_from_hex("0f68002d320000888888888800000000000000c30c30c30c30c307ffffffffffffff0000001dcd64ff01000000000000000021ff0000000000015555555555555505ee111111111f1f1f1f1f1f1f1f1e1f1f1f1f1f1f1f1f00000000000000fd1f1f1f000000000000000000000000000000000001110000000000000080000000000000000000000000055555555555555500000000000000010000000000000000000000000000000400000000ff000000000555555555555555000088888800c331300cc3300cc300eade00000000000000000000000000000000008000fd0000000000000000000000080000000000888888011111111111111111111111000000000000000000000000000000000001ff0000000001fd0000888888888888880000000000000b00000000111111b80b0000000000001111", &mut a);
        super::do_test(&a);
    }
}
