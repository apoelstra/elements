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
        extend_vec_from_hex("0000000000020000000000aaaaaaaaaaaaaa0a0000000000000100040000000000555555888888050000ff00000001000000000055555555eb7437d3829a3e1dd276ff2a145dbd9cc14dbb9be943f3596e0993a2fd3197637f1eb0ed596edb6118866118aa3832373933aa0a866100006118866118866100010f00000000010000000000008024ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffbf00000000010000000000000000000000800000000000000000000000003cd10000c30c30c304000000759b13f59b19789d52ee6c9b0e86e88468af005b7aa16e72cc12f2ad0474555559050000000000000000006118866100005555555555555505000000a0197a81ee0f3a540d4ab45a72d88e42f6986ac81c28fd24a10cb9aa65ddf054405840b84065ce2a1421eb7437d2d1e73e1dd276ff2a145dbd9cc14dbb9be943f3596e0993a2fd3197637f1eb0ed596edb6118866118aa3832373933aa0a866100008800000001000000010f00000000010000000000008024ffffffffffbf00000000010000000000000000000000800000000000000000000000003cd10000c30c30c304000000759b13f59b19789d52ee6c9b0e86e88468af005b7a000000000000004c74c09ec3cee81278bf583932e1a8f83e765555555555550500000000000000ff0000003d0900006118866118866100000000000056555555000000612b0000000000ff0001", &mut a);
        super::do_test(&a);
    }
}
