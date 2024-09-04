pub trait Seeder: Sized {
    fn extract_u8(&mut self) -> Option<u8>;

    fn bit_iter(&mut self) -> BitIter<Self> {
        BitIter {
            seeder: self,
            last_u8: 0,
            bit_idx: 8,
        }
    }
}

impl<R: std::io::Read> Seeder for R {
    fn extract_u8(&mut self) -> Option<u8> {
        let mut res = [0];
        self.read_exact(&mut res).ok()?;
        Some(res[0])
    }
}

/// A wrapper around a seeder that yields individual bits.
///
/// If you read past the first `None` this may waste bytes from
/// the underlying seeder (if there are any). If this is a
/// concern you should fuse it.
pub struct BitIter<'s, S: Seeder> {
    seeder: &'s mut S,
    last_u8: u8,
    bit_idx: usize,
}

impl<'s, S: Seeder> Iterator for BitIter<'s, S> {
    type Item = bool;
    fn next(&mut self) -> Option<bool> {
        let mask = if self.bit_idx == 8 {
            self.last_u8 = self.seeder.extract_u8()?;
            self.bit_idx = 0;
            1
        } else {
            self.bit_idx += 1;
            1 << (self.bit_idx - 1)
        };

        Some(self.last_u8 & mask != 0)
    }
}

#[allow(non_camel_case_types)]
pub enum u2 {
    _0,
    _1,
    _2,
    _3,
}

#[allow(non_camel_case_types)]
pub enum u3 {
    _0,
    _1,
    _2,
    _3,
    _4,
    _5,
    _6,
    _7,
}

impl<'s, S: Seeder> BitIter<'s, S> {
    pub fn next_u2(&mut self) -> Option<u2> {
        match (self.next()?, self.next()?) {
            (false, false) => Some(u2::_0),
            (false, true) => Some(u2::_1),
            (true, false) => Some(u2::_2),
            (true, true) => Some(u2::_3),
        }
    }

    pub fn next_u3(&mut self) -> Option<u3> {
        match (self.next()?, self.next()?, self.next()?) {
            (false, false, false) => Some(u3::_0),
            (false, false, true) => Some(u3::_1),
            (false, true, false) => Some(u3::_2),
            (false, true, true) => Some(u3::_3),
            (true, false, false) => Some(u3::_4),
            (true, false, true) => Some(u3::_5),
            (true, true, false) => Some(u3::_6),
            (true, true, true) => Some(u3::_7),
        }
    }
}
