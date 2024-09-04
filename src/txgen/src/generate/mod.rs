mod elements;
mod pubkey;
mod simplicity;
mod testtx;

use crate::Seeder;
pub use testtx::Transaction as TestTransaction;

pub struct Sampled<D> {
    data: D,
    size: usize,
}

impl<D> Sampled<D> {
    pub fn into_data(self) -> D {
        self.data
    }

    pub fn data(&self) -> &D {
        &self.data
    }

    pub fn size(&self) -> usize {
        self.size
    }

    fn single(data: D) -> Self {
        Sampled {
            data,
            size: std::mem::size_of::<D>(),
        }
    }

    fn map<E, F: FnOnce(D) -> E>(self, f: F) -> Sampled<E> {
        Sampled {
            data: f(self.data),
            size: self.size,
        }
    }
}

pub trait Generate: Sized {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>>;

    fn sample_then_map<Other, S: Seeder, F: Fn(Self) -> Other>(
        s: &mut S,
        f: F,
    ) -> Option<Sampled<Other>> {
        Self::sample(s).map(|samp| samp.map(f))
    }
}

macro_rules! generate_int {
    ($ty:ty) => {
        impl Generate for $ty {
            fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
                let mut ret = 0;
                for _ in 0..::core::mem::size_of::<$ty>() {
                    ret <<= 8;
                    ret += <$ty>::from(s.extract_u8()?);
                }
                Some(Sampled::single(ret))
            }
        }
    };
}

generate_int!(u16);
generate_int!(u32);
generate_int!(u64);
generate_int!(usize);
generate_int!(i16);
generate_int!(i32);
generate_int!(i64);
generate_int!(isize);

impl Generate for u8 {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        s.extract_u8().map(Sampled::single)
    }
}

macro_rules! generate_array {
    ($n:expr) => {
        impl Generate for [u8; $n] {
            fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
                let switch = s.extract_u8()?;
                if switch & 3 == 0 {
                    Some(Sampled {
                        data: [0; $n],
                        size: $n,
                    })
                } else if switch & 3 == 0 {
                    Some(Sampled {
                        data: [0xff; $n],
                        size: $n,
                    })
                } else {
                    let mut ret = [0; $n];
                    for byte in &mut ret {
                        *byte = s.extract_u8()?;
                    }
                    Some(Sampled {
                        data: ret,
                        size: $n,
                    })
                }
            }
        }
    };
}
generate_array!(1);
generate_array!(2);
generate_array!(4);
generate_array!(8);
generate_array!(16);
generate_array!(20);
generate_array!(32);
generate_array!(33);
generate_array!(64);
generate_array!(65);

impl<T: Generate> Generate for Box<T> {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        Generate::sample_then_map(s, Box::new)
    }
}

impl<T: Generate> Generate for Option<T> {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        // With options we do a 50-50 Some/None split
        if s.extract_u8()? & 1 == 0 {
            Generate::sample_then_map(s, Some)
        } else {
            Some(Sampled::single(None))
        }
    }
}

/*
// We can't really control the size of Vec<Vec<u8>> so set this to something
// where n^2 is still a reasonableish amount of RAM.
//const MAX_VEC_SIZE: usize = 1024 * 1024;
const MAX_VEC_SIZE: usize = 8 * 1024;

impl<T: Generate> Generate for Vec<T> {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        // Build the vector by concatenating uniformly 0-to-127-byte sized vectors,
        // interpreting 128 or higher as "stop".
        let mut ret = Sampled {
            data: Vec::with_capacity(128),
            size: 0,
        };

        loop {
            let n = s.extract_u8()?;
            if n & 0x80 == 0x80 || n == 0 { return Some(ret) }
            for _ in 0..n {
                let sample = <T as Generate>::sample(s)?;
                ret.size += sample.size;
                ret.data.push(sample.data);

                if sample.size > MAX_VEC_SIZE {
                    return Some(ret)
                }
            }
        }
    }
}
*/

impl Generate for Vec<u8> {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        let byte1 = s.extract_u8()?;
        let byte2 = s.extract_u8()?;
        let size = (usize::from(byte1 & 0x0f) << 8) + usize::from(byte2);
        assert!(size < 0x1000);

        let mut rng_byte = byte1 >> 4;
        let mut data = Vec::with_capacity(size);
        for _ in 0..size {
            rng_byte = rng_byte.wrapping_mul(91).wrapping_add(7);
            data.push(rng_byte);
        }
        Some(Sampled { data, size })
    }
}

impl Generate for Vec<Vec<u8>> {
    fn sample<S: Seeder>(s: &mut S) -> Option<Sampled<Self>> {
        let len = usize::from(s.extract_u8()?);

        let mut size = 0;
        let mut data = Vec::with_capacity(size);
        for _ in 0..len {
            let samp = Vec::<u8>::sample(s)?;
            data.push(samp.data);
            size += samp.size;
        }

        Some(Sampled { data, size })
    }
}
