// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/*!
 * An implementation of the RC4 (also sometimes called ARC4) stream cipher. THIS IMPLEMENTATION IS
 * NOT A FIXED TIME IMPLEMENTATION.
 */

use symmetriccipher::{StreamEncryptor, StreamDecryptor};

pub struct Rc4 {
    priv i: uint,
    priv j: uint,
    priv state: [u8, ..256]
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Rc4 {
        assert!(key.len() >= 1 && key.len() <= 256);
        let mut rc4 = Rc4 { i: 0, j: 0, state: [0, ..256] };
        for (i, x) in rc4.state.mut_iter().enumerate() {
            *x = i as u8;
        }
        let mut j: u8 = 0;
        for i in range(0u, 256) {
            j = j + rc4.state[i] + key[i % key.len()];
            rc4.state.swap(i, j as uint);
        }
        rc4
    }
}

fn process(rc4: &mut Rc4, input: &[u8], out: &mut [u8]) {
    assert!(input.len() == out.len());
    for (x, y) in input.iter().zip(out.mut_iter()) {
        rc4.i = (rc4.i + 1) % 256;
        rc4.j = (rc4.j + rc4.state[rc4.i] as uint) % 256;
        rc4.state.swap(rc4.i, rc4.j);
        let k = rc4.state[(rc4.state[rc4.i] + rc4.state[rc4.j]) as uint];
        *y = *x ^ k;
    }
}

impl StreamEncryptor for Rc4 {
    fn encrypt(&mut self, input: &[u8], out: &mut [u8]) {
        process(self, input, out);
    }
}

impl StreamDecryptor for Rc4 {
    fn decrypt(&mut self, input: &[u8], out: &mut [u8]) {
        process(self, input, out);
    }
}

#[cfg(test)]
mod test {
    use std::vec;
    use rc4::Rc4;

    struct Test {
        key: ~str,
        input: ~str,
        output: ~[u8]
    }

    fn tests() -> ~[Test] {
        ~[
            Test {
                key: ~"Key",
                input: ~"Plaintext",
                output: ~[0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]
            },
            Test {
                key: ~"Wiki",
                input: ~"pedia",
                output: ~[0x10, 0x21, 0xBF, 0x04, 0x20]
            },
            Test {
                key: ~"Secret",
                input: ~"Attack at dawn",
                output: ~[0x45, 0xA0, 0x1F, 0x64, 0x5F, 0xC3, 0x5B,
                          0x38, 0x35, 0x52, 0x54, 0x4B, 0x9B, 0xF5]
            }
        ]
    }

    #[test]
    fn wikipedia_tests() {
        let tests = tests();
        for t in tests.iter() {
            let mut rc4 = Rc4::new(t.key.as_bytes());
            let mut result = vec::from_elem(t.output.len(), 0u8);
            rc4.encrypt(t.input.as_bytes(), result);
            assert!(result == t.output);
        }
    }
}

#[cfg(test)]
mod bench {
    use extra::test::BenchHarness;
    use rc4::Rc4;

    #[bench]
    pub fn rc4_10(bh: & mut BenchHarness) {
        let mut rc4 = Rc4::new("key".as_bytes());
        let input = [1u8, ..10];
        let mut output = [0u8, ..10];
        do bh.iter {
            rc4.encrypt(input, output);
        }
        bh.bytes = input.len() as u64;
    }

    #[bench]
    pub fn rc4_1k(bh: & mut BenchHarness) {
        let mut rc4 = Rc4::new("key".as_bytes());
        let input = [1u8, ..1024];
        let mut output = [0u8, ..1024];
        do bh.iter {
            rc4.encrypt(input, output);
        }
        bh.bytes = input.len() as u64;
    }

    #[bench]
    pub fn rc4_64k(bh: & mut BenchHarness) {
        let mut rc4 = Rc4::new("key".as_bytes());
        let input = [1u8, ..65536];
        let mut output = [0u8, ..65536];
        do bh.iter {
            rc4.encrypt(input, output);
        }
        bh.bytes = input.len() as u64;
    }
}
