#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use hex::FromHex;
use sha2::{Digest, Sha256, Sha384, Sha512};

openvm::entry!(main);

fn verify_hash<D: Digest>(input_hex: &str, expected_hex: &str) {
    let input = Vec::from_hex(input_hex).unwrap();
    let expected = Vec::from_hex(expected_hex).unwrap();
    let output = D::digest(&input);
    assert_eq!(output[..], expected[..]);
}

fn main() {
    verify_hash::<Sha256>(
        "5a86b737eaea8ee976a0a24da63e7ed7eefad18a101c1211e2b3650c5187c2a8\
         a650547208251f6d4237e661c7bf4c77f335390394c37fa1a9f9be836ac28509",
        "42e61e174fbb3897d6dd6cef3dd2802fe67b331953b06114a65c772859dfc1aa",
    );

    verify_hash::<Sha384>(
        "3bf52cc5ee86b9a0190f390a5c0366a560b557000dbe5115fd9ee11630a62769\
         011575f15881198f227876e8fe685a6939bc8b89fd48a34ec5e71e131462b288\
         6794dffa68ccc6d564733e67ffef25e627c6f4b5460796e3bce67bf58ca6e8e5\
         55bc916a8531697ac948b90dc8616f25101db90b50c3d3dbc9e21e42ff387187",
        "12b6cb35eda92ee37356ddee77781a17b3d90e563824a984faffc6fdd1693bd7\
         626039635563cfc3b9a2b00f9c65eefd",
    );

    verify_hash::<Sha512>(
        "fd2203e467574e834ab07c9097ae164532f24be1eb5d88f1af7748ceff0d2c67\
         a21f4e4097f9d3bb4e9fbf97186e0db6db0100230a52b453d421f8ab9c9a6043\
         aa3295ea20d2f06a2f37470d8a99075f1b8a8336f6228cf08b5942fc1fb4299c\
         7d2480e8e82bce175540bdfad7752bc95b577f229515394f3ae5cec870a4b2f8",
        "a21b1077d52b27ac545af63b32746c6e3c51cb0cb9f281eb9f3580a6d4996d5c\
         9917d2a6e484627a9d5a06fa1b25327a9d710e027387fc3e07d7c4d14c6086cc",
    );
}
