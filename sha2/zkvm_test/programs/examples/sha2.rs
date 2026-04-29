#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use hex::FromHex;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

openvm::entry!(main);

fn verify_hash<D: Digest>(input: &[u8], expected_hex: &str) {
    let expected = Vec::from_hex(expected_hex).unwrap();
    let output = D::digest(input);
    assert_eq!(output[..], expected[..]);
}

// Test vectors from FIPS 180-4. The 112-byte input is multi-block for both the
// SHA-256 family (2 compressed blocks after padding) and the SHA-512 family
// (2 compressed blocks after padding), so it exercises the compress loop in
// the zkVM backend, not just a single intrinsic call.
fn main() {
    let short = b"abc";
    let long: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

    verify_hash::<Sha224>(
        short,
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
    );
    verify_hash::<Sha256>(
        short,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    verify_hash::<Sha384>(
        short,
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
         8086072ba1e7cc2358baeca134c825a7",
    );
    verify_hash::<Sha512>(
        short,
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    );
    verify_hash::<Sha512_224>(
        short,
        "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
    );
    verify_hash::<Sha512_256>(
        short,
        "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
    );

    verify_hash::<Sha224>(
        long,
        "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3",
    );
    verify_hash::<Sha256>(
        long,
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
    );
    verify_hash::<Sha384>(
        long,
        "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712\
         fcc7c71a557e2db966c3e9fa91746039",
    );
    verify_hash::<Sha512>(
        long,
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
         501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
    );
    verify_hash::<Sha512_224>(
        long,
        "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9",
    );
    verify_hash::<Sha512_256>(
        long,
        "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a",
    );
}
