#![no_main]
#![no_std]

// Known-answer tests for every public SHA-3 / Keccak variant.
//
// Every long-input assertion hashes the same 2040-bit (255-byte) message from
// the Keccak team's "Known-answer and Monte Carlo test results" v3.0,
// 2011-01-14 (KeccakKAT-3.zip, ShortMsgKAT_{224,256,384,512}.txt, Len = 2040).
//
// Expected outputs:
// - Keccak-{224,256,384,512}: taken from the same KeccakKAT-3 files (official,
//   from the Keccak design team).
// - SHA3-{224,256,384,512} and SHAKE{128,256}: taken from this crate's own
//   upstream test fixtures at sha3/tests/data/*.blb (longest vector). The
//   Keccak team's KATs predate the SHA-3 padding change, so no independent
//   NIST CAVS vector exists for this exact 2040-bit message.
//
// Empty-input assertions come from NIST CAVP SHA3/SHAKE ShortMsg rsp files
// (sha-3bytetestvectors.zip / shakebytetestvectors.zip, Len = 0) for the
// SHA-3 / SHAKE variants and from KeccakKAT-3 ShortMsgKAT_*.txt (Len = 0) for
// the Keccak variants. Keccak256Full's empty-input value comes from
// sha3/tests/data/keccak_256_full_kat.blb.

extern crate alloc;

use hex_literal::hex;
use sha3::{
    Digest, Keccak224, Keccak256, Keccak256Full, Keccak384, Keccak512, Sha3_224, Sha3_256,
    Sha3_384, Sha3_512, Shake128, Shake256,
    digest::{ExtendableOutput, Update},
};

openvm::entry!(main);

const LONG_MSG: [u8; 255] = hex!(
    "3a3a819c48efde2ad914fbf00e18ab6bc4f14513ab27d0c178a188b61431e7f5"
    "623cb66b23346775d386b50e982c493adbbfc54b9a3cd383382336a1a0b2150a"
    "15358f336d03ae18f666c7573d55c4fd181c29e6ccfde63ea35f0adf5885cfc0"
    "a3d84a2b2e4dd24496db789e663170cef74798aa1bbcd4574ea0bba40489d764"
    "b2f83aadc66b148b4a0cd95246c127d5871c4f11418690a5ddf01246a0c80a43"
    "c70088b6183639dcfda4125bd113a8f49ee23ed306faac576c3fb0c1e256671d"
    "817fc2534a52f5b439f72e424de376f4c565cca82307dd9ef76da5b7c4eb7e08"
    "5172e328807c02d011ffbf33785378d79dc266f6a5be6bb0e4a92eceebaeb1"
);

fn main() {
    // --- SHA3-224 ---
    assert_eq!(
        Sha3_224::digest(b"")[..],
        hex!("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7")[..],
    );
    assert_eq!(
        Sha3_224::digest(&LONG_MSG)[..],
        hex!("94689ea9f347dda8dd798a858605868743c6bd03a6a65c6085d52bed")[..],
    );

    // --- SHA3-256 ---
    assert_eq!(
        Sha3_256::digest(b"")[..],
        hex!("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")[..],
    );
    assert_eq!(
        Sha3_256::digest(&LONG_MSG)[..],
        hex!("c11f3522a8fb7b3532d80b6d40023a92b489addad93bf5d64b23f35e9663521c")[..],
    );

    // --- SHA3-384 ---
    assert_eq!(
        Sha3_384::digest(b"")[..],
        hex!(
            "0c63a75b845e4f7d01107d852e4c2485"
            "c51a50aaaa94fc61995e71bbee983a2a"
            "c3713831264adb47fb6bd1e058d5f004"
        )[..],
    );
    assert_eq!(
        Sha3_384::digest(&LONG_MSG)[..],
        hex!(
            "128dc611762be9b135b3739484cfaadc"
            "a7481d68514f3dfd6f5d78bb1863ae68"
            "130835cdc7061a7ed964b32f1db75ee1"
        )[..],
    );

    // --- SHA3-512 ---
    assert_eq!(
        Sha3_512::digest(b"")[..],
        hex!(
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
            "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        )[..],
    );
    assert_eq!(
        Sha3_512::digest(&LONG_MSG)[..],
        hex!(
            "6e8b8bd195bdd560689af2348bdc74ab7cd05ed8b9a57711e9be71e9726fda45"
            "91fee12205edacaf82ffbbaf16dff9e702a708862080166c2ff6ba379bc7ffc2"
        )[..],
    );

    // --- Keccak-224 ---
    assert_eq!(
        Keccak224::digest(b"")[..],
        hex!("f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd")[..],
    );
    assert_eq!(
        Keccak224::digest(&LONG_MSG)[..],
        hex!("5af56987ea9cf11fcd0eac5ebc14b037365e9b1123e31cb2dfc7929a")[..],
    );

    // --- Keccak-256 ---
    assert_eq!(
        Keccak256::digest(b"")[..],
        hex!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")[..],
    );
    assert_eq!(
        Keccak256::digest(&LONG_MSG)[..],
        hex!("348fb774adc970a16b1105669442625e6adaa8257a89effdb5a802f161b862ea")[..],
    );

    // --- Keccak-384 ---
    assert_eq!(
        Keccak384::digest(b"")[..],
        hex!(
            "2c23146a63a29acf99e73b88f8c24eaa"
            "7dc60aa771780ccc006afbfa8fe2479b"
            "2dd2b21362337441ac12b515911957ff"
        )[..],
    );
    assert_eq!(
        Keccak384::digest(&LONG_MSG)[..],
        hex!(
            "6bff1c8405a3fe594e360e3bccea1ebc"
            "d509310dc79b9e45c263783d7a5dd662"
            "c6789b18bd567dbdda1554f5bee6a860"
        )[..],
    );

    // --- Keccak-512 ---
    assert_eq!(
        Keccak512::digest(b"")[..],
        hex!(
            "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304"
            "c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e"
        )[..],
    );
    assert_eq!(
        Keccak512::digest(&LONG_MSG)[..],
        hex!(
            "81950e7096d31d4f22e3db71cac725bf59e81af54c7ca9e6aeee71c010fc5467"
            "466312a01aa5c137cfb140646941556796f612c9351268737c7e9a2b9631d1fa"
        )[..],
    );

    // --- Keccak256Full (200-byte output; CryptoNight variant; no published
    //     KAT for this 2040-bit input, so only the empty-input vector runs). ---
    assert_eq!(
        Keccak256Full::digest(b"")[..],
        hex!(
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
            "3dbb9a2cd87ca974b9a2b0ec61119bcb5cedf9c0c411221f6141a25f17c60d82"
            "d24680abbcbfba815b762b24b751d5b1e85325ba5e6df23c10725bfe986ace3b"
            "a2d24535a79f7dbabb153bb0d33c0dfa09cec712ebd7fe3b49a9194e859c82eb"
            "ff11a645651a5d1b726be100f44641069fab7164e13487fe3609bbeebd88309c"
            "baacb2a7ecb8e8de2145cf1db7623b16916d7210991b576bbe182362cf22fab7"
            "d7af9f77f71afea3"
        )[..],
    );

    // --- SHAKE128 (16-byte output window) ---
    let mut out16 = [0u8; 16];
    let mut h = Shake128::default();
    Update::update(&mut h, b"");
    h.finalize_xof_into(&mut out16);
    assert_eq!(out16, hex!("7f9c2ba4e88f827d616045507605853e"));

    let mut out16 = [0u8; 16];
    let mut h = Shake128::default();
    Update::update(&mut h, &LONG_MSG);
    h.finalize_xof_into(&mut out16);
    assert_eq!(out16, hex!("14236e75b9784df4f57935f945356cbe"));

    // --- SHAKE256 (32-byte output window) ---
    let mut out32 = [0u8; 32];
    let mut h = Shake256::default();
    Update::update(&mut h, b"");
    h.finalize_xof_into(&mut out32);
    assert_eq!(
        out32,
        hex!("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"),
    );

    let mut out32 = [0u8; 32];
    let mut h = Shake256::default();
    Update::update(&mut h, &LONG_MSG);
    h.finalize_xof_into(&mut out32);
    assert_eq!(
        out32,
        hex!("8a5199b4a7e133e264a86202720655894d48cff344a928cf8347f48379cef347"),
    );
}
