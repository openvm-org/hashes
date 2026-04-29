fn main() {
    println!("cargo::rustc-check-cfg=cfg(keccak_backend, values(\"soft\"))");
}
