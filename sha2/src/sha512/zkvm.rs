use openvm_sha2_guest::zkvm_sha512_impl;

pub(crate) fn compress(state: &mut [u64; 8], blocks: &[[u8; 128]]) {
    let state_ptr = state.as_mut_ptr().cast::<u8>();
    for block in blocks {
        // SAFETY: `state` and `block` point to valid buffers of at least 64 and
        // 128 bytes respectively. The intrinsic tolerates `state == output`.
        // `target_os = "zkvm"` is little-endian (guarded by `compile_error!` in
        // `lib.rs`), so the u64 state matches the LE word layout the VM expects.
        unsafe {
            zkvm_sha512_impl(state_ptr.cast_const(), block.as_ptr(), state_ptr);
        }
    }
}
