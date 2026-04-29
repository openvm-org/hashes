use openvm_sha2_guest::zkvm_sha256_impl;

pub(crate) fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    let state_ptr = state.as_mut_ptr().cast::<u8>();
    for block in blocks {
        // SAFETY: `state` and `block` point to valid buffers of at least 32 and
        // 64 bytes respectively. The intrinsic tolerates `state == output`.
        // `target_os = "zkvm"` is little-endian (guarded by `compile_error!` in
        // `lib.rs`), so the u32 state matches the LE word layout the VM expects.
        unsafe {
            zkvm_sha256_impl(state_ptr.cast_const(), block.as_ptr(), state_ptr);
        }
    }
}
