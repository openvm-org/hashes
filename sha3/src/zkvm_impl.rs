use core::fmt;

use digest::{
    FixedOutput, FixedOutputReset, HashMarker, Output, OutputSizeUser, Reset, Update,
    block_api::BlockSizeUser,
    consts::{U32, U136},
};
use openvm_keccak256::Keccak256 as InnerKeccak256;

/// Keccak-256 hasher backed by the OpenVM zkVM implementation.
#[derive(Clone)]
pub struct Keccak256 {
    inner: InnerKeccak256,
}

impl Default for Keccak256 {
    fn default() -> Self {
        Self {
            inner: InnerKeccak256::new(),
        }
    }
}

impl BlockSizeUser for Keccak256 {
    type BlockSize = U136;
}

impl Update for Keccak256 {
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }
}

impl OutputSizeUser for Keccak256 {
    type OutputSize = U32;
}

impl FixedOutput for Keccak256 {
    fn finalize_into(self, out: &mut Output<Self>) {
        // SAFETY: Output<Self> is GenericArray<u8, U32>, always exactly 32 bytes.
        unsafe { self.inner.finalize(out) };
    }
}

impl HashMarker for Keccak256 {}

impl Reset for Keccak256 {
    fn reset(&mut self) {
        *self = Self::default();
    }
}

impl FixedOutputReset for Keccak256 {
    fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        FixedOutput::finalize_into(self.clone(), out);
        Reset::reset(self);
    }
}

impl fmt::Debug for Keccak256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Keccak256 { ... }")
    }
}
