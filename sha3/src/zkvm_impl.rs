#[cfg(feature = "std")]
extern crate std;

use core::fmt;
use digest::{
    consts::{U136, U32},
    core_api::BlockSizeUser,
    FixedOutput, FixedOutputReset, HashMarker, Output, OutputSizeUser, Reset, Update,
};
use openvm_keccak256::Keccak256 as InnerKeccak256;

/// Keccak-256 hasher backed by the openvm zkvm implementation.
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

#[cfg(feature = "std")]
impl std::io::Write for Keccak256 {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Update::update(self, buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
