#[cfg(not(target_os = "zkvm"))]
use core::convert::TryInto;

const PLEN: usize = 25;
const DEFAULT_ROUND_COUNT: usize = 24;

#[inline(always)]
fn xor_block_into_state(state: &mut [u64; PLEN], block: &[u8]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        openvm_keccak256_guest::native_xorin(
            state.as_mut_ptr() as *mut u8,
            block.as_ptr(),
            block.len(),
        );
    }
    #[cfg(not(target_os = "zkvm"))]
    for (b, s) in block.chunks_exact(8).zip(state.iter_mut()) {
        *s ^= u64::from_le_bytes(b.try_into().unwrap());
    }
}

#[inline(always)]
fn p1600(state: &mut [u64; PLEN], round_count: usize) {
    // The openvm keccak256 zkVM extension only implements the standard 24-round
    // Keccak-f[1600]; reduced-round Keccak-p variants fall back to software.
    #[cfg(target_os = "zkvm")]
    if round_count == DEFAULT_ROUND_COUNT {
        unsafe {
            openvm_keccak256_guest::native_keccakf(state.as_mut_ptr() as *mut u8);
        }
        return;
    }
    keccak::p1600(state, round_count);
}

#[derive(Clone)]
pub(crate) struct Sha3State {
    pub state: [u64; PLEN],
    round_count: usize,
}

impl Default for Sha3State {
    fn default() -> Self {
        Self {
            state: [0u64; PLEN],
            round_count: DEFAULT_ROUND_COUNT,
        }
    }
}

impl Sha3State {
    pub(crate) fn new(round_count: usize) -> Self {
        Self {
            state: [0u64; PLEN],
            round_count,
        }
    }

    #[inline(always)]
    pub(crate) fn absorb_block(&mut self, block: &[u8]) {
        debug_assert_eq!(block.len() % 8, 0);
        xor_block_into_state(&mut self.state, block);
        p1600(&mut self.state, self.round_count);
    }

    #[inline(always)]
    pub(crate) fn as_bytes(&self, out: &mut [u8]) {
        for (o, s) in out.chunks_mut(8).zip(self.state.iter()) {
            o.copy_from_slice(&s.to_le_bytes()[..o.len()]);
        }
    }

    #[inline(always)]
    pub(crate) fn permute(&mut self) {
        p1600(&mut self.state, self.round_count);
    }
}
