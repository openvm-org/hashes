#[cfg(feature = "std")]
extern crate std;

use core::fmt;
#[cfg(feature = "oid")]
use digest::const_oid::{AssociatedOid, ObjectIdentifier};
use digest::{
    consts::{U128, U32, U48, U64},
    core_api::BlockSizeUser,
    FixedOutput, FixedOutputReset, HashMarker, Output, OutputSizeUser, Reset, Update,
};
use openvm_sha2::{Sha256 as InnerSha256, Sha384 as InnerSha384, Sha512 as InnerSha512};

macro_rules! impl_zkvm_sha {
    ($name:ident, $inner:ty, $output_size:ty, $block_size:ty, $oid:expr) => {
        /// Wrapper around the openvm zkvm implementation.
        #[derive(Clone)]
        pub struct $name {
            inner: $inner,
        }

        impl Default for $name {
            fn default() -> Self {
                Self {
                    inner: <$inner>::new(),
                }
            }
        }

        impl BlockSizeUser for $name {
            type BlockSize = $block_size;
        }

        impl Update for $name {
            fn update(&mut self, data: &[u8]) {
                self.inner.update(data);
            }
        }

        impl OutputSizeUser for $name {
            type OutputSize = $output_size;
        }

        impl FixedOutput for $name {
            fn finalize_into(self, out: &mut Output<Self>) {
                out.copy_from_slice(&self.inner.finalize());
            }
        }

        impl HashMarker for $name {}

        impl Reset for $name {
            fn reset(&mut self) {
                *self = Self::default();
            }
        }

        impl FixedOutputReset for $name {
            fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
                FixedOutput::finalize_into(self.clone(), out);
                Reset::reset(self);
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

        #[cfg(feature = "oid")]
        impl AssociatedOid for $name {
            const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap($oid);
        }

        #[cfg(feature = "std")]
        impl std::io::Write for $name {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                Update::update(self, buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
    };
}

impl_zkvm_sha!(Sha256, InnerSha256, U32, U64, "2.16.840.1.101.3.4.2.1");
impl_zkvm_sha!(Sha384, InnerSha384, U48, U128, "2.16.840.1.101.3.4.2.2");
impl_zkvm_sha!(Sha512, InnerSha512, U64, U128, "2.16.840.1.101.3.4.2.3");
