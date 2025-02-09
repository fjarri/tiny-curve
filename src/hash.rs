//! Implementing ECDSA traits requires a hash that has an output
//! equal to the size of the field element.
//! No real hash functions have an output that small, so we make our own.

use primeorder::elliptic_curve::generic_array::GenericArray;
use sha2::{
    digest::{
        core_api::BlockSizeUser, Digest, FixedOutput, FixedOutputReset, HashMarker, Output,
        OutputSizeUser, Reset, Update,
    },
    Sha256,
};

use crate::prime_field::ReprSizeTypenum;

// TODO: this only needs the `BYTES` parametrization to work around
// https://github.com/RustCrypto/signatures/issues/880
// When `ecdsa` 0.17 is out, this can be removed, along with zeroizing the beginning of the hash.
#[derive(Debug, Clone, Default)]
pub struct TinyHash<const BYTES: usize>(Sha256);

impl<const BYTES: usize> HashMarker for TinyHash<BYTES> {}

impl<const BYTES: usize> Update for TinyHash<BYTES> {
    fn update(&mut self, data: &[u8]) {
        Update::update(&mut self.0, data)
    }
}

impl<const BYTES: usize> FixedOutput for TinyHash<BYTES> {
    fn finalize_into(self, out: &mut Output<Self>) {
        let full_output = self.0.finalize();
        let output_len = out.len();
        debug_assert!(output_len <= full_output.len());
        AsMut::<[u8]>::as_mut(out).copy_from_slice(&full_output[..output_len]);
        AsMut::<[u8]>::as_mut(out)[..output_len - BYTES].fill(0);
    }
}

impl<const BYTES: usize> OutputSizeUser for TinyHash<BYTES> {
    type OutputSize = ReprSizeTypenum;
}

impl<const BYTES: usize> Reset for TinyHash<BYTES> {
    fn reset(&mut self) {
        Reset::reset(&mut self.0)
    }
}

impl<const BYTES: usize> FixedOutputReset for TinyHash<BYTES> {
    fn finalize_into_reset(
        &mut self,
        out: &mut GenericArray<u8, <Self as OutputSizeUser>::OutputSize>,
    ) {
        <Self as FixedOutput>::finalize_into(self.clone(), out);
        <Self as Reset>::reset(self);
    }
}

impl<const BYTES: usize> BlockSizeUser for TinyHash<BYTES> {
    type BlockSize = <Sha256 as BlockSizeUser>::BlockSize;
}
