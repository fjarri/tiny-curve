//! Implementing ECDSA traits requires a hash that has an output
//! equal to the size of the field element.
//! No real hash functions have an output that small, so we make our own.

use primeorder::elliptic_curve::generic_array::{typenum, GenericArray};
use sha2::{
    digest::{
        core_api::BlockSizeUser, Digest, FixedOutput, FixedOutputReset, HashMarker, Output,
        OutputSizeUser, Reset, Update,
    },
    Sha256,
};

#[derive(Debug, Clone, Default)]
pub struct TinyHash(Sha256);

impl HashMarker for TinyHash {}

impl Update for TinyHash {
    fn update(&mut self, data: &[u8]) {
        Update::update(&mut self.0, data)
    }
}

impl FixedOutput for TinyHash {
    fn finalize_into(self, out: &mut Output<Self>) {
        let full_output = self.0.finalize();
        AsMut::<[u8]>::as_mut(out).copy_from_slice(&full_output[..8])
    }
}

impl OutputSizeUser for TinyHash {
    type OutputSize = typenum::U8;
}

impl Reset for TinyHash {
    fn reset(&mut self) {
        Reset::reset(&mut self.0)
    }
}

impl FixedOutputReset for TinyHash {
    fn finalize_into_reset(
        &mut self,
        out: &mut GenericArray<u8, <Self as OutputSizeUser>::OutputSize>,
    ) {
        let mut full_output = Output::<Sha256>::default();
        FixedOutputReset::finalize_into_reset(&mut self.0, &mut full_output);
        AsMut::<[u8]>::as_mut(out).copy_from_slice(&full_output[..8]);
    }
}

impl BlockSizeUser for TinyHash {
    type BlockSize = <Sha256 as BlockSizeUser>::BlockSize;
}
