use ecdsa::{
    hazmat::{DigestPrimitive, SignPrimitive},
    SignatureSize,
};
use primeorder::{
    elliptic_curve::{
        generic_array::ArrayLength, ops::Reduce, CurveArithmetic, FieldBytes, PrimeCurve,
    },
    PrimeField,
};

use crate::{
    curve16::TinyCurve16,
    curve32::TinyCurve32,
    curve64::TinyCurve64,
    hash::TinyHash,
    prime_field::FieldElement,
    traits::{Modulus, PrimeFieldConstants, PrimitiveUint},
};

impl<C, T, const M: u64> SignPrimitive<C> for FieldElement<T, M>
where
    T: PrimitiveUint,
    Modulus<T, M>: PrimeFieldConstants<T>,
    C: PrimeCurve + CurveArithmetic<Scalar = Self>,
    SignatureSize<C>: ArrayLength<u8>,
    Self: Reduce<C::Uint, Bytes = FieldBytes<C>>
        + PrimeField<Repr = FieldBytes<C>>
        + Into<FieldBytes<C>>,
{
}

impl DigestPrimitive for TinyCurve16 {
    type Digest = TinyHash;
}

impl DigestPrimitive for TinyCurve32 {
    type Digest = TinyHash;
}

impl DigestPrimitive for TinyCurve64 {
    type Digest = TinyHash;
}

#[cfg(test)]
mod tests {
    use ecdsa::SigningKey;
    use rand_core::OsRng;

    use crate::TinyCurve64;

    #[test]
    fn sign() {
        let prehash = b"12345678";
        let sk = SigningKey::<TinyCurve64>::random(&mut OsRng);
        let _signature = sk.sign_prehash_recoverable(prehash);
    }
}
