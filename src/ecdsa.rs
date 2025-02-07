use ecdsa::{
    hazmat::{DigestPrimitive, SignPrimitive, VerifyPrimitive},
    SignatureSize,
};
use primeorder::{
    elliptic_curve::{
        generic_array::ArrayLength, ops::Reduce, CurveArithmetic, FieldBytes, PrimeCurve,
    },
    AffinePoint, PrimeField,
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

impl VerifyPrimitive<TinyCurve16> for AffinePoint<TinyCurve16> {}

impl VerifyPrimitive<TinyCurve32> for AffinePoint<TinyCurve32> {}

impl VerifyPrimitive<TinyCurve64> for AffinePoint<TinyCurve64> {}

impl DigestPrimitive for TinyCurve16 {
    type Digest = TinyHash<2>;
}

impl DigestPrimitive for TinyCurve32 {
    type Digest = TinyHash<4>;
}

impl DigestPrimitive for TinyCurve64 {
    type Digest = TinyHash<8>;
}

#[cfg(test)]
mod tests {
    use ecdsa::{SigningKey, VerifyingKey};
    use rand_core::OsRng;

    use crate::TinyCurve64;

    #[test]
    fn sign() {
        let prehash = b"123456781234567812345678";
        let sk = SigningKey::<TinyCurve64>::random(&mut OsRng);

        let (signature, recovery_id) = sk.sign_prehash_recoverable(prehash).unwrap();
        let vk = VerifyingKey::recover_from_prehash(prehash, &signature, recovery_id).unwrap();
        assert_eq!(sk.verifying_key(), &vk);
    }
}
