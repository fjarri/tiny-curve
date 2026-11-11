use primeorder::{
    AffinePoint, FieldArithmetic, PrimeCurve, PrimeCurveParams, ProjectivePoint,
    array::typenum,
    elliptic_curve::{
        Curve, CurveArithmetic, FieldBytesSize, bigint::Odd, point::PointCompression,
        scalar::FromUintUnchecked,
    },
    mul_backend::VariableOnly,
    point_arithmetic::EquationAIsMinusThree,
};

#[cfg(feature = "ecdsa")]
use ::{
    ecdsa::{DigestAlgorithm, EcdsaCurve},
    sha2::Sha256,
};

#[cfg(feature = "pkcs8")]
use primeorder::elliptic_curve::pkcs8::{AssociatedOid, ObjectIdentifier};

use crate::{
    prime_field::{FieldElement, ReprUint},
    traits::{Modulus, PrimeFieldConstants},
};

const ORDER: u64 = 0xffffffff1a0a85df;
const FIELD_MODULUS: u64 = 0xfffffffffffffc7f;

impl PrimeFieldConstants<u64> for Modulus<u64, FIELD_MODULUS> {
    type ReprSize = FieldBytesSize<TinyCurve64>;
    const MODULUS_STR: &'static str = "fffffffffffffc7f";
    const MODULUS: u64 = FIELD_MODULUS;
    const NUM_BITS: u32 = 64;
    const CAPACITY: u32 = 63;
    const TWO_INV: u64 = 0x7ffffffffffffe40;
    const MULTIPLICATIVE_GENERATOR: u64 = 3;
    const S: u32 = 1;
    const ROOT_OF_UNITY: u64 = 0xfffffffffffffc7e;
    const ROOT_OF_UNITY_INV: u64 = 0xfffffffffffffc7e;
    const DELTA: u64 = 9;
    type WnafStorageSize = typenum::U65;
}

impl PrimeFieldConstants<u64> for Modulus<u64, ORDER> {
    type ReprSize = FieldBytesSize<TinyCurve64>;
    const MODULUS_STR: &'static str = "ffffffff1a0a85df";
    const MODULUS: u64 = ORDER;
    const NUM_BITS: u32 = 64;
    const CAPACITY: u32 = 63;
    const TWO_INV: u64 = 0x7fffffff8d0542f0;
    const MULTIPLICATIVE_GENERATOR: u64 = 5;
    const S: u32 = 1;
    const ROOT_OF_UNITY: u64 = 0xffffffff1a0a85de;
    const ROOT_OF_UNITY_INV: u64 = 0xffffffff1a0a85de;
    const DELTA: u64 = 25;
    type WnafStorageSize = typenum::U65;
}

/// An elliptic curve with a 64-bit order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct TinyCurve64;

impl Curve for TinyCurve64 {
    type FieldBytesSize = typenum::U8;
    type Uint = ReprUint;
    const ORDER: Odd<Self::Uint> = Self::Uint::from_u64(ORDER)
        .to_odd()
        .expect_copied("the curve order is odd");
}

impl FieldArithmetic for TinyCurve64 {
    type FieldElement = FieldElement<u64, FIELD_MODULUS>;
}

impl CurveArithmetic for TinyCurve64 {
    type Scalar = FieldElement<u64, ORDER>;
    type AffinePoint = AffinePoint<Self>;
    type ProjectivePoint = ProjectivePoint<Self>;
}

// `From`/`TryFrom` conversions between the scalar and `NonZeroScalar`/`ScalarValue`/`SecretKey`,
// and `Mul`/`MulVartime` impls for the scalar with affine and projective points.
primeorder::elliptic_curve::scalar_impls!(TinyCurve64, FieldElement<u64, ORDER>);

impl PrimeCurve for TinyCurve64 {}

impl PrimeCurveParams for TinyCurve64 {
    type Backend = VariableOnly;
    type PointArithmetic = EquationAIsMinusThree;

    const EQUATION_A: Self::FieldElement = FieldElement::new_unchecked(FIELD_MODULUS - 3);
    const EQUATION_B: Self::FieldElement = FieldElement::new_unchecked(6);
    const GENERATOR: (Self::FieldElement, Self::FieldElement) = (
        FieldElement::new_unchecked(11619086278950426528),
        FieldElement::new_unchecked(2765382488766937725),
    );
}

impl PointCompression for TinyCurve64 {
    const COMPRESS_POINTS: bool = true;
}

#[cfg(feature = "ecdsa")]
impl EcdsaCurve for TinyCurve64 {
    const NORMALIZE_S: bool = false;
}

#[cfg(feature = "ecdsa")]
impl DigestAlgorithm for TinyCurve64 {
    type Digest = Sha256;
}

#[cfg(feature = "pkcs8")]
impl AssociatedOid for TinyCurve64 {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.202767.3");
}

#[cfg(test)]
mod tests {
    use primeorder::array::typenum::Unsigned;
    use primeorder::{
        PrimeField,
        elliptic_curve::{
            CurveArithmetic, Field, FieldBytesSize, Group, ProjectivePoint, array::Array,
            ops::Reduce,
        },
    };
    use proptest::prelude::*;
    use rand::rngs::SysRng;
    use rand_core::UnwrapErr;

    use super::TinyCurve64;
    use crate::prime_field::ReprUint;

    type Scalar = <TinyCurve64 as CurveArithmetic>::Scalar;
    type Point = ProjectivePoint<TinyCurve64>;

    #[test]
    fn identity() {
        let x = Scalar::random(&mut UnwrapErr(SysRng));
        let y = Scalar::ZERO - x;
        let p = Point::mul_by_generator(&x) + Point::mul_by_generator(&y);
        assert_eq!(p, Point::IDENTITY);
    }

    #[test]
    fn to_and_from_repr() {
        let mut repr = Array::<u8, FieldBytesSize<TinyCurve64>>::default();

        // `s` now contains the value `M - 1`.
        let s = -Scalar::new_unchecked(1);
        let s_uint: ReprUint = s.into();

        // Check that to_repr/from_repr work normally
        let s_uint_repr = s_uint.to_be_bytes();
        repr.copy_from_slice(
            &s_uint_repr[s_uint_repr.len() - FieldBytesSize::<TinyCurve64>::USIZE..],
        );
        let s_repr = s.to_repr();
        assert_eq!(repr, s_repr);
        assert_eq!(Scalar::from_repr(repr).unwrap(), s);

        // Now construct a representation of the value `M` (which would be out of range).
        // `M` still fits into the repr since the modulus is smaller than `2^(8 * repr.len())`.
        let x_uint = s_uint.wrapping_add(&ReprUint::ONE);
        let x_uint_repr = x_uint.to_be_bytes();
        repr.copy_from_slice(
            &x_uint_repr[x_uint_repr.len() - FieldBytesSize::<TinyCurve64>::USIZE..],
        );
        assert!(bool::from(Scalar::from_repr(repr).is_none()));
    }

    prop_compose! {
        /// Generate a random odd modulus.
        fn scalar()(n in any::<u64>()) -> Scalar {
            Scalar::reduce(&ReprUint::from(n))
        }
    }

    proptest! {
        #[test]
        fn mul_by_generator(x in scalar(), y in scalar()) {
            let p1 = Point::mul_by_generator(&x) + Point::mul_by_generator(&y);
            let p2 = Point::mul_by_generator(&(x + y));
            assert_eq!(p1, p2);
        }
    }
}

#[cfg(test)]
mod tests_scalar {
    use primeorder::{Field, elliptic_curve::CurveArithmetic};

    use super::TinyCurve64;
    use crate::prime_field::ReprUint;

    type F = <TinyCurve64 as CurveArithmetic>::Scalar;

    primefield::test_primefield!(F, ReprUint);
}

#[cfg(test)]
mod tests_field_element {
    use primeorder::{Field, FieldArithmetic};

    use super::TinyCurve64;
    use crate::prime_field::ReprUint;

    type F = <TinyCurve64 as FieldArithmetic>::FieldElement;

    primefield::test_primefield!(F, ReprUint);
}

#[cfg(all(test, feature = "ecdsa"))]
mod tests_ecdsa {
    use ecdsa::{SigningKey, VerifyingKey};
    use primeorder::elliptic_curve::Generate;
    use rand::rngs::SysRng;
    use rand_core::UnwrapErr;

    use super::TinyCurve64;

    #[test]
    fn sign_and_verify() {
        let prehash = b"123456781234567812345678";
        let sk = SigningKey::<TinyCurve64>::generate_from_rng(&mut UnwrapErr(SysRng));

        let (signature, recovery_id) = sk.sign_prehash_recoverable(prehash);
        let vk = VerifyingKey::recover_from_prehash(prehash, &signature, recovery_id).unwrap();
        assert_eq!(sk.verifying_key(), &vk);
    }
}

#[cfg(all(test, feature = "pkcs8"))]
mod tests_pkcs8 {
    use primeorder::elliptic_curve::Generate;
    use primeorder::elliptic_curve::{
        PublicKey, SecretKey,
        pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    };
    use rand::rngs::SysRng;
    use rand_core::UnwrapErr;

    use super::TinyCurve64;

    #[test]
    fn serialize_secret_key() {
        let sk = SecretKey::<TinyCurve64>::generate_from_rng(&mut UnwrapErr(SysRng));
        let der = sk.to_pkcs8_der().unwrap();
        let sk_back = SecretKey::<TinyCurve64>::from_pkcs8_der(der.as_bytes()).unwrap();
        assert_eq!(sk, sk_back);
    }

    #[test]
    fn serialize_public_key() {
        let sk = SecretKey::<TinyCurve64>::generate_from_rng(&mut UnwrapErr(SysRng));
        let pk = sk.public_key();
        let der = pk.to_public_key_der().unwrap();
        let pk_back = PublicKey::<TinyCurve64>::from_public_key_der(der.as_bytes()).unwrap();
        assert_eq!(pk, pk_back);
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests_serde {
    use primeorder::elliptic_curve::Generate;
    use primeorder::elliptic_curve::{PublicKey, SecretKey};
    use rand::rngs::SysRng;
    use rand_core::UnwrapErr;

    use super::TinyCurve64;

    #[test]
    fn serialize_public_key() {
        let sk = SecretKey::<TinyCurve64>::generate_from_rng(&mut UnwrapErr(SysRng));
        let pk = sk.public_key();
        let bytes = postcard::to_allocvec(&pk).unwrap();
        let pk_back: PublicKey<TinyCurve64> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(pk, pk_back);
    }

    #[cfg(feature = "ecdsa")]
    #[test]
    fn serialize_verifying_key() {
        let sk = SecretKey::<TinyCurve64>::generate_from_rng(&mut UnwrapErr(SysRng));
        let pk = sk.public_key();
        let vk = ecdsa::VerifyingKey::from(&pk);
        let bytes = postcard::to_allocvec(&vk).unwrap();
        let vk_back: ecdsa::VerifyingKey<TinyCurve64> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(vk, vk_back);
    }
}
