use primeorder::{
    elliptic_curve::{
        point::PointCompression, Curve, CurveArithmetic, FieldBytes, FieldBytesEncoding,
    },
    point_arithmetic::EquationAIsMinusThree,
    AffinePoint, PrimeCurve, PrimeCurveParams, ProjectivePoint,
};

#[cfg(feature = "ecdsa")]
use ::ecdsa::hazmat::{DigestPrimitive, VerifyPrimitive};

#[cfg(feature = "pkcs8")]
use primeorder::elliptic_curve::pkcs8::{AssociatedOid, ObjectIdentifier};

use crate::{
    prime_field::{FieldElement, ReprSizeTypenum, ReprUint},
    traits::{Modulus, PrimeFieldConstants},
};

#[cfg(feature = "ecdsa")]
use crate::hash::TinyHash;

const ORDER: u64 = 0xffffffff1a0a85df;
const FIELD_MODULUS: u64 = 0xfffffffffffffc7f;

impl PrimeFieldConstants<u64> for Modulus<u64, FIELD_MODULUS> {
    type Repr = FieldBytes<TinyCurve64>;
    const MODULUS_STR: &'static str = "0xfffffffffffffc7f";
    const MODULUS: u64 = FIELD_MODULUS;
    const NUM_BITS: u32 = 64;
    const CAPACITY: u32 = 63;
    const TWO_INV: u64 = 0x7ffffffffffffe40;
    const MULTIPLICATIVE_GENERATOR: u64 = 3;
    const S: u32 = 1;
    const ROOT_OF_UNITY: u64 = 0xfffffffffffffc7e;
    const ROOT_OF_UNITY_INV: u64 = 0xfffffffffffffc7e;
    const DELTA: u64 = 9;
}

impl PrimeFieldConstants<u64> for Modulus<u64, ORDER> {
    type Repr = FieldBytes<TinyCurve64>;
    const MODULUS_STR: &'static str = "0xffffffff1a0a85df";
    const MODULUS: u64 = ORDER;
    const NUM_BITS: u32 = 64;
    const CAPACITY: u32 = 63;
    const TWO_INV: u64 = 0x7fffffff8d0542f0;
    const MULTIPLICATIVE_GENERATOR: u64 = 5;
    const S: u32 = 1;
    const ROOT_OF_UNITY: u64 = 0xffffffff1a0a85de;
    const ROOT_OF_UNITY_INV: u64 = 0xffffffff1a0a85de;
    const DELTA: u64 = 25;
}

/// An elliptic curve with a 64-bit order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct TinyCurve64;

impl Curve for TinyCurve64 {
    type FieldBytesSize = ReprSizeTypenum;
    type Uint = ReprUint;
    const ORDER: Self::Uint = Self::Uint::from_u64(ORDER);
}

impl FieldBytesEncoding<TinyCurve64> for <TinyCurve64 as Curve>::Uint {}

impl CurveArithmetic for TinyCurve64 {
    type Scalar = FieldElement<u64, ORDER>;
    type AffinePoint = AffinePoint<Self>;
    type ProjectivePoint = ProjectivePoint<Self>;
}

impl PrimeCurve for TinyCurve64 {}

impl PrimeCurveParams for TinyCurve64 {
    type FieldElement = FieldElement<u64, FIELD_MODULUS>;
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
impl VerifyPrimitive<TinyCurve64> for AffinePoint<TinyCurve64> {}

#[cfg(feature = "ecdsa")]
impl DigestPrimitive for TinyCurve64 {
    type Digest = TinyHash<8>;
}

#[cfg(feature = "pkcs8")]
impl AssociatedOid for TinyCurve64 {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.202767.3");
}

#[cfg(test)]
mod tests {
    use primeorder::elliptic_curve::{
        ops::{MulByGenerator, Reduce},
        CurveArithmetic, Field, ProjectivePoint,
    };
    use proptest::prelude::*;
    use rand_core::OsRng;

    use super::TinyCurve64;
    use crate::prime_field::ReprUint;

    type Scalar = <TinyCurve64 as CurveArithmetic>::Scalar;
    type Point = ProjectivePoint<TinyCurve64>;

    #[test]
    fn identity() {
        let x = Scalar::random(&mut OsRng);
        let y = Scalar::ZERO - x;
        let p = Point::mul_by_generator(&x) + Point::mul_by_generator(&y);
        assert_eq!(p, Point::IDENTITY);
    }

    prop_compose! {
        /// Generate a random odd modulus.
        fn scalar()(n in any::<u64>()) -> Scalar {
            Scalar::reduce(ReprUint::from(n))
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
    use primeorder::{elliptic_curve::CurveArithmetic, Field, PrimeField};

    use super::TinyCurve64;

    type F = <TinyCurve64 as CurveArithmetic>::Scalar;

    primeorder::impl_field_identity_tests!(F);
    primeorder::impl_field_invert_tests!(F);
    primeorder::impl_field_sqrt_tests!(F);

    // t = (modulus - 1) >> S
    const T: [u64; 1] = [(F::MODULUS - 1) >> F::S];
    primeorder::impl_primefield_tests!(F, T);
}

#[cfg(test)]
mod tests_field_element {
    use primeorder::{Field, PrimeCurveParams, PrimeField};

    use super::TinyCurve64;

    type F = <TinyCurve64 as PrimeCurveParams>::FieldElement;

    primeorder::impl_field_identity_tests!(F);
    primeorder::impl_field_invert_tests!(F);
    primeorder::impl_field_sqrt_tests!(F);

    // t = (modulus - 1) >> S
    const T: [u64; 1] = [(F::MODULUS - 1) >> F::S];
    primeorder::impl_primefield_tests!(F, T);
}

#[cfg(all(test, feature = "ecdsa"))]
mod tests_ecdsa {
    use ecdsa::{SigningKey, VerifyingKey};
    use rand_core::OsRng;

    use super::TinyCurve64;

    #[test]
    fn sign_and_verify() {
        let prehash = b"123456781234567812345678";
        let sk = SigningKey::<TinyCurve64>::random(&mut OsRng);

        let (signature, recovery_id) = sk.sign_prehash_recoverable(prehash).unwrap();
        let vk = VerifyingKey::recover_from_prehash(prehash, &signature, recovery_id).unwrap();
        assert_eq!(sk.verifying_key(), &vk);
    }
}

#[cfg(all(test, feature = "pkcs8"))]
mod tests_pkcs8 {
    use primeorder::elliptic_curve::{
        pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
        PublicKey, SecretKey,
    };
    use rand_core::OsRng;

    use super::TinyCurve64;

    #[test]
    fn serialize_secret_key() {
        let sk = SecretKey::<TinyCurve64>::random(&mut OsRng);
        let der = sk.to_pkcs8_der().unwrap();
        let sk_back = SecretKey::<TinyCurve64>::from_pkcs8_der(der.as_bytes()).unwrap();
        assert_eq!(sk, sk_back);
    }

    #[test]
    fn serialize_public_key() {
        let sk = SecretKey::<TinyCurve64>::random(&mut OsRng);
        let pk = sk.public_key();
        let der = pk.to_public_key_der().unwrap();
        let pk_back = PublicKey::<TinyCurve64>::from_public_key_der(der.as_bytes()).unwrap();
        assert_eq!(pk, pk_back);
    }
}
