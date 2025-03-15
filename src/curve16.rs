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

const ORDER: u64 = 0xfe93;
const FIELD_MODULUS: u64 = 0xffa7;

impl PrimeFieldConstants<u16> for Modulus<u16, FIELD_MODULUS> {
    type Repr = FieldBytes<TinyCurve16>;
    const MODULUS_STR: &'static str = "0xffa7";
    const MODULUS: u16 = FIELD_MODULUS as u16;
    const NUM_BITS: u32 = 16;
    const CAPACITY: u32 = 15;
    const TWO_INV: u16 = 0x7fd4;
    const MULTIPLICATIVE_GENERATOR: u16 = 5;
    const S: u32 = 1;
    const ROOT_OF_UNITY: u16 = 0xffa6;
    const ROOT_OF_UNITY_INV: u16 = 0xffa6;
    const DELTA: u16 = 25;
}

impl PrimeFieldConstants<u16> for Modulus<u16, ORDER> {
    type Repr = FieldBytes<TinyCurve16>;
    const MODULUS_STR: &'static str = "0xfe93";
    const MODULUS: u16 = ORDER as u16;
    const NUM_BITS: u32 = 16;
    const CAPACITY: u32 = 15;
    const TWO_INV: u16 = 0x7f4a;
    const MULTIPLICATIVE_GENERATOR: u16 = 2;
    const S: u32 = 1;
    const ROOT_OF_UNITY: u16 = 0xfe92;
    const ROOT_OF_UNITY_INV: u16 = 0xfe92;
    const DELTA: u16 = 4;
}

/// An elliptic curve with a 16-bit order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct TinyCurve16;

impl Curve for TinyCurve16 {
    type FieldBytesSize = ReprSizeTypenum;
    type Uint = ReprUint;
    const ORDER: Self::Uint = Self::Uint::from_u64(ORDER);
}

impl FieldBytesEncoding<TinyCurve16> for <TinyCurve16 as Curve>::Uint {}

impl CurveArithmetic for TinyCurve16 {
    type Scalar = FieldElement<u16, ORDER>;
    type AffinePoint = AffinePoint<Self>;
    type ProjectivePoint = ProjectivePoint<Self>;
}

impl PrimeCurve for TinyCurve16 {}

impl PrimeCurveParams for TinyCurve16 {
    type FieldElement = FieldElement<u16, FIELD_MODULUS>;
    type PointArithmetic = EquationAIsMinusThree;

    const EQUATION_A: Self::FieldElement = FieldElement::new_unchecked(FIELD_MODULUS as u16 - 3);
    const EQUATION_B: Self::FieldElement = FieldElement::new_unchecked(7);
    const GENERATOR: (Self::FieldElement, Self::FieldElement) = (
        FieldElement::new_unchecked(23947),
        FieldElement::new_unchecked(53757),
    );
}

impl PointCompression for TinyCurve16 {
    const COMPRESS_POINTS: bool = true;
}

#[cfg(feature = "ecdsa")]
impl VerifyPrimitive<TinyCurve16> for AffinePoint<TinyCurve16> {}

#[cfg(feature = "ecdsa")]
impl DigestPrimitive for TinyCurve16 {
    type Digest = TinyHash<2>;
}

#[cfg(feature = "pkcs8")]
impl AssociatedOid for TinyCurve16 {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.202767.1");
}

#[cfg(test)]
mod tests {
    use primeorder::{
        elliptic_curve::{
            bigint::Encoding,
            generic_array::GenericArray,
            ops::{MulByGenerator, Reduce},
            CurveArithmetic, Field, FieldBytesSize, ProjectivePoint,
        },
        PrimeField,
    };
    use proptest::prelude::*;
    use rand_core::OsRng;

    use super::TinyCurve16;
    use crate::prime_field::ReprUint;

    type Scalar = <TinyCurve16 as CurveArithmetic>::Scalar;
    type Point = ProjectivePoint<TinyCurve16>;

    #[test]
    fn identity() {
        let x = Scalar::random(&mut OsRng);
        let y = Scalar::ZERO - x;
        let p = Point::mul_by_generator(&x) + Point::mul_by_generator(&y);
        assert_eq!(p, Point::IDENTITY);
    }

    #[test]
    fn to_and_from_repr() {
        let mut repr = GenericArray::<u8, FieldBytesSize<TinyCurve16>>::default();

        // `s` now contains the value `M - 1`.
        let s = -Scalar::new_unchecked(1);
        let s_uint: ReprUint = s.into();

        // Check that to_repr/from_repr work normally
        let s_uint_repr = s_uint.to_be_bytes();
        repr.copy_from_slice(&s_uint_repr);
        let s_repr = s.to_repr();
        assert_eq!(repr, s_repr);
        assert_eq!(Scalar::from_repr(repr).unwrap(), s);

        // Now construct a representation of the value `M` (which would be out of range)
        let x_uint = s_uint.wrapping_add(&ReprUint::ONE);
        let x_uint_repr = x_uint.to_be_bytes();
        repr.copy_from_slice(&x_uint_repr);
        assert!(bool::from(Scalar::from_repr(repr).is_none()));
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

    use super::TinyCurve16;

    type F = <TinyCurve16 as CurveArithmetic>::Scalar;

    primeorder::impl_field_identity_tests!(F);
    primeorder::impl_field_invert_tests!(F);
    primeorder::impl_field_sqrt_tests!(F);

    // t = (modulus - 1) >> S
    const T: [u64; 1] = [(F::MODULUS - 1) as u64 >> F::S];
    primeorder::impl_primefield_tests!(F, T);
}

#[cfg(test)]
mod tests_field_element {
    use primeorder::{Field, PrimeCurveParams, PrimeField};

    use super::TinyCurve16;

    type F = <TinyCurve16 as PrimeCurveParams>::FieldElement;

    primeorder::impl_field_identity_tests!(F);
    primeorder::impl_field_invert_tests!(F);
    primeorder::impl_field_sqrt_tests!(F);

    // t = (modulus - 1) >> S
    const T: [u64; 1] = [(F::MODULUS - 1) as u64 >> F::S];
    primeorder::impl_primefield_tests!(F, T);
}

#[cfg(all(test, feature = "ecdsa"))]
mod tests_ecdsa {
    use ecdsa::{SigningKey, VerifyingKey};
    use rand_core::OsRng;

    use super::TinyCurve16;

    #[test]
    fn sign_and_verify() {
        let prehash = b"123456781234567812345678";
        let sk = SigningKey::<TinyCurve16>::random(&mut OsRng);

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

    use super::TinyCurve16;

    #[test]
    fn serialize_secret_key() {
        let sk = SecretKey::<TinyCurve16>::random(&mut OsRng);
        let der = sk.to_pkcs8_der().unwrap();
        let sk_back = SecretKey::<TinyCurve16>::from_pkcs8_der(der.as_bytes()).unwrap();
        assert_eq!(sk, sk_back);
    }

    #[test]
    fn serialize_public_key() {
        let sk = SecretKey::<TinyCurve16>::random(&mut OsRng);
        let pk = sk.public_key();
        let der = pk.to_public_key_der().unwrap();
        let pk_back = PublicKey::<TinyCurve16>::from_public_key_der(der.as_bytes()).unwrap();
        assert_eq!(pk, pk_back);
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests_serde {
    use primeorder::elliptic_curve::{PublicKey, SecretKey};
    use rand_core::OsRng;

    use super::TinyCurve16;

    #[test]
    fn serialize_public_key() {
        let sk = SecretKey::<TinyCurve16>::random(&mut OsRng);
        let pk = sk.public_key();
        let bytes = postcard::to_allocvec(&pk).unwrap();
        let pk_back: PublicKey<TinyCurve16> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(pk, pk_back);
    }

    #[cfg(feature = "ecdsa")]
    #[test]
    fn serialize_verifying_key() {
        let sk = SecretKey::<TinyCurve16>::random(&mut OsRng);
        let pk = sk.public_key();
        let vk = ecdsa::VerifyingKey::from(&pk);
        let bytes = postcard::to_allocvec(&vk).unwrap();
        let vk_back: ecdsa::VerifyingKey<TinyCurve16> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(vk, vk_back);
    }
}
