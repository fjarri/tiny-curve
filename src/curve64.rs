use primeorder::{
    elliptic_curve::{
        bigint::U64, generic_array::typenum, Curve, CurveArithmetic, FieldBytes, FieldBytesEncoding,
    },
    point_arithmetic::EquationAIsMinusThree,
    AffinePoint, PrimeCurve, PrimeCurveParams, ProjectivePoint,
};

use crate::{
    prime_field::FieldElement,
    traits::{Modulus, PrimeFieldConstants},
};

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
    type FieldBytesSize = typenum::U8;
    type Uint = U64;
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

#[cfg(test)]
mod tests {
    use super::TinyCurve64;
    use primeorder::elliptic_curve::{
        bigint::U64,
        ops::{MulByGenerator, Reduce},
        CurveArithmetic, ProjectivePoint,
    };
    use proptest::prelude::*;

    type Scalar = <TinyCurve64 as CurveArithmetic>::Scalar;
    type Point = ProjectivePoint<TinyCurve64>;

    prop_compose! {
        /// Generate a random odd modulus.
        fn scalar()(n in any::<u64>()) -> Scalar {
            Scalar::reduce(U64::from(n))
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
