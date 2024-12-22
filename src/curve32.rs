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

const ORDER: u64 = 0xffff0f07;
const FIELD_MODULUS: u64 = 0xffffff67;

impl PrimeFieldConstants<u32> for Modulus<u32, FIELD_MODULUS> {
    type Repr = FieldBytes<TinyCurve32>;
    const MODULUS_STR: &'static str = "0xffffff67";
    const MODULUS: u32 = FIELD_MODULUS as u32;
    const NUM_BITS: u32 = 32;
    const CAPACITY: u32 = 31;
    const TWO_INV: u32 = 0x7fffffb4;
    const MULTIPLICATIVE_GENERATOR: u32 = 3;
    const S: u32 = 1;
    const ROOT_OF_UNITY: u32 = 0xffffff66;
    const ROOT_OF_UNITY_INV: u32 = 0xffffff66;
    const DELTA: u32 = 9;
}

impl PrimeFieldConstants<u32> for Modulus<u32, ORDER> {
    type Repr = FieldBytes<TinyCurve32>;
    const MODULUS_STR: &'static str = "0xffff0f07";
    const MODULUS: u32 = ORDER as u32;
    const NUM_BITS: u32 = 32;
    const CAPACITY: u32 = 31;
    const TWO_INV: u32 = 0x7fff8784;
    const MULTIPLICATIVE_GENERATOR: u32 = 3;
    const S: u32 = 1;
    const ROOT_OF_UNITY: u32 = 0xffff0f06;
    const ROOT_OF_UNITY_INV: u32 = 0xffff0f06;
    const DELTA: u32 = 9;
}

/// An elliptic curve with a 32-bit order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct TinyCurve32;

impl Curve for TinyCurve32 {
    type FieldBytesSize = typenum::U8;
    type Uint = U64;
    const ORDER: Self::Uint = Self::Uint::from_u64(ORDER);
}

impl FieldBytesEncoding<TinyCurve32> for <TinyCurve32 as Curve>::Uint {}

impl CurveArithmetic for TinyCurve32 {
    type Scalar = FieldElement<u32, ORDER>;
    type AffinePoint = AffinePoint<Self>;
    type ProjectivePoint = ProjectivePoint<Self>;
}

impl PrimeCurve for TinyCurve32 {}

impl PrimeCurveParams for TinyCurve32 {
    type FieldElement = FieldElement<u32, FIELD_MODULUS>;
    type PointArithmetic = EquationAIsMinusThree;

    const EQUATION_A: Self::FieldElement = FieldElement::new_unchecked(FIELD_MODULUS as u32 - 3);
    const EQUATION_B: Self::FieldElement = FieldElement::new_unchecked(8);
    const GENERATOR: (Self::FieldElement, Self::FieldElement) = (
        FieldElement::new_unchecked(4274000713),
        FieldElement::new_unchecked(443355223),
    );
}

#[cfg(test)]
mod tests {
    use super::TinyCurve32;
    use primeorder::elliptic_curve::{
        bigint::U64,
        ops::{MulByGenerator, Reduce},
        CurveArithmetic, ProjectivePoint,
    };
    use proptest::prelude::*;

    type Scalar = <TinyCurve32 as CurveArithmetic>::Scalar;
    type Point = ProjectivePoint<TinyCurve32>;

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

    use super::TinyCurve32;

    type F = <TinyCurve32 as CurveArithmetic>::Scalar;

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

    use super::TinyCurve32;

    type F = <TinyCurve32 as PrimeCurveParams>::FieldElement;

    primeorder::impl_field_identity_tests!(F);
    primeorder::impl_field_invert_tests!(F);
    primeorder::impl_field_sqrt_tests!(F);

    // t = (modulus - 1) >> S
    const T: [u64; 1] = [(F::MODULUS - 1) as u64 >> F::S];
    primeorder::impl_primefield_tests!(F, T);
}
