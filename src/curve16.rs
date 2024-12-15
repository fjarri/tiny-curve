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

const ORDER: u64 = 0xfe9f;
const FIELD_MODULUS: u64 = 0xfff1;

impl PrimeFieldConstants<u16> for Modulus<u16, FIELD_MODULUS> {
    type Repr = FieldBytes<TinyCurve16>;
    const MODULUS: &'static str = "0xfff1";
    const NUM_BITS: u32 = 16;
    const CAPACITY: u32 = 15;
    const TWO_INV: u16 = 0x7ff9;
    const MULTIPLICATIVE_GENERATOR: u16 = 0x11;
    const S: u32 = 4;
    const ROOT_OF_UNITY: u16 = 0xf0c8;
    const ROOT_OF_UNITY_INV: u16 = 0x4ce5;
    const DELTA: u16 = 39958;
}

impl PrimeFieldConstants<u16> for Modulus<u16, ORDER> {
    type Repr = FieldBytes<TinyCurve16>;
    const MODULUS: &'static str = "0xfe9f";
    const NUM_BITS: u32 = 16;
    const CAPACITY: u32 = 15;
    const TWO_INV: u16 = 0x7f50;
    const MULTIPLICATIVE_GENERATOR: u16 = 5;
    const S: u32 = 1;
    const ROOT_OF_UNITY: u16 = 0xfe9e;
    const ROOT_OF_UNITY_INV: u16 = 0xfe9e;
    const DELTA: u16 = 25;
}

/// An elliptic curve with a 32-bit order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct TinyCurve16;

impl Curve for TinyCurve16 {
    type FieldBytesSize = typenum::U8;
    type Uint = U64;
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
    const EQUATION_B: Self::FieldElement = FieldElement::new_unchecked(10);
    const GENERATOR: (Self::FieldElement, Self::FieldElement) = (
        FieldElement::new_unchecked(48073),
        FieldElement::new_unchecked(20668),
    );
}

#[cfg(test)]
mod tests {
    use super::TinyCurve16;
    use primeorder::elliptic_curve::{
        bigint::U64,
        ops::{MulByGenerator, Reduce},
        CurveArithmetic, ProjectivePoint,
    };
    use proptest::prelude::*;

    type Scalar = <TinyCurve16 as CurveArithmetic>::Scalar;
    type Point = ProjectivePoint<TinyCurve16>;

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
