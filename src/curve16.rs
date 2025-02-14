use primeorder::{
    elliptic_curve::{Curve, CurveArithmetic, FieldBytes, FieldBytesEncoding},
    point_arithmetic::EquationAIsMinusThree,
    AffinePoint, PrimeCurve, PrimeCurveParams, ProjectivePoint,
};

use crate::{
    prime_field::{FieldElement, ReprSizeTypenum, ReprUint},
    traits::{Modulus, PrimeFieldConstants},
};

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

#[cfg(test)]
mod tests {
    use primeorder::elliptic_curve::{
        ops::{MulByGenerator, Reduce},
        CurveArithmetic, Field, ProjectivePoint,
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
