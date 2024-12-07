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

const ORDER: u64 = 0xffff8d41;
const FIELD_MODULUS: u64 = 0xffffff79;

impl PrimeFieldConstants<u32> for Modulus<u32, FIELD_MODULUS> {
    type Repr = FieldBytes<TinyCurve32>;
    const MODULUS: &'static str = "0xffffff79";
    const NUM_BITS: u32 = 32;
    const CAPACITY: u32 = 31;
    const TWO_INV: u32 = 0x7fffffbd;
    const MULTIPLICATIVE_GENERATOR: u32 = 0x3a;
    const S: u32 = 3;
    const ROOT_OF_UNITY: u32 = 0xe50232d0;
    const ROOT_OF_UNITY_INV: u32 = 0x816ffec8;
    const DELTA: u32 = 45878479;
}

impl PrimeFieldConstants<u32> for Modulus<u32, ORDER> {
    type Repr = FieldBytes<TinyCurve32>;
    const MODULUS: &'static str = "0xffff8d41";
    const NUM_BITS: u32 = 32;
    const CAPACITY: u32 = 31;
    const TWO_INV: u32 = 0x7fffc6a1;
    const MULTIPLICATIVE_GENERATOR: u32 = 3;
    const S: u32 = 6;
    const ROOT_OF_UNITY: u32 = 0x12e92375;
    const ROOT_OF_UNITY_INV: u32 = 0x3b6407f9;
    const DELTA: u32 = 3717271734;
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
    const EQUATION_B: Self::FieldElement = FieldElement::new_unchecked(6);
    const GENERATOR: (Self::FieldElement, Self::FieldElement) = (
        FieldElement::new_unchecked(1657199161),
        FieldElement::new_unchecked(3487949248),
    );
}
