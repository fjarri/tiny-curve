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

const ORDER: u64 = 0xfffffffe47ac0c17;
const FIELD_MODULUS: u64 = 0xfffffffffffffe95;

impl PrimeFieldConstants<u64> for Modulus<u64, FIELD_MODULUS> {
    type Repr = FieldBytes<TinyCurve64>;
    const MODULUS: &'static str = "0xfffffffffffffe95";
    const NUM_BITS: u32 = 64;
    const CAPACITY: u32 = 63;
    const TWO_INV: u64 = 0x7fffffffffffff4b;
    const MULTIPLICATIVE_GENERATOR: u64 = 5;
    const S: u32 = 2;
    const ROOT_OF_UNITY: u64 = 0xd40662ba9996b1b8;
    const ROOT_OF_UNITY_INV: u64 = 0x2bf99d4566694cdd;
    const DELTA: u64 = 625;
}

impl PrimeFieldConstants<u64> for Modulus<u64, ORDER> {
    type Repr = FieldBytes<TinyCurve64>;
    const MODULUS: &'static str = "0xfffffffe47ac0c17";
    const NUM_BITS: u32 = 64;
    const CAPACITY: u32 = 63;
    const TWO_INV: u64 = 0x7fffffff23d6060c;
    const MULTIPLICATIVE_GENERATOR: u64 = 3;
    const S: u32 = 1;
    const ROOT_OF_UNITY: u64 = 0xfffffffe47ac0c16;
    const ROOT_OF_UNITY_INV: u64 = 0xfffffffe47ac0c16;
    const DELTA: u64 = 9;
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
    const EQUATION_B: Self::FieldElement = FieldElement::new_unchecked(1);
    const GENERATOR: (Self::FieldElement, Self::FieldElement) = (
        FieldElement::new_unchecked(8681109523785822645),
        FieldElement::new_unchecked(9413656544546528568),
    );
}
