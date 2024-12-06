use elliptic_curve::{
    bigint::U64, generic_array::typenum, Curve, CurveArithmetic, FieldBytesEncoding,
};
use primeorder::{
    point_arithmetic::EquationAIsMinusThree, AffinePoint, PrimeCurve, PrimeCurveParams,
    ProjectivePoint,
};

use crate::prime_field::FieldElement;

pub trait PrimeFieldConstants {
    const MODULUS: &'static str;
    const NUM_BITS: u32;
    const CAPACITY: u32;
    const TWO_INV: u64;
    const MULTIPLICATIVE_GENERATOR: u64;
    const S: u32 = 2;
    const ROOT_OF_UNITY: u64;
    const ROOT_OF_UNITY_INV: u64;
    const DELTA: u64;
}

pub struct Modulus<const M: u64>;

const ORDER: u64 = 0xfffffffe47ac0c17;
const FIELD_MODULUS: u64 = 0xfffffffffffffe95;

impl PrimeFieldConstants for Modulus<0xfffffffffffffe95> {
    const MODULUS: &'static str = "0xfffffffffffffe95";
    const NUM_BITS: u32 = 64;
    const CAPACITY: u32 = 63;
    const TWO_INV: u64 = 9223372036854775779;
    const MULTIPLICATIVE_GENERATOR: u64 = 2;
    const S: u32 = 2;
    const ROOT_OF_UNITY: u64 = 2296021864060584341;
    const ROOT_OF_UNITY_INV: u64 = 16150722209648967216;
    const DELTA: u64 = 16;
}

impl PrimeFieldConstants for Modulus<0xfffffffe47ac0c17> {
    const MODULUS: &'static str = "0xfffffffffffffe95";
    const NUM_BITS: u32 = 64;
    const CAPACITY: u32 = 63;
    const TWO_INV: u64 = 9223372036854775779;
    const MULTIPLICATIVE_GENERATOR: u64 = 2;
    const S: u32 = 2;
    const ROOT_OF_UNITY: u64 = 2296021864060584341;
    const ROOT_OF_UNITY_INV: u64 = 16150722209648967216;
    const DELTA: u64 = 16;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct TinyCurve;

impl Curve for TinyCurve {
    type FieldBytesSize = typenum::U8;
    type Uint = U64;
    const ORDER: Self::Uint = U64::from_u64(ORDER);
}

impl FieldBytesEncoding<TinyCurve> for U64 {}

impl CurveArithmetic for TinyCurve {
    type Scalar = FieldElement<ORDER>;
    type AffinePoint = AffinePoint<Self>;
    type ProjectivePoint = ProjectivePoint<Self>;
}

impl PrimeCurve for TinyCurve {}

impl PrimeCurveParams for TinyCurve {
    type FieldElement = FieldElement<FIELD_MODULUS>;
    type PointArithmetic = EquationAIsMinusThree;

    const EQUATION_A: Self::FieldElement = FieldElement::new_unchecked(3).neg();
    const EQUATION_B: Self::FieldElement = FieldElement::new_unchecked(1);
    const GENERATOR: (Self::FieldElement, Self::FieldElement) = (
        FieldElement::new_unchecked(8681109523785822645),
        FieldElement::new_unchecked(9413656544546528568),
    );
}
