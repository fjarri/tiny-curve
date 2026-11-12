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
    use super::TinyCurve64;
    crate::test_macros::test_curve!(TinyCurve64);
}

#[cfg(test)]
mod tests_scalar {
    use super::TinyCurve64;
    crate::test_macros::test_scalar!(TinyCurve64);
}

#[cfg(test)]
mod tests_field_element {
    use super::TinyCurve64;
    crate::test_macros::test_field!(TinyCurve64);
}
