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

const ORDER: u64 = 0xffff0f07;
const FIELD_MODULUS: u64 = 0xffffff67;

impl PrimeFieldConstants<u32> for Modulus<u32, FIELD_MODULUS> {
    type ReprSize = FieldBytesSize<TinyCurve32>;
    const MODULUS_STR: &'static str = "00000000ffffff67";
    const MODULUS: u32 = FIELD_MODULUS as u32;
    const NUM_BITS: u32 = 32;
    const CAPACITY: u32 = 31;
    const TWO_INV: u32 = 0x7fffffb4;
    const MULTIPLICATIVE_GENERATOR: u32 = 3;
    const S: u32 = 1;
    const ROOT_OF_UNITY: u32 = 0xffffff66;
    const ROOT_OF_UNITY_INV: u32 = 0xffffff66;
    const DELTA: u32 = 9;
    type WnafStorageSize = typenum::U33;
}

impl PrimeFieldConstants<u32> for Modulus<u32, ORDER> {
    type ReprSize = FieldBytesSize<TinyCurve32>;
    const MODULUS_STR: &'static str = "00000000ffff0f07";
    const MODULUS: u32 = ORDER as u32;
    const NUM_BITS: u32 = 32;
    const CAPACITY: u32 = 31;
    const TWO_INV: u32 = 0x7fff8784;
    const MULTIPLICATIVE_GENERATOR: u32 = 3;
    const S: u32 = 1;
    const ROOT_OF_UNITY: u32 = 0xffff0f06;
    const ROOT_OF_UNITY_INV: u32 = 0xffff0f06;
    const DELTA: u32 = 9;
    type WnafStorageSize = typenum::U33;
}

/// An elliptic curve with a 32-bit order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct TinyCurve32;

impl Curve for TinyCurve32 {
    type FieldBytesSize = typenum::U4;
    type Uint = ReprUint;
    const ORDER: Odd<Self::Uint> = Self::Uint::from_u64(ORDER)
        .to_odd()
        .expect_copied("the curve order is odd");
}

impl FieldArithmetic for TinyCurve32 {
    type FieldElement = FieldElement<u32, FIELD_MODULUS>;
}

impl CurveArithmetic for TinyCurve32 {
    type Scalar = FieldElement<u32, ORDER>;
    type AffinePoint = AffinePoint<Self>;
    type ProjectivePoint = ProjectivePoint<Self>;
}

// `From`/`TryFrom` conversions between the scalar and `NonZeroScalar`/`ScalarValue`/`SecretKey`,
// and `Mul`/`MulVartime` impls for the scalar with affine and projective points.
primeorder::elliptic_curve::scalar_impls!(TinyCurve32, FieldElement<u32, ORDER>);

impl PrimeCurve for TinyCurve32 {}

impl PrimeCurveParams for TinyCurve32 {
    type Backend = VariableOnly;
    type PointArithmetic = EquationAIsMinusThree;

    const EQUATION_A: Self::FieldElement = FieldElement::new_unchecked(FIELD_MODULUS as u32 - 3);
    const EQUATION_B: Self::FieldElement = FieldElement::new_unchecked(8);
    const GENERATOR: (Self::FieldElement, Self::FieldElement) = (
        FieldElement::new_unchecked(4274000713),
        FieldElement::new_unchecked(443355223),
    );
}

impl PointCompression for TinyCurve32 {
    const COMPRESS_POINTS: bool = true;
}

#[cfg(feature = "ecdsa")]
impl EcdsaCurve for TinyCurve32 {
    const NORMALIZE_S: bool = false;
}

#[cfg(feature = "ecdsa")]
impl DigestAlgorithm for TinyCurve32 {
    type Digest = Sha256;
}

#[cfg(feature = "pkcs8")]
impl AssociatedOid for TinyCurve32 {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.202767.2");
}

#[cfg(test)]
mod tests {
    use super::TinyCurve32;
    crate::test_macros::test_curve!(TinyCurve32);
}

#[cfg(test)]
mod tests_scalar {
    use super::TinyCurve32;
    crate::test_macros::test_scalar!(TinyCurve32);
}

#[cfg(test)]
mod tests_field_element {
    use super::TinyCurve32;
    crate::test_macros::test_field!(TinyCurve32);
}
