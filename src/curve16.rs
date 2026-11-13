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

const ORDER: u64 = 0xfe93;
const FIELD_MODULUS: u64 = 0xffa7;

impl PrimeFieldConstants<u16> for Modulus<u16, FIELD_MODULUS> {
    type ReprSize = FieldBytesSize<TinyCurve16>;
    const MODULUS_STR: &'static str = "000000000000ffa7";
    const MODULUS: u16 = FIELD_MODULUS as u16;
    const NUM_BITS: u32 = 16;
    const CAPACITY: u32 = 15;
    const TWO_INV: u16 = 0x7fd4;
    const MULTIPLICATIVE_GENERATOR: u16 = 5;
    const S: u32 = 1;
    const ROOT_OF_UNITY: u16 = 0xffa6;
    const ROOT_OF_UNITY_INV: u16 = 0xffa6;
    const DELTA: u16 = 25;
    type WnafStorageSize = typenum::U17;
}

impl PrimeFieldConstants<u16> for Modulus<u16, ORDER> {
    type ReprSize = FieldBytesSize<TinyCurve16>;
    const MODULUS_STR: &'static str = "000000000000fe93";
    const MODULUS: u16 = ORDER as u16;
    const NUM_BITS: u32 = 16;
    const CAPACITY: u32 = 15;
    const TWO_INV: u16 = 0x7f4a;
    const MULTIPLICATIVE_GENERATOR: u16 = 2;
    const S: u32 = 1;
    const ROOT_OF_UNITY: u16 = 0xfe92;
    const ROOT_OF_UNITY_INV: u16 = 0xfe92;
    const DELTA: u16 = 4;
    type WnafStorageSize = typenum::U17;
}

/// An elliptic curve with a 16-bit order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct TinyCurve16;

impl Curve for TinyCurve16 {
    type FieldBytesSize = typenum::U2;
    type Uint = ReprUint;
    const ORDER: Odd<Self::Uint> = Self::Uint::from_u64(ORDER)
        .to_odd()
        .expect_copied("the curve order is odd");
}

impl FieldArithmetic for TinyCurve16 {
    type FieldElement = FieldElement<u16, FIELD_MODULUS>;
}

impl CurveArithmetic for TinyCurve16 {
    type Scalar = FieldElement<u16, ORDER>;
    type AffinePoint = AffinePoint<Self>;
    type ProjectivePoint = ProjectivePoint<Self>;
}

// `From`/`TryFrom` conversions between the scalar and `NonZeroScalar`/`ScalarValue`/`SecretKey`,
// and `Mul`/`MulVartime` impls for the scalar with affine and projective points.
primeorder::elliptic_curve::scalar_impls!(TinyCurve16, FieldElement<u16, ORDER>);

impl PrimeCurve for TinyCurve16 {}

impl PrimeCurveParams for TinyCurve16 {
    type Backend = VariableOnly;
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
impl EcdsaCurve for TinyCurve16 {
    const NORMALIZE_S: bool = false;
}

#[cfg(feature = "ecdsa")]
impl DigestAlgorithm for TinyCurve16 {
    type Digest = Sha256;
}

#[cfg(feature = "pkcs8")]
impl AssociatedOid for TinyCurve16 {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.202767.1");
}

#[cfg(test)]
mod tests {
    use super::TinyCurve16;
    crate::test_macros::test_curve!(TinyCurve16);
}

#[cfg(test)]
mod tests_scalar {
    use super::TinyCurve16;
    crate::test_macros::test_scalar!(TinyCurve16);
}

#[cfg(test)]
mod tests_field_element {
    use super::TinyCurve16;
    crate::test_macros::test_field!(TinyCurve16);
}
