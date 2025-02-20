use core::{
    fmt::Debug,
    iter::{Product, Sum},
    ops::{AddAssign, MulAssign, Neg, ShrAssign, SubAssign},
};

use primeorder::{
    elliptic_curve::{
        bigint::{Encoding, Integer, Uint, U64},
        generic_array::{typenum, GenericArray},
        ops::{Invert, Reduce},
        scalar::{FromUintUnchecked, IsHigh},
        subtle::{Choice, ConstantTimeEq, CtOption},
        Curve, CurveArithmetic, FieldBytes, FieldBytesEncoding, ScalarPrimitive,
    },
    point_arithmetic::EquationAIsMinusThree,
    AffinePoint, PrimeCurve, PrimeCurveParams, PrimeField, ProjectivePoint,
};

type EfficientRepr = [u64; 1];

type CanonicalRepr = [u64; 1];

const fn add<const M: u64>(lhs: &[u64; 1], rhs: &[u64; 1]) -> [u64; 1] {
    let lhs = lhs[0];
    let rhs = rhs[0];
    let modulus = M; // T::from_u64(M).expect("the modulus fits into `T`");
    let mut result = lhs.wrapping_add(rhs);
    if result >= modulus || result < lhs {
        result = result.wrapping_sub(modulus);
    }
    [result]
}

const fn sub<const M: u64>(lhs: &[u64; 1], rhs: &[u64; 1]) -> [u64; 1] {
    let lhs = lhs[0];
    let rhs = rhs[0];
    let modulus = M; // T::from_u64(M).expect("the modulus fits into `T`");
    let mut result = lhs.wrapping_sub(rhs);
    if lhs < rhs {
        result = result.wrapping_add(modulus);
    }
    [result]
}

const fn mul<const M: u64>(lhs: &[u64; 1], rhs: &[u64; 1]) -> [u64; 1] {
    let lhs = lhs[0];
    let rhs = rhs[0];
    let modulus = M; // T::from_u64(M).expect("the modulus fits into `T`");
    let result = ((lhs as u128) * (rhs as u128) % (modulus as u128)) as u64;
    [result]
}

const fn neg<const M: u64>(arg: &[u64; 1]) -> [u64; 1] {
    let arg = arg[0];
    let modulus = M; // T::from_u64(M).expect("the modulus fits into `T`");
    let result = if arg == 0 { arg } else { modulus - arg };
    [result]
}

const fn from_efficient(arg: &EfficientRepr) -> CanonicalRepr {
    *arg
}

const fn to_efficient(arg: &CanonicalRepr) -> EfficientRepr {
    *arg
}

const fn add_field(lhs: &EfficientRepr, rhs: &EfficientRepr) -> EfficientRepr {
    add::<MODULUS>(lhs, rhs)
}

const fn sub_field(lhs: &EfficientRepr, rhs: &EfficientRepr) -> EfficientRepr {
    sub::<MODULUS>(lhs, rhs)
}

const fn mul_field(lhs: &EfficientRepr, rhs: &EfficientRepr) -> EfficientRepr {
    mul::<MODULUS>(lhs, rhs)
}

const fn neg_field(arg: &EfficientRepr) -> EfficientRepr {
    neg::<MODULUS>(arg)
}

const fn square_field(arg: &EfficientRepr) -> EfficientRepr {
    mul_field(arg, arg)
}

const fn add_scalar(lhs: &EfficientRepr, rhs: &EfficientRepr) -> EfficientRepr {
    add::<ORDER>(lhs, rhs)
}

const fn sub_scalar(lhs: &EfficientRepr, rhs: &EfficientRepr) -> EfficientRepr {
    sub::<ORDER>(lhs, rhs)
}

const fn mul_scalar(lhs: &EfficientRepr, rhs: &EfficientRepr) -> EfficientRepr {
    mul::<ORDER>(lhs, rhs)
}

const fn neg_scalar(arg: &EfficientRepr) -> EfficientRepr {
    neg::<ORDER>(arg)
}

const fn square_scalar(arg: &EfficientRepr) -> EfficientRepr {
    mul_scalar(arg, arg)
}

const MODULUS_HEX: &str = "fffffffffffffc7f";
const MODULUS: u64 = U64::from_be_hex(MODULUS_HEX).as_words()[0];
const MODULUS_UINT: U64 = U64::from_be_hex(MODULUS_HEX);

const ORDER_HEX: &str = "ffffffff1a0a85df";
const ORDER: u64 = U64::from_be_hex(ORDER_HEX).as_words()[0];
const ORDER_UINT: U64 = U64::from_be_hex(ORDER_HEX);

#[derive(Debug, Clone, Copy)]
pub struct FieldElement(U64);

impl FieldElement {
    fn sqrt(&self) -> CtOption<Self> {
        let res = self.pow_vartime(&[(MODULUS >> 2) + 1]);
        let is_square = res.square().ct_eq(self);
        CtOption::new(res, is_square)
    }
}

impl PrimeField for FieldElement {
    type Repr = FieldBytes<TinyCurve64>;

    const MODULUS: &'static str = MODULUS_HEX;
    const NUM_BITS: u32 = 64;
    const CAPACITY: u32 = 63;
    const TWO_INV: Self = Self(Uint::from_u64(0x7ffffffffffffe40));
    const MULTIPLICATIVE_GENERATOR: Self = Self(Uint::from_u64(3));
    const S: u32 = 1;
    const ROOT_OF_UNITY: Self = Self(Uint::from_u64(0xfffffffffffffc7e));
    const ROOT_OF_UNITY_INV: Self = Self(Uint::from_u64(0xfffffffffffffc7e));
    const DELTA: Self = Self(Uint::from_u64(9));

    fn from_repr(repr: Self::Repr) -> CtOption<Self> {
        let value = U64::from_be_bytes(repr.into());
        let within_range = Choice::from((value < MODULUS_UINT) as u8);
        CtOption::new(Self(value), within_range)
    }

    fn to_repr(&self) -> Self::Repr {
        self.0.to_be_bytes().into()
    }

    fn is_odd(&self) -> Choice {
        self.0.is_odd()
    }
}

#[derive(Debug, Clone, Copy, PartialOrd, Ord)]
pub struct Scalar(U64);

impl Scalar {
    const fn from_u64_unchecked(source: u64) -> Self {
        debug_assert!(source < ORDER);
        Self(Uint::from_u64(source))
    }

    fn to_u64(&self) -> u64 {
        self.0.into()
    }

    fn invert(&self) -> CtOption<Self> {
        let modulus = ORDER;
        let inverse = crate::primitives::modular_inverse(self.to_u64(), modulus);
        match inverse {
            Some(inv) => CtOption::new(Self::from_u64_unchecked(inv), Choice::from(1)),
            None => CtOption::new(Self::ZERO, Choice::from(0)),
        }
    }

    fn sqrt(&self) -> CtOption<Self> {
        let res = self.pow_vartime(&[(ORDER >> 2) + 1]);
        let is_square = res.square().ct_eq(self);
        CtOption::new(res, is_square)
    }
}

impl PrimeField for Scalar {
    type Repr = FieldBytes<TinyCurve64>;

    const MODULUS: &'static str = ORDER_HEX;
    const NUM_BITS: u32 = 64;
    const CAPACITY: u32 = 63;
    const TWO_INV: Self = Self::from_u64_unchecked(0x7fffffff8d0542f0);
    const MULTIPLICATIVE_GENERATOR: Self = Self::from_u64_unchecked(5);
    const S: u32 = 1;
    const ROOT_OF_UNITY: Self = Self::from_u64_unchecked(0xffffffff1a0a85de);
    const ROOT_OF_UNITY_INV: Self = Self::from_u64_unchecked(0xffffffff1a0a85de);
    const DELTA: Self = Self::from_u64_unchecked(25);

    fn from_repr(repr: Self::Repr) -> CtOption<Self> {
        let value = U64::from_be_bytes(repr.into());
        let within_range = Choice::from((value < MODULUS_UINT) as u8);
        CtOption::new(Self(value), within_range)
    }

    fn to_repr(&self) -> Self::Repr {
        self.0.to_be_bytes().into()
    }

    fn is_odd(&self) -> Choice {
        self.0.is_odd()
    }
}

/// An elliptic curve with a 64-bit order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct TinyCurve64;

impl Curve for TinyCurve64 {
    type FieldBytesSize = typenum::U8;
    type Uint = U64;
    const ORDER: Self::Uint = ORDER_UINT;
}

impl FieldBytesEncoding<TinyCurve64> for <TinyCurve64 as Curve>::Uint {}

impl CurveArithmetic for TinyCurve64 {
    type Scalar = Scalar;
    type AffinePoint = AffinePoint<Self>;
    type ProjectivePoint = ProjectivePoint<Self>;
}

impl PrimeCurve for TinyCurve64 {}

impl PrimeCurveParams for TinyCurve64 {
    type FieldElement = FieldElement;
    type PointArithmetic = EquationAIsMinusThree;

    const EQUATION_A: Self::FieldElement = FieldElement(Uint::from_u64(MODULUS - 3));
    const EQUATION_B: Self::FieldElement = FieldElement(Uint::from_u64(1));
    const GENERATOR: (Self::FieldElement, Self::FieldElement) = (
        FieldElement(Uint::from_u64(8681109523785822645)),
        FieldElement(Uint::from_u64(9413656544546528568)),
    );
}

impl ShrAssign<usize> for Scalar {
    fn shr_assign(&mut self, shift: usize) {
        self.0.shr_assign(shift)
    }
}

impl Reduce<<TinyCurve64 as Curve>::Uint> for Scalar {
    type Bytes = FieldBytes<TinyCurve64>;

    fn reduce(n: <TinyCurve64 as Curve>::Uint) -> Self {
        Self::from_u64_unchecked(u64::from(n) % ORDER)
    }

    fn reduce_bytes(bytes: &Self::Bytes) -> Self {
        let uint = <TinyCurve64 as Curve>::Uint::from_be_slice(bytes);
        Self::reduce(uint)
    }
}

impl IsHigh for Scalar {
    fn is_high(&self) -> Choice {
        Choice::from((self.to_u64() > (ORDER >> 1)) as u8)
    }
}

impl FromUintUnchecked for Scalar {
    type Uint = U64;

    fn from_uint_unchecked(uint: Self::Uint) -> Self {
        Self::from_u64_unchecked(uint.into())
    }
}

impl Invert for Scalar {
    type Output = CtOption<Self>;

    fn invert(&self) -> Self::Output {
        self.invert()
    }
}

impl<C> From<ScalarPrimitive<C>> for Scalar
where
    C: Curve<Uint = U64>,
{
    fn from(source: ScalarPrimitive<C>) -> Self {
        Self::from_uint_unchecked(source.to_uint())
    }
}

impl<C> From<Scalar> for ScalarPrimitive<C>
where
    C: Curve<Uint = U64>,
{
    fn from(source: Scalar) -> Self {
        ScalarPrimitive::new(C::Uint::from(source.to_u64())).expect("the value is within range")
    }
}

impl From<Scalar> for U64 {
    fn from(source: Scalar) -> Self {
        source.0
    }
}

impl From<Scalar> for GenericArray<u8, typenum::U8> {
    fn from(source: Scalar) -> Self {
        let mut bytes = Self::default();
        let source_bytes = source.to_u64().to_be_bytes();
        bytes.copy_from_slice(source_bytes.as_ref());
        bytes
    }
}

impl AsRef<Scalar> for Scalar {
    fn as_ref(&self) -> &Scalar {
        self
    }
}

primeorder::impl_mont_field_element!(
    TinyCurve64,
    FieldElement,
    FieldBytes<TinyCurve64>,
    U64,
    MODULUS_UINT,
    EfficientRepr,
    from_efficient,
    to_efficient,
    add_field,
    sub_field,
    mul_field,
    neg_field,
    square_field
);

primeorder::impl_mont_field_element!(
    TinyCurve64,
    Scalar,
    FieldBytes<TinyCurve64>,
    U64,
    MODULUS_UINT,
    EfficientRepr,
    from_efficient,
    to_efficient,
    add_scalar,
    sub_scalar,
    mul_scalar,
    neg_scalar,
    square_scalar
);

#[cfg(test)]
mod tests_scalar {
    use primeorder::PrimeField;

    use super::{Scalar, ORDER};

    /// t = (modulus - 1) >> S
    const T: [u64; 1] = [(ORDER - 1) >> Scalar::S];

    primeorder::impl_field_identity_tests!(Scalar);
    primeorder::impl_field_invert_tests!(Scalar);
    primeorder::impl_field_sqrt_tests!(Scalar);
    primeorder::impl_primefield_tests!(Scalar, T);
}

#[cfg(test)]
mod tests_field {
    use primeorder::PrimeField;

    use super::{FieldElement, MODULUS};

    /// t = (modulus - 1) >> S
    const T: [u64; 1] = [(MODULUS - 1) >> FieldElement::S];

    primeorder::impl_field_identity_tests!(FieldElement);
    primeorder::impl_field_sqrt_tests!(FieldElement);
    primeorder::impl_primefield_tests!(FieldElement, T);
}
