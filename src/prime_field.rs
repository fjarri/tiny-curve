use core::{
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, ShrAssign, Sub, SubAssign},
};

use elliptic_curve::{
    bigint::{
        modular::runtime_mod::{DynResidue, DynResidueParams},
        U64,
    },
    ops::{Invert, Reduce},
    rand_core::RngCore,
    scalar::{FromUintUnchecked, IsHigh},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::DefaultIsZeroes,
    Curve, Field, FieldBytes, PrimeField, ScalarPrimitive,
};

use crate::curve::{Modulus, PrimeFieldConstants, TinyCurve};

#[derive(Default, Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
pub struct FieldElement<const M: u64>(u64);

impl<const M: u64> FieldElement<M> {
    pub(crate) const fn new_unchecked(value: u64) -> Self {
        Self(value)
    }

    pub(crate) const fn neg(self) -> Self {
        Self(if self.0 == 0 { 0 } else { M - self.0 })
    }

    fn from_u128(value: u128) -> Self {
        Self((value % (M as u128)) as u64)
    }
}

impl<const M: u64> DefaultIsZeroes for FieldElement<M> {}

impl<const M: u64> From<ScalarPrimitive<TinyCurve>> for FieldElement<M> {
    fn from(source: ScalarPrimitive<TinyCurve>) -> Self {
        Self(source.to_uint().as_words()[0])
    }
}

impl<const M: u64> FromUintUnchecked for FieldElement<M> {
    type Uint = U64;

    fn from_uint_unchecked(uint: Self::Uint) -> Self {
        Self(uint.as_words()[0])
    }
}

impl<const M: u64> From<u64> for FieldElement<M> {
    fn from(source: u64) -> Self {
        Self(source)
    }
}

impl<const M: u64> From<FieldElement<M>> for FieldBytes<TinyCurve> {
    fn from(source: FieldElement<M>) -> Self {
        source.0.to_be_bytes().into()
    }
}

impl<const M: u64> From<FieldElement<M>> for ScalarPrimitive<TinyCurve> {
    fn from(source: FieldElement<M>) -> Self {
        ScalarPrimitive::new(U64::from(source.0)).expect("the value is within range")
    }
}

impl<const M: u64> From<FieldElement<M>> for <TinyCurve as Curve>::Uint {
    fn from(source: FieldElement<M>) -> Self {
        U64::from(source.0)
    }
}

impl<const M: u64> Invert for FieldElement<M> {
    type Output = CtOption<Self>;

    fn invert(&self) -> Self::Output {
        let uint_mod =
            DynResidue::new(&U64::from(self.0), DynResidueParams::new(&TinyCurve::ORDER));
        let (inv, inv_exists) = uint_mod.invert();
        let result = Self::from_uint_unchecked(inv.retrieve());
        CtOption::new(result, inv_exists.into())
    }
}

impl<const M: u64> IsHigh for FieldElement<M> {
    fn is_high(&self) -> Choice {
        Choice::from((self.0 > (M >> 1)) as u8)
    }
}

impl<const M: u64> Reduce<<TinyCurve as Curve>::Uint> for FieldElement<M> {
    type Bytes = FieldBytes<TinyCurve>;

    fn reduce(n: <TinyCurve as Curve>::Uint) -> Self {
        Self(n.as_words()[0] % M)
    }

    fn reduce_bytes(bytes: &Self::Bytes) -> Self {
        // TODO: How can it be ensured to be uniform with `impl From<FieldElement<M>> for FieldBytes`?
        let uint = <TinyCurve as Curve>::Uint::from_be_slice(bytes);
        Self::reduce(uint)
    }
}

impl<const M: u64> ShrAssign<usize> for FieldElement<M> {
    fn shr_assign(&mut self, shift: usize) {
        self.0.shr_assign(shift)
    }
}

// Addition

impl<'a, const M: u64> AddAssign<&'a FieldElement<M>> for FieldElement<M> {
    fn add_assign(&mut self, rhs: &'a FieldElement<M>) {
        *self = Self::from_u128((self.0 as u128) + (rhs.0 as u128))
    }
}

impl<const M: u64> AddAssign<FieldElement<M>> for FieldElement<M> {
    fn add_assign(&mut self, rhs: FieldElement<M>) {
        *self += &rhs
    }
}

impl<const M: u64> Add<FieldElement<M>> for FieldElement<M> {
    type Output = FieldElement<M>;
    fn add(mut self, rhs: FieldElement<M>) -> Self::Output {
        self += rhs;
        self
    }
}

impl<'a, const M: u64> Add<&'a FieldElement<M>> for FieldElement<M> {
    type Output = FieldElement<M>;
    fn add(mut self, rhs: &'a FieldElement<M>) -> Self::Output {
        self += rhs;
        self
    }
}

// Subtraction

impl<'a, const M: u64> SubAssign<&'a FieldElement<M>> for FieldElement<M> {
    fn sub_assign(&mut self, rhs: &'a FieldElement<M>) {
        *self = Self::from_u128((self.0 as u128) + (M as u128) - (rhs.0 as u128))
    }
}

impl<const M: u64> SubAssign<FieldElement<M>> for FieldElement<M> {
    fn sub_assign(&mut self, rhs: FieldElement<M>) {
        *self -= &rhs
    }
}

impl<const M: u64> Sub<FieldElement<M>> for FieldElement<M> {
    type Output = FieldElement<M>;
    fn sub(mut self, rhs: FieldElement<M>) -> Self::Output {
        self -= rhs;
        self
    }
}

impl<'a, const M: u64> Sub<&'a FieldElement<M>> for FieldElement<M> {
    type Output = FieldElement<M>;
    fn sub(mut self, rhs: &'a FieldElement<M>) -> Self::Output {
        self -= rhs;
        self
    }
}

// Multiplication

impl<'a, const M: u64> MulAssign<&'a FieldElement<M>> for FieldElement<M> {
    fn mul_assign(&mut self, rhs: &'a FieldElement<M>) {
        *self = Self::from_u128((self.0 as u128) * (rhs.0 as u128))
    }
}

impl<const M: u64> MulAssign<FieldElement<M>> for FieldElement<M> {
    fn mul_assign(&mut self, rhs: FieldElement<M>) {
        *self *= &rhs
    }
}

impl<const M: u64> Mul<FieldElement<M>> for FieldElement<M> {
    type Output = FieldElement<M>;
    fn mul(mut self, rhs: FieldElement<M>) -> Self::Output {
        self *= rhs;
        self
    }
}

impl<'a, const M: u64> Mul<&'a FieldElement<M>> for FieldElement<M> {
    type Output = FieldElement<M>;
    fn mul(mut self, rhs: &'a FieldElement<M>) -> Self::Output {
        self *= rhs;
        self
    }
}

impl<const M: u64> Sum for FieldElement<M> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::from(0), Add::add)
    }
}

impl<'a, const M: u64> Sum<&'a FieldElement<M>> for FieldElement<M> {
    fn sum<I: Iterator<Item = &'a FieldElement<M>>>(iter: I) -> Self {
        iter.fold(Self::from(0), Add::add)
    }
}

impl<const M: u64> Product for FieldElement<M> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::from(1), Mul::mul)
    }
}

impl<'a, const M: u64> Product<&'a FieldElement<M>> for FieldElement<M> {
    fn product<I: Iterator<Item = &'a FieldElement<M>>>(iter: I) -> Self {
        iter.fold(Self::from(1), Mul::mul)
    }
}

impl<const M: u64> Neg for FieldElement<M> {
    type Output = Self;
    fn neg(self) -> Self::Output {
        self.neg()
    }
}

impl<const M: u64> ConstantTimeEq for FieldElement<M> {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.0.ct_eq(&rhs.0)
    }
}

impl<const M: u64> ConditionallySelectable for FieldElement<M> {
    fn conditional_select(lhs: &Self, rhs: &Self, choice: Choice) -> Self {
        Self(u64::conditional_select(&lhs.0, &rhs.0, choice))
    }
}

impl<const M: u64> Field for FieldElement<M>
where
    Modulus<M>: PrimeFieldConstants,
{
    const ZERO: Self = Self(0);
    const ONE: Self = Self(1);

    fn random(mut rng: impl RngCore) -> Self {
        let mut buffer = [0u8; 16];
        rng.fill_bytes(&mut buffer);
        Self::from_u128(u128::from_be_bytes(buffer))
    }

    fn square(&self) -> Self {
        Self::from_u128((self.0 as u128) * (self.0 as u128))
    }

    fn double(&self) -> Self {
        Self::from_u128((self.0 as u128) << 1)
    }

    fn invert(&self) -> CtOption<Self> {
        <Self as Invert>::invert(self)
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        elliptic_curve::ff::helpers::sqrt_ratio_generic(num, div)
    }
}

impl<const M: u64> PrimeField for FieldElement<M>
where
    Modulus<M>: PrimeFieldConstants,
{
    type Repr = FieldBytes<TinyCurve>;

    const MODULUS: &'static str = Modulus::<M>::MODULUS;
    const NUM_BITS: u32 = Modulus::<M>::NUM_BITS;
    const CAPACITY: u32 = Modulus::<M>::CAPACITY;
    const TWO_INV: Self = FieldElement::new_unchecked(Modulus::<M>::TWO_INV);
    const MULTIPLICATIVE_GENERATOR: Self =
        FieldElement::new_unchecked(Modulus::<M>::MULTIPLICATIVE_GENERATOR);
    const S: u32 = Modulus::<M>::S;
    const ROOT_OF_UNITY: Self = FieldElement::new_unchecked(Modulus::<M>::ROOT_OF_UNITY);
    const ROOT_OF_UNITY_INV: Self = FieldElement::new_unchecked(Modulus::<M>::ROOT_OF_UNITY_INV);
    const DELTA: Self = FieldElement::new_unchecked(Modulus::<M>::DELTA);

    fn from_repr(repr: Self::Repr) -> CtOption<Self> {
        let value = u64::from_be_bytes(repr.into());
        let within_range = Choice::from((value < M) as u8);
        CtOption::new(Self(value), within_range)
    }

    fn to_repr(&self) -> Self::Repr {
        self.0.to_be_bytes().into()
    }

    fn is_odd(&self) -> Choice {
        Choice::from(self.0 as u8 & 1)
    }
}

impl<const M: u64> AsRef<FieldElement<M>> for FieldElement<M> {
    fn as_ref(&self) -> &FieldElement<M> {
        self
    }
}
