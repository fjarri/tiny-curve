use core::{
    fmt::Debug,
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, ShrAssign, Sub, SubAssign},
};

use num_traits::{ConstZero, FromBytes, ToBytes};
use primeorder::elliptic_curve::{
    bigint::{
        modular::runtime_mod::{DynResidue, DynResidueParams},
        U64,
    },
    ff::helpers::sqrt_ratio_generic,
    generic_array::{typenum, GenericArray},
    ops::{Invert, Reduce},
    rand_core::RngCore,
    scalar::{FromUintUnchecked, IsHigh},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::DefaultIsZeroes,
    Curve, Field, PrimeField, ScalarPrimitive,
};

use crate::traits::{Modulus, PrimeFieldConstants, PrimitiveUint};

#[derive(Default, Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
pub struct FieldElement<T: PrimitiveUint, const M: u64>(T);

impl<T, const M: u64> FieldElement<T, M>
where
    T: PrimitiveUint,
{
    pub(crate) const fn new_unchecked(value: T) -> Self {
        Self(value)
    }

    fn new_unchecked_u64(value: u64) -> Self {
        debug_assert!(value < M);
        Self(T::from_u64(value).expect("the value is less than the modulus and therefore fits `T`"))
    }

    fn to_u64(self) -> u64 {
        self.0.into()
    }
}

impl<T, const M: u64> FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn reduce_from_wide(value: T::Wide) -> Self {
        let modulus = T::from_u64(M).unwrap().into_wide();
        Self(T::from_wide(value % modulus).unwrap())
    }
}

impl<T, const M: u64> DefaultIsZeroes for FieldElement<T, M> where T: PrimitiveUint {}

impl<C, T, const M: u64> From<ScalarPrimitive<C>> for FieldElement<T, M>
where
    C: Curve<Uint = U64>,
    T: PrimitiveUint,
{
    fn from(source: ScalarPrimitive<C>) -> Self {
        Self::from_uint_unchecked(source.to_uint())
    }
}

impl<T, const M: u64> FromUintUnchecked for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    type Uint = U64;

    fn from_uint_unchecked(uint: Self::Uint) -> Self {
        Self::new_unchecked_u64(uint.into())
    }
}

impl<T, const M: u64> From<u64> for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn from(source: u64) -> Self {
        debug_assert!(source < M);
        Self::new_unchecked_u64(source)
    }
}

impl<T, const M: u64> From<FieldElement<T, M>> for GenericArray<u8, typenum::U8>
where
    T: PrimitiveUint,
{
    fn from(source: FieldElement<T, M>) -> Self {
        let mut bytes = Self::default();
        let source_bytes = source.to_u64().to_be_bytes();
        bytes.copy_from_slice(source_bytes.as_ref());
        bytes
    }
}

impl<C, T, const M: u64> From<FieldElement<T, M>> for ScalarPrimitive<C>
where
    C: Curve,
    T: PrimitiveUint,
{
    fn from(source: FieldElement<T, M>) -> Self {
        ScalarPrimitive::new(C::Uint::from(source.to_u64())).expect("the value is within range")
    }
}

impl<T, const M: u64> From<FieldElement<T, M>> for U64
where
    T: PrimitiveUint,
{
    fn from(source: FieldElement<T, M>) -> Self {
        U64::from(source.to_u64())
    }
}

impl<T, const M: u64> Invert for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    type Output = CtOption<Self>;

    fn invert(&self) -> Self::Output {
        let uint_mod = DynResidue::new(&U64::from(*self), DynResidueParams::new(&U64::from(M)));
        let (inv, inv_exists) = uint_mod.invert();
        let result = Self::from_uint_unchecked(inv.retrieve());
        CtOption::new(result, inv_exists.into())
    }
}

impl<T, const M: u64> IsHigh for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn is_high(&self) -> Choice {
        Choice::from((self.to_u64() > (M >> 1)) as u8)
    }
}

impl<T, const M: u64> Reduce<U64> for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    type Bytes = GenericArray<u8, typenum::U8>;

    fn reduce(n: U64) -> Self {
        Self::from(u64::from(n) % M)
    }

    fn reduce_bytes(bytes: &Self::Bytes) -> Self {
        let uint = U64::from_be_slice(bytes);
        Self::reduce(uint)
    }
}

impl<T, const M: u64> ShrAssign<usize> for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn shr_assign(&mut self, shift: usize) {
        self.0.shr_assign(shift)
    }
}

// Addition

impl<'a, T, const M: u64> AddAssign<&'a FieldElement<T, M>> for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn add_assign(&mut self, rhs: &'a FieldElement<T, M>) {
        *self = Self::reduce_from_wide(self.0.into_wide() + rhs.0.into_wide())
    }
}

impl<T, const M: u64> AddAssign<FieldElement<T, M>> for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn add_assign(&mut self, rhs: FieldElement<T, M>) {
        *self += &rhs
    }
}

impl<T, const M: u64> Add<FieldElement<T, M>> for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    type Output = FieldElement<T, M>;
    fn add(mut self, rhs: FieldElement<T, M>) -> Self::Output {
        self += rhs;
        self
    }
}

impl<'a, T, const M: u64> Add<&'a FieldElement<T, M>> for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    type Output = FieldElement<T, M>;
    fn add(mut self, rhs: &'a FieldElement<T, M>) -> Self::Output {
        self += rhs;
        self
    }
}

// Subtraction

impl<'a, T, const M: u64> SubAssign<&'a FieldElement<T, M>> for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn sub_assign(&mut self, rhs: &'a FieldElement<T, M>) {
        *self = Self::reduce_from_wide(
            self.0.into_wide() + T::from_u64(M).unwrap().into_wide() - rhs.0.into_wide(),
        )
    }
}

impl<T, const M: u64> SubAssign<FieldElement<T, M>> for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn sub_assign(&mut self, rhs: FieldElement<T, M>) {
        *self -= &rhs
    }
}

impl<T, const M: u64> Sub<FieldElement<T, M>> for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    type Output = FieldElement<T, M>;
    fn sub(mut self, rhs: FieldElement<T, M>) -> Self::Output {
        self -= rhs;
        self
    }
}

impl<'a, T, const M: u64> Sub<&'a FieldElement<T, M>> for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    type Output = FieldElement<T, M>;
    fn sub(mut self, rhs: &'a FieldElement<T, M>) -> Self::Output {
        self -= rhs;
        self
    }
}

// Multiplication

impl<'a, T, const M: u64> MulAssign<&'a FieldElement<T, M>> for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn mul_assign(&mut self, rhs: &'a FieldElement<T, M>) {
        *self = Self::reduce_from_wide(self.0.into_wide() * rhs.0.into_wide())
    }
}

impl<T, const M: u64> MulAssign<FieldElement<T, M>> for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn mul_assign(&mut self, rhs: FieldElement<T, M>) {
        *self *= &rhs
    }
}

impl<T, const M: u64> Mul<FieldElement<T, M>> for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    type Output = FieldElement<T, M>;
    fn mul(mut self, rhs: FieldElement<T, M>) -> Self::Output {
        self *= rhs;
        self
    }
}

impl<'a, T, const M: u64> Mul<&'a FieldElement<T, M>> for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    type Output = FieldElement<T, M>;
    fn mul(mut self, rhs: &'a FieldElement<T, M>) -> Self::Output {
        self *= rhs;
        self
    }
}

impl<T, const M: u64> Sum for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::from(0), Add::add)
    }
}

impl<'a, T, const M: u64> Sum<&'a FieldElement<T, M>> for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn sum<I: Iterator<Item = &'a FieldElement<T, M>>>(iter: I) -> Self {
        iter.fold(Self::from(0), Add::add)
    }
}

impl<T, const M: u64> Product for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::from(1), Mul::mul)
    }
}

impl<'a, T, const M: u64> Product<&'a FieldElement<T, M>> for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn product<I: Iterator<Item = &'a FieldElement<T, M>>>(iter: I) -> Self {
        iter.fold(Self::from(1), Mul::mul)
    }
}

impl<T, const M: u64> Neg for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self(if self.0 == T::ZERO {
            T::ZERO
        } else {
            T::from_u64(M).unwrap() - self.0
        })
    }
}

impl<T, const M: u64> ConstantTimeEq for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.0.ct_eq(&rhs.0)
    }
}

impl<T, const M: u64> ConditionallySelectable for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn conditional_select(lhs: &Self, rhs: &Self, choice: Choice) -> Self {
        Self(T::conditional_select(&lhs.0, &rhs.0, choice))
    }
}

impl<T, const M: u64> Field for FieldElement<T, M>
where
    T: PrimitiveUint,
    Modulus<T, M>: PrimeFieldConstants<T>,
{
    const ZERO: Self = Self(T::ZERO);
    const ONE: Self = Self(T::ONE);

    fn random(mut rng: impl RngCore) -> Self {
        let mut buffer = T::Wide::ZERO.to_be_bytes();
        rng.fill_bytes(buffer.as_mut());
        Self::reduce_from_wide(T::Wide::from_be_bytes(&buffer))
    }

    fn square(&self) -> Self {
        Self::reduce_from_wide(self.0.into_wide() * self.0.into_wide())
    }

    fn double(&self) -> Self {
        Self::reduce_from_wide(self.0.into_wide() << 1)
    }

    fn invert(&self) -> CtOption<Self> {
        <Self as Invert>::invert(self)
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        sqrt_ratio_generic(num, div)
    }
}

impl<T, const M: u64> PrimeField for FieldElement<T, M>
where
    T: PrimitiveUint,
    Modulus<T, M>: PrimeFieldConstants<T>,
{
    type Repr = <Modulus<T, M> as PrimeFieldConstants<T>>::Repr;

    const MODULUS: &'static str = Modulus::<T, M>::MODULUS;
    const NUM_BITS: u32 = Modulus::<T, M>::NUM_BITS;
    const CAPACITY: u32 = Modulus::<T, M>::CAPACITY;
    const TWO_INV: Self = FieldElement::new_unchecked(Modulus::<T, M>::TWO_INV);
    const MULTIPLICATIVE_GENERATOR: Self =
        FieldElement::new_unchecked(Modulus::<T, M>::MULTIPLICATIVE_GENERATOR);
    const S: u32 = Modulus::<T, M>::S;
    const ROOT_OF_UNITY: Self = FieldElement::new_unchecked(Modulus::<T, M>::ROOT_OF_UNITY);
    const ROOT_OF_UNITY_INV: Self = FieldElement::new_unchecked(Modulus::<T, M>::ROOT_OF_UNITY_INV);
    const DELTA: Self = FieldElement::new_unchecked(Modulus::<T, M>::DELTA);

    fn from_repr(repr: Self::Repr) -> CtOption<Self> {
        let value = u64::from_be_bytes(repr.into());
        let within_range = Choice::from((value < M) as u8);
        CtOption::new(Self::new_unchecked_u64(value), within_range)
    }

    fn to_repr(&self) -> Self::Repr {
        self.to_u64().to_be_bytes().into()
    }

    fn is_odd(&self) -> Choice {
        Choice::from((self.to_u64() & 1) as u8)
    }
}

impl<T, const M: u64> AsRef<FieldElement<T, M>> for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn as_ref(&self) -> &FieldElement<T, M> {
        self
    }
}
