use core::{
    fmt::Debug,
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, ShrAssign, Sub, SubAssign},
};

use num_traits::{ConstZero, FromBytes, ToBytes};
use primeorder::elliptic_curve::{
    bigint::U64,
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
    Modulus<T, M>: PrimeFieldConstants<T>,
{
    #[cfg(test)]
    pub(crate) const MODULUS: T = Modulus::<T, M>::MODULUS;

    // TODO: needed by `impl_primefield_tests!`. Ideally it should just use arithmetic ops.
    #[cfg(test)]
    pub(crate) fn add(&self, rhs: &Self) -> Self {
        let modulus = T::from_u64(M).expect("the modulus fits into `T`");
        let mut result = self.0.wrapping_add(&rhs.0);
        if result >= modulus || result < self.0 {
            result = result.wrapping_sub(&modulus);
        }
        Self(result)
    }

    // TODO: needed by `impl_primefield_tests!`. Ideally it should just use arithmetic ops.
    #[cfg(test)]
    pub(crate) fn multiply(&self, rhs: &Self) -> Self {
        Self(T::reduce_from_wide::<M>(self.0.to_wide() * rhs.0.to_wide()))
    }

    pub(crate) fn sqrt(&self) -> CtOption<Self> {
        // All our moduli are chosen so that they are 3 mod 4.
        debug_assert!(M & 3 == 3);
        // This means calculating the square root can be done via exponentiation.
        let res = self.pow_vartime([(M >> 2) + 1]);
        let is_square = res.square().ct_eq(self);
        CtOption::new(res, is_square)
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

// TODO: needed by `impl_primefield_tests!`.
#[cfg(test)]
impl<T, const M: u64> From<u32> for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn from(source: u32) -> Self {
        let source = source.into();
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
        let modulus = T::from_u64(M).expect("the modulus fits into `T`");
        let inverse = modular_inverse(self.0, modulus);
        match inverse {
            Some(inv) => CtOption::new(Self(inv), Choice::from(1)),
            None => CtOption::new(Self(T::ZERO), Choice::from(0)),
        }
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
        let modulus = T::from_u64(M).expect("the modulus fits into `T`");
        let mut result = self.0.wrapping_add(&rhs.0);
        if result >= modulus || result < self.0 {
            result = result.wrapping_sub(&modulus);
        }
        *self = Self(result)
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
        let modulus = T::from_u64(M).expect("the modulus fits into `T`");
        let mut result = self.0.wrapping_sub(&rhs.0);
        if self.0 < rhs.0 {
            result = result.wrapping_add(&modulus);
        }
        *self = Self(result)
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
        *self = Self(T::reduce_from_wide::<M>(self.0.to_wide() * rhs.0.to_wide()))
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
        iter.fold(Self::from(0u64), Add::add)
    }
}

impl<'a, T, const M: u64> Sum<&'a FieldElement<T, M>> for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn sum<I: Iterator<Item = &'a FieldElement<T, M>>>(iter: I) -> Self {
        iter.fold(Self::from(0u64), Add::add)
    }
}

impl<T, const M: u64> Product for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::from(1u64), Mul::mul)
    }
}

impl<'a, T, const M: u64> Product<&'a FieldElement<T, M>> for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn product<I: Iterator<Item = &'a FieldElement<T, M>>>(iter: I) -> Self {
        iter.fold(Self::from(1u64), Mul::mul)
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
            T::from_u64(M).expect("the modulus fits into `T`") - self.0
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
        Self(T::reduce_from_wide::<M>(T::Wide::from_be_bytes(&buffer)))
    }

    fn square(&self) -> Self {
        Self(T::reduce_from_wide::<M>(
            self.0.to_wide() * self.0.to_wide(),
        ))
    }

    fn double(&self) -> Self {
        *self + self
    }

    fn invert(&self) -> CtOption<Self> {
        <Self as Invert>::invert(self)
    }

    fn sqrt(&self) -> CtOption<Self> {
        self.sqrt()
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        // Note that this relies on `Self::sqrt()`,
        // so in order to avoid infinite recurrence, that has to be overridden as well.
        sqrt_ratio_generic(num, div)
    }
}

impl<T, const M: u64> PrimeField for FieldElement<T, M>
where
    T: PrimitiveUint,
    Modulus<T, M>: PrimeFieldConstants<T>,
{
    type Repr = <Modulus<T, M> as PrimeFieldConstants<T>>::Repr;

    const MODULUS: &'static str = Modulus::<T, M>::MODULUS_STR;
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

/// Calculates modular inverse of `a` modulo `b`.
fn modular_inverse<T: PrimitiveUint>(a: T, modulus: T) -> Option<T> {
    // Using Extended Euclidean algorithm.
    // Essentially, it finds `n` and `m` such that `a * m + b * n = gcd(a, b)`.
    // If `gcd(a, b) = 1` (which is required for there to be an inverse),
    // and we find such nonzero `m` and `n`, it means `m` is our answer
    // since then `a * m = 1 mod b`.

    // A simlpe struct to keep track of the signs, since eGCD requires signed variables,
    // and our values can take the full range of the unsigned ones.
    #[derive(Clone, Copy)]
    struct Signed<T> {
        value: T,
        is_negative: bool,
    }

    if modulus <= T::ONE {
        return None;
    }

    let mut a = a;
    let mut b = modulus;

    let mut x0 = Signed {
        value: T::ZERO,
        is_negative: false,
    }; // b = 1*b + 0*a
    let mut x1 = Signed {
        value: T::ONE,
        is_negative: false,
    }; // a = 0*b + 1*a

    while a > T::ONE {
        if b == T::ZERO {
            // Means that original `a` and `modulus` were not co-prime so there is no answer
            return None;
        }

        // (b, a) := (a % b, b)
        let t = b;
        let q = a / b;
        b = a % b;
        a = t;

        // (x0, x1) := (x1 - q * x0, x0)
        let temp_x0 = x0;
        let qx0 = q * x0.value;
        // Allows us to exclude one branch in the condition below.
        debug_assert!(!(x0.is_negative == x1.is_negative && x1.value == qx0));
        if x0.is_negative != x1.is_negative {
            x0.value = x1.value + qx0;
            x0.is_negative = x1.is_negative;
        } else if x1.value > qx0 {
            x0.value = x1.value - qx0;
            x0.is_negative = x1.is_negative;
        } else {
            x0.value = qx0 - x1.value;
            x0.is_negative = !x0.is_negative;
        }
        x1 = temp_x0;
    }

    Some(if x1.is_negative {
        modulus - x1.value
    } else {
        x1.value
    })
}

#[cfg(test)]
mod tests {
    use super::modular_inverse;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn inverse(x in any::<u64>()) {
            let m = 0xfffffffffffffe95u64; // a prime, so there's always an inverse for non-zero `x`
            let x = if x == 0 {
                1
            }
            else {
                x
            };
            let inv = modular_inverse(x, m).unwrap();
            let should_be_one = ((inv as u128) * (x as u128) % (m as  u128)) as u64;
            assert_eq!(should_be_one, 1);
        }
    }
}
