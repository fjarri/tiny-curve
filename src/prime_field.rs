use core::{
    fmt::Debug,
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, ShrAssign, Sub, SubAssign},
};

use num_traits::{ConstZero, FromBytes, ToBytes};
use primeorder::{
    elliptic_curve::{
        array::Array,
        bigint::{
            ctutils::{self, CtAssign, CtEq, CtSelectUsingCtAssign},
            U64,
        },
        ff::helpers::sqrt_ratio_generic,
        ops::{BatchInvert, Invert, MulVartime, Reduce, ReduceNonZero, Retrieve},
        rand_core::{TryCryptoRng, TryRng},
        scalar::{FromUintUnchecked, IsHigh},
        subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
        zeroize::DefaultIsZeroes,
        Field, Generate, PrimeField,
    },
    ByteOrder, FieldExt, PrimeFieldExt, WnafSize,
};

use crate::{
    primitives::{add, modular_inverse, mul, neg, sub},
    traits::{Modulus, PrimeFieldConstants, PrimitiveUint},
};

// The external integer representation of a field element.
pub(crate) type ReprUint = U64;

// The byte representation of a field element (per-modulus size).
type ReprBytes<T, const M: u64> = Array<u8, <Modulus<T, M> as PrimeFieldConstants<T>>::ReprSize>;

#[derive(Default, Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
pub struct FieldElement<T: PrimitiveUint, const M: u64>(T);

impl<T, const M: u64> CtEq for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn ct_eq(&self, other: &Self) -> ctutils::Choice {
        // TODO: `subtle` is still required by `ff`; switch to native `ctutils` when possible.
        ConstantTimeEq::ct_eq(self, other).into()
    }
}

impl<T, const M: u64> CtAssign for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn ct_assign(&mut self, src: &Self, choice: ctutils::Choice) {
        ConditionallySelectable::conditional_assign(self, src, choice.into())
    }
}

// Gives us `CtSelect` via a blanket impl.
impl<T, const M: u64> CtSelectUsingCtAssign for FieldElement<T, M> where T: PrimitiveUint {}

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

    fn to_uint(self) -> ReprUint {
        ReprUint::from(self.to_u64())
    }

    fn from_uint_unchecked(uint: ReprUint) -> Self {
        debug_assert!(uint.bits_vartime() <= u64::BITS);
        const DATA_SIZE: usize = u64::BITS as usize / 8;
        let bytes = uint.to_be_bytes();
        let value_bytes: [u8; DATA_SIZE] = bytes[bytes.len() - DATA_SIZE..]
            .try_into()
            .expect("slice has the correct length");
        Self::new_unchecked_u64(u64::from_be_bytes(value_bytes))
    }
}

impl<T, const M: u64> FieldElement<T, M>
where
    T: PrimitiveUint,
    Modulus<T, M>: PrimeFieldConstants<T>,
{
    // TODO: needed by `primefield::test_field_identity!`. Ideally it should just use arithmetic ops.
    #[cfg(test)]
    pub(crate) fn add(&self, rhs: &Self) -> Self {
        Self(add::<T, M>(&self.0, &rhs.0))
    }

    // TODO: needed by `primefield::test_field_identity!`. Ideally it should just use arithmetic ops.
    #[cfg(test)]
    pub(crate) fn multiply(&self, rhs: &Self) -> Self {
        Self(mul::<T, M>(&self.0, &rhs.0))
    }

    pub(crate) fn sqrt(&self) -> CtOption<Self> {
        // All our moduli are chosen so that they are 3 mod 4.
        debug_assert!(M & 3 == 3);
        // This means calculating the square root can be done via exponentiation.
        let res = self.pow_vartime([(M >> 2) + 1]);
        let is_square = ConstantTimeEq::ct_eq(&res.square(), self);
        CtOption::new(res, is_square)
    }

    fn to_repr(self) -> ReprBytes<T, M> {
        let mut out = ReprBytes::<T, M>::default();
        let out_len = out.len();

        let bytes = self.to_u64().to_be_bytes();
        debug_assert!(out_len <= bytes.len());
        debug_assert!(bytes[..bytes.len() - out_len].iter().all(|x| x == &0));
        out.copy_from_slice(&bytes[bytes.len() - out_len..]);

        out
    }

    fn try_from_repr(repr: &ReprBytes<T, M>) -> CtOption<Self> {
        let value = u64::from(uint_from_bytes_unchecked(repr));

        let within_range = value < M;

        // If the value is not within [0, M), avoid triggering debug checks in `new_unchecked_u64`,
        // and make it more clear that the value is invalid.
        let value = if within_range { value } else { 0 };

        CtOption::new(
            Self::new_unchecked_u64(value),
            Choice::from(within_range as u8),
        )
    }
}

fn uint_from_bytes_unchecked<T, const M: u64>(repr: &ReprBytes<T, M>) -> ReprUint
where
    T: PrimitiveUint,
    Modulus<T, M>: PrimeFieldConstants<T>,
{
    let mut buffer = [0u8; 8];
    debug_assert!(repr.len() <= buffer.len());
    let buffer_len = buffer.len();
    buffer[buffer_len - repr.len()..].copy_from_slice(repr);
    ReprUint::from(u64::from_be_bytes(buffer))
}

impl<T, const M: u64> DefaultIsZeroes for FieldElement<T, M> where T: PrimitiveUint {}

impl<T, const M: u64> FromUintUnchecked for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    type Uint = ReprUint;

    fn from_uint_unchecked(uint: Self::Uint) -> Self {
        FieldElement::from_uint_unchecked(uint)
    }
}

impl<T, const M: u64> Retrieve for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    type Output = ReprUint;
    fn retrieve(&self) -> Self::Output {
        self.to_uint()
    }
}

impl<T, const M: u64> Generate for FieldElement<T, M>
where
    T: PrimitiveUint,
    Modulus<T, M>: PrimeFieldConstants<T>,
{
    fn try_generate_from_rng<R>(rng: &mut R) -> Result<Self, <R as TryRng>::Error>
    where
        R: TryCryptoRng + ?Sized,
    {
        Self::try_random(rng)
    }
}

impl<T, const M: u64> WnafSize for FieldElement<T, M>
where
    T: PrimitiveUint,
    Modulus<T, M>: PrimeFieldConstants<T>,
{
    // Must be `NUM_BITS + 1`, so it is defined per-modulus.
    type StorageSize = <Modulus<T, M> as PrimeFieldConstants<T>>::WnafStorageSize;
}

// No methods yet, it's a placeholder for future optimized operations.
impl<T, const M: u64> FieldExt for FieldElement<T, M>
where
    T: PrimitiveUint,
    Modulus<T, M>: PrimeFieldConstants<T>,
{
}

impl<T, const M: u64> PrimeFieldExt for FieldElement<T, M>
where
    T: PrimitiveUint,
    Modulus<T, M>: PrimeFieldConstants<T>,
{
    const REPR_ENDIANNESS: ByteOrder = ByteOrder::BigEndian;
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

impl<T, const M: u64> From<FieldElement<T, M>> for ReprBytes<T, M>
where
    T: PrimitiveUint,
    Modulus<T, M>: PrimeFieldConstants<T>,
{
    fn from(source: FieldElement<T, M>) -> Self {
        source.to_repr()
    }
}

impl<T, const M: u64> From<FieldElement<T, M>> for ReprUint
where
    T: PrimitiveUint,
{
    fn from(source: FieldElement<T, M>) -> Self {
        source.to_uint()
    }
}

// Needed by `elliptic_curve::scalar_impls!`
impl<T, const M: u64> From<&FieldElement<T, M>> for ReprUint
where
    T: PrimitiveUint,
{
    fn from(source: &FieldElement<T, M>) -> Self {
        source.to_uint()
    }
}

impl<T, const M: u64> Invert for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    type Output = CtOption<Self>;

    fn invert(&self) -> Self::Output {
        let inverse = modular_inverse::<T, M>(&self.0);
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

impl<T, const M: u64> Reduce<ReprUint> for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn reduce(n: &ReprUint) -> Self {
        let value = u64::from(*n);
        Self::new_unchecked_u64(value % M)
    }
}

impl<T, const M: u64> Reduce<ReprBytes<T, M>> for FieldElement<T, M>
where
    T: PrimitiveUint,
    Modulus<T, M>: PrimeFieldConstants<T>,
{
    fn reduce(n: &ReprBytes<T, M>) -> Self {
        let uint = uint_from_bytes_unchecked(n);
        Self::reduce(&uint)
    }
}

impl<T, const M: u64> ReduceNonZero<ReprUint> for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn reduce_nonzero(n: &ReprUint) -> Self {
        let value = u64::from(*n);
        Self::new_unchecked_u64(value % (M - 1) + 1)
    }
}

impl<T, const M: u64> ReduceNonZero<ReprBytes<T, M>> for FieldElement<T, M>
where
    T: PrimitiveUint,
    Modulus<T, M>: PrimeFieldConstants<T>,
{
    fn reduce_nonzero(n: &ReprBytes<T, M>) -> Self {
        let uint = uint_from_bytes_unchecked(n);
        Self::reduce_nonzero(&uint)
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
        *self = Self(add::<T, M>(&self.0, &rhs.0))
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
        *self = Self(sub::<T, M>(&self.0, &rhs.0))
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
        *self = Self(mul::<T, M>(&self.0, &rhs.0))
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
        Self(neg::<T, M>(&self.0))
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

    fn try_random<R>(rng: &mut R) -> Result<Self, R::Error>
    where
        R: TryRng + ?Sized,
    {
        let mut buffer = T::Wide::ZERO.to_be_bytes();
        rng.try_fill_bytes(buffer.as_mut())?;
        Ok(Self(T::reduce_from_wide::<M>(T::Wide::from_be_bytes(
            &buffer,
        ))))
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
    type Repr = ReprBytes<T, M>;

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
        FieldElement::try_from_repr(&repr)
    }

    fn to_repr(&self) -> Self::Repr {
        (*self).to_repr()
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

// Uses the provided generic implementation (Montgomery's trick).
impl<T, const M: u64> BatchInvert for FieldElement<T, M>
where
    T: PrimitiveUint,
    Modulus<T, M>: PrimeFieldConstants<T>,
{
}

// There is nothing to gain from a variable-time multiplication for these small fields.

impl<T, const M: u64> MulVartime for FieldElement<T, M>
where
    T: PrimitiveUint,
    Modulus<T, M>: PrimeFieldConstants<T>,
{
    fn mul_vartime(self, rhs: Self) -> Self {
        self * rhs
    }
}

impl<'a, T, const M: u64> MulVartime<&'a FieldElement<T, M>> for FieldElement<T, M>
where
    T: PrimitiveUint,
    Modulus<T, M>: PrimeFieldConstants<T>,
{
    fn mul_vartime(self, rhs: &'a FieldElement<T, M>) -> Self {
        self * rhs
    }
}
