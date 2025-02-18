use core::{
    fmt::Debug,
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, ShrAssign, Sub, SubAssign},
};

use num_traits::{ConstZero, FromBytes, ToBytes};
use primeorder::elliptic_curve::{
    bigint::{Encoding, NonZero, U192},
    ff::helpers::sqrt_ratio_generic,
    generic_array::{typenum, GenericArray},
    ops::{Invert, Reduce, ReduceNonZero},
    rand_core::RngCore,
    scalar::{FromUintUnchecked, IsHigh},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::DefaultIsZeroes,
    Curve, Field, PrimeField, ScalarPrimitive,
};

#[cfg(feature = "ecdsa")]
use ::{
    ecdsa::{hazmat::SignPrimitive, SignatureSize},
    primeorder::{
        elliptic_curve::{generic_array::ArrayLength, CurveArithmetic},
        FieldBytes, PrimeCurve,
    },
};

use crate::{
    primitives::{add, modular_inverse, mul, neg, sub},
    traits::{Modulus, PrimeFieldConstants, PrimitiveUint},
};

// The external representation of a field element.
// `U64` would be enough, but it has to match `ReprSizeTypenum`
// due to some internal checks in RustCrypto stack.
pub(crate) type ReprUint = U192;

// The size of the external representation of a field element.
// `U8` would be enough, but `U24` is the lowest size for which
// `sec1::ModulusSize` is implemented, which is needed for `elliptic_curve::FromEncodedPoint`.
// TODO: U8 should work starting from `sec1=0.8`, which will probably be
// a dependency of `primeorder=0.14`.
pub(crate) type ReprSizeTypenum = typenum::U24;

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
        Self(add::<T, M>(&self.0, &rhs.0))
    }

    // TODO: needed by `impl_primefield_tests!`. Ideally it should just use arithmetic ops.
    #[cfg(test)]
    pub(crate) fn multiply(&self, rhs: &Self) -> Self {
        Self(mul::<T, M>(&self.0, &rhs.0))
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
    C: Curve<Uint = ReprUint>,
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
    type Uint = ReprUint;

    fn from_uint_unchecked(uint: Self::Uint) -> Self {
        debug_assert!(uint.bits_vartime() <= u64::BITS as usize);
        const DATA_SIZE: usize = u64::BITS as usize / 8;
        let bytes = uint.to_be_bytes();
        let value_bytes: [u8; DATA_SIZE] = bytes[bytes.len() - DATA_SIZE..]
            .try_into()
            .expect("slice has the correct length");
        Self::new_unchecked_u64(u64::from_be_bytes(value_bytes))
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

impl<T, const M: u64> From<FieldElement<T, M>> for GenericArray<u8, typenum::U24>
where
    T: PrimitiveUint,
{
    fn from(source: FieldElement<T, M>) -> Self {
        let mut bytes = Self::default();
        let bytes_len = bytes.len();
        let source_bytes = source.to_u64().to_be_bytes();
        bytes[bytes_len - source_bytes.len()..].copy_from_slice(source_bytes.as_ref());
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

impl<T, const M: u64> From<FieldElement<T, M>> for ReprUint
where
    T: PrimitiveUint,
{
    fn from(source: FieldElement<T, M>) -> Self {
        ReprUint::from(source.to_u64())
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
    type Bytes = GenericArray<u8, ReprSizeTypenum>;

    fn reduce(n: ReprUint) -> Self {
        const DATA_SIZE: usize = u64::BITS as usize / 8;

        // TODO: use `rem_vartime()` when the crypto stack switches to crypto-bigint 0.6
        let reduced = n.rem(&NonZero::new(ReprUint::from(M)).expect("the modulus is non-zero"));

        let bytes = reduced.to_be_bytes();
        let value_bytes: [u8; DATA_SIZE] = bytes[bytes.len() - DATA_SIZE..]
            .try_into()
            .expect("slice has the correct length");
        Self::new_unchecked_u64(u64::from_be_bytes(value_bytes))
    }

    fn reduce_bytes(bytes: &Self::Bytes) -> Self {
        let uint = ReprUint::from_be_slice(bytes);
        Self::reduce(uint)
    }
}

impl<T, const M: u64> ReduceNonZero<ReprUint> for FieldElement<T, M>
where
    T: PrimitiveUint,
{
    fn reduce_nonzero(n: ReprUint) -> Self {
        const DATA_SIZE: usize = u64::BITS as usize / 8;

        // TODO: use `rem_vartime()` when the crypto stack switches to crypto-bigint 0.6
        let reduced = n.rem(
            &NonZero::new(ReprUint::from(M - 1))
                .expect("the modulus is non-zero and greater than 1"),
        );

        let bytes = reduced.to_be_bytes();
        let value_bytes: [u8; DATA_SIZE] = bytes[bytes.len() - DATA_SIZE..]
            .try_into()
            .expect("slice has the correct length");
        Self::new_unchecked_u64(u64::from_be_bytes(value_bytes) + 1)
    }

    fn reduce_nonzero_bytes(bytes: &Self::Bytes) -> Self {
        let uint = ReprUint::from_be_slice(bytes);
        Self::reduce_nonzero(uint)
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
        const DATA_SIZE: usize = u64::BITS as usize / 8;
        let repr_len = repr.as_ref().len();
        let data: [u8; DATA_SIZE] = repr.as_ref()[repr_len - DATA_SIZE..]
            .try_into()
            .expect("slice has the correct length");
        let value = u64::from_be_bytes(data);
        let high_bits_are_zero = repr.as_ref()[..repr_len - DATA_SIZE]
            .iter()
            .all(|x| x == &0);
        let within_range = Choice::from((high_bits_are_zero && value < M) as u8);
        CtOption::new(Self::new_unchecked_u64(value), within_range)
    }

    fn to_repr(&self) -> Self::Repr {
        const DATA_SIZE: usize = u64::BITS as usize / 8;
        let mut repr = Self::Repr::default();
        let repr_len = repr.as_ref().len();
        repr.as_mut()[repr_len - DATA_SIZE..].copy_from_slice(&self.to_u64().to_be_bytes());
        repr
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

#[cfg(feature = "ecdsa")]
impl<C, T, const M: u64> SignPrimitive<C> for FieldElement<T, M>
where
    T: PrimitiveUint,
    Modulus<T, M>: PrimeFieldConstants<T>,
    C: PrimeCurve + CurveArithmetic<Scalar = Self>,
    SignatureSize<C>: ArrayLength<u8>,
    Self: Reduce<C::Uint, Bytes = FieldBytes<C>>
        + PrimeField<Repr = FieldBytes<C>>
        + Into<FieldBytes<C>>,
{
}
