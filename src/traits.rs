use core::{fmt::Debug, marker::PhantomData, ops::ShrAssign};

use num_traits::{
    ConstOne, ConstZero, FromBytes, FromPrimitive, ToBytes, Unsigned, WrappingAdd, WrappingSub,
};
use primeorder::elliptic_curve::subtle::{ConditionallySelectable, ConstantTimeEq};

use crate::reciprocal::{rem_wide_with_reciprocal, Reciprocal};

pub trait PrimeFieldConstants<T> {
    type Repr: AsRef<[u8]> + AsMut<[u8]> + Send + Sync + Default + Clone + Copy;
    const MODULUS_STR: &'static str;
    const MODULUS: T;
    const NUM_BITS: u32;
    const CAPACITY: u32;
    const TWO_INV: T;
    const MULTIPLICATIVE_GENERATOR: T;
    const S: u32 = 2;
    const ROOT_OF_UNITY: T;
    const ROOT_OF_UNITY_INV: T;
    const DELTA: T;
}

pub struct Modulus<T, const M: u64>(PhantomData<T>);

pub trait HasReciprocal {
    const RECIPROCAL: Reciprocal;
}

impl<const M: u64> HasReciprocal for Modulus<u64, M> {
    const RECIPROCAL: Reciprocal = Reciprocal::new(M);
}

pub trait HasWide: Sized {
    type Wide: WideUint;
    fn to_wide(self) -> Self::Wide;
    fn from_wide_unchecked(source: Self::Wide) -> Self;
}

impl HasWide for u16 {
    type Wide = u32;
    fn to_wide(self) -> Self::Wide {
        self.into()
    }
    fn from_wide_unchecked(source: Self::Wide) -> Self {
        source as Self
    }
}

impl HasWide for u32 {
    type Wide = u64;
    fn to_wide(self) -> Self::Wide {
        self.into()
    }
    fn from_wide_unchecked(source: Self::Wide) -> Self {
        source as Self
    }
}

impl HasWide for u64 {
    type Wide = u128;
    fn to_wide(self) -> Self::Wide {
        self.into()
    }
    fn from_wide_unchecked(source: Self::Wide) -> Self {
        source as Self
    }
}

pub trait PrimitiveUint:
    'static
    + Send
    + Sync
    + Default
    + Debug
    + Clone
    + Copy
    + Ord
    + Eq
    + ConstantTimeEq
    + ConditionallySelectable
    + Unsigned
    + ConstZero
    + ConstOne
    + FromPrimitive
    + WrappingAdd
    + WrappingSub
    + ShrAssign<usize>
    + HasWide
    + Into<u64>
{
    fn reduce_from_wide<const M: u64>(value: Self::Wide) -> Self {
        Self::from_wide_unchecked(
            value
                % Self::from_u64(M)
                    .expect("modulus is within range")
                    .to_wide(),
        )
    }
}

pub trait WideUint:
    Unsigned + ToBytes<Bytes = <Self as FromBytes>::Bytes> + FromBytes<Bytes: Sized> + ConstZero
{
}

impl PrimitiveUint for u16 {}

impl PrimitiveUint for u32 {}

impl PrimitiveUint for u64 {
    fn reduce_from_wide<const M: u64>(value: Self::Wide) -> Self {
        // This is the only integer size for which this gives a speed-up.
        let reciprocal = Modulus::<Self, M>::RECIPROCAL;
        rem_wide_with_reciprocal(value, &reciprocal)
    }
}

impl WideUint for u32 {}
impl WideUint for u64 {}
impl WideUint for u128 {}
