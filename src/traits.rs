use core::{
    fmt::Debug,
    marker::PhantomData,
    ops::{Shl, ShrAssign},
};

use num_traits::{ConstOne, ConstZero, FromBytes, FromPrimitive, ToBytes, Unsigned};
use primeorder::elliptic_curve::subtle::{ConditionallySelectable, ConstantTimeEq};

pub trait PrimeFieldConstants<T> {
    type Repr: AsRef<[u8]>
        + AsMut<[u8]>
        + Send
        + Sync
        + Default
        + Clone
        + Copy
        + From<[u8; 8]>
        + Into<[u8; 8]>;
    const MODULUS: &'static str;
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

pub trait HasWide: Sized {
    type Wide: WideUint;
    fn to_wide(self) -> Self::Wide;
    fn from_wide_unchecked(source: Self::Wide) -> Self;
    fn try_from_wide(source: Self::Wide) -> Option<Self>;
}

impl HasWide for u16 {
    type Wide = u32;
    fn to_wide(self) -> Self::Wide {
        self.into()
    }
    fn from_wide_unchecked(source: Self::Wide) -> Self {
        source as Self
    }
    fn try_from_wide(wide: Self::Wide) -> Option<Self> {
        Self::try_from(wide).ok()
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
    fn try_from_wide(wide: Self::Wide) -> Option<Self> {
        Self::try_from(wide).ok()
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
    fn try_from_wide(wide: Self::Wide) -> Option<Self> {
        Self::try_from(wide).ok()
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
    + ShrAssign<usize>
    + HasWide
    + Into<u64>
{
    const BITS: u32;
}

pub trait WideUint:
    Unsigned
    + ToBytes<Bytes = <Self as FromBytes>::Bytes>
    + FromBytes<Bytes: Sized>
    + ConstZero
    + Shl<usize, Output = Self>
{
}

impl PrimitiveUint for u16 {
    const BITS: u32 = Self::BITS;
}
impl PrimitiveUint for u32 {
    const BITS: u32 = Self::BITS;
}
impl PrimitiveUint for u64 {
    const BITS: u32 = Self::BITS;
}

impl WideUint for u32 {}
impl WideUint for u64 {}
impl WideUint for u128 {}
