use bip32::{PrivateKeyBytes, PublicKeyBytes};
use primeorder::elliptic_curve::{
    bigint::ArrayEncoding,
    generic_array::{typenum::Unsigned, GenericArray},
    ops::{MulByGenerator, ReduceNonZero},
    sec1::{EncodedPoint, FromEncodedPoint, ModulusSize, ToEncodedPoint},
    Curve, CurveArithmetic, NonZeroScalar, PublicKey, SecretKey,
};

use crate::prime_field::ReprSizeTypenum;

/// A newtype wrapper for [`elliptic_curve::SecretKey`] implementing [`bip32`] traits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKeyBip32<C: CurveArithmetic>(SecretKey<C>);

impl<C: CurveArithmetic> From<SecretKey<C>> for PrivateKeyBip32<C> {
    fn from(source: SecretKey<C>) -> Self {
        Self(source)
    }
}

impl<C: CurveArithmetic> AsRef<SecretKey<C>> for PrivateKeyBip32<C> {
    fn as_ref(&self) -> &SecretKey<C> {
        &self.0
    }
}

impl<C: CurveArithmetic> From<PrivateKeyBip32<C>> for SecretKey<C> {
    fn from(source: PrivateKeyBip32<C>) -> Self {
        source.0
    }
}

/// A newtype wrapper for [`elliptic_curve::PublicKey`] implementing [`bip32`] traits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKeyBip32<C: CurveArithmetic>(PublicKey<C>);

impl<C: CurveArithmetic> From<PublicKey<C>> for PublicKeyBip32<C> {
    fn from(source: PublicKey<C>) -> Self {
        Self(source)
    }
}

impl<C: CurveArithmetic> AsRef<PublicKey<C>> for PublicKeyBip32<C> {
    fn as_ref(&self) -> &PublicKey<C> {
        &self.0
    }
}

impl<C: CurveArithmetic> From<PublicKeyBip32<C>> for PublicKey<C> {
    fn from(source: PublicKeyBip32<C>) -> Self {
        source.0
    }
}

impl<C> bip32::PublicKey for PublicKeyBip32<C>
where
    C: Curve + CurveArithmetic,
    C::AffinePoint: ToEncodedPoint<C> + FromEncodedPoint<C>,
    C::FieldBytesSize: ModulusSize,
    C::Scalar: ReduceNonZero<C::Uint>,
{
    fn from_bytes(bytes: PublicKeyBytes) -> Result<Self, bip32::Error> {
        let bytes_len = bytes.len();
        let ep =
            EncodedPoint::<C>::from_bytes(&bytes[bytes_len - ReprSizeTypenum::to_usize() - 1..])
                .map_err(|_| bip32::Error::Decode)?;
        Ok(Self(
            Option::from(PublicKey::from_encoded_point(&ep)).ok_or(bip32::Error::Crypto)?,
        ))
    }

    fn to_bytes(&self) -> PublicKeyBytes {
        let mut bytes = [0u8; 33];
        let bytes_len = bytes.len();
        let ep = self.0.to_encoded_point(true);
        bytes[bytes_len - ReprSizeTypenum::to_usize() - 1..].copy_from_slice(ep.as_bytes());
        bytes
    }

    fn derive_child(&self, other: PrivateKeyBytes) -> Result<Self, bip32::Error> {
        let bytes_len = other.len();
        let repr = GenericArray::<u8, <C::Uint as ArrayEncoding>::ByteSize>::from_exact_iter(
            other[bytes_len - <C::Uint as ArrayEncoding>::ByteSize::to_usize()..]
                .iter()
                .copied(),
        )
        .expect("slice length is correct");
        let child_scalar = NonZeroScalar::<C>::reduce_nonzero(C::Uint::from_be_byte_array(repr));

        let child_point =
            self.0.to_projective() + C::ProjectivePoint::mul_by_generator(&child_scalar);
        Ok(Self(
            PublicKey::from_affine(child_point.into()).map_err(|_| bip32::Error::Crypto)?,
        ))
    }
}

impl<C> bip32::PrivateKey for PrivateKeyBip32<C>
where
    C: Curve + CurveArithmetic,
    C::AffinePoint: ToEncodedPoint<C> + FromEncodedPoint<C>,
    C::FieldBytesSize: ModulusSize,
    C::Scalar: ReduceNonZero<C::Uint>,
{
    type PublicKey = PublicKeyBip32<C>;

    fn from_bytes(bytes: &PrivateKeyBytes) -> Result<Self, bip32::Error> {
        let bytes_len = bytes.len();
        Ok(Self(
            SecretKey::from_slice(&bytes[bytes_len - ReprSizeTypenum::to_usize()..])
                .map_err(|_| bip32::Error::Crypto)?,
        ))
    }

    fn to_bytes(&self) -> PrivateKeyBytes {
        let repr = self.0.to_bytes();
        let mut bytes = PrivateKeyBytes::default();
        let bytes_len = bytes.len();
        bytes[bytes_len - repr.len()..].copy_from_slice(&repr);
        bytes
    }

    fn derive_child(&self, other: PrivateKeyBytes) -> Result<Self, bip32::Error> {
        let bytes_len = other.len();
        let repr = GenericArray::<u8, <C::Uint as ArrayEncoding>::ByteSize>::from_exact_iter(
            other[bytes_len - <C::Uint as ArrayEncoding>::ByteSize::to_usize()..]
                .iter()
                .copied(),
        )
        .expect("slice length is correct");
        let child_scalar = NonZeroScalar::<C>::reduce_nonzero(C::Uint::from_be_byte_array(repr));
        let derived_scalar = *self.0.to_nonzero_scalar().as_ref() + *child_scalar.as_ref();

        Option::<NonZeroScalar<C>>::from(NonZeroScalar::new(derived_scalar))
            .map(SecretKey::from)
            .map(Self)
            .ok_or(bip32::Error::Crypto)
    }

    fn public_key(&self) -> Self::PublicKey {
        PublicKeyBip32(SecretKey::public_key(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use bip32::{ChildNumber, PrivateKey as _, PublicKey as _};
    use primeorder::elliptic_curve::SecretKey;
    use rand_core::OsRng;

    use crate::curve64::TinyCurve64;

    use super::{PrivateKeyBip32, PublicKeyBip32};

    #[test]
    fn public_key_roundtrip() {
        let sk = SecretKey::<TinyCurve64>::random(&mut OsRng);
        let pk = sk.public_key();

        let pk_bip32 = PublicKeyBip32::from(pk);
        let bytes = pk_bip32.to_bytes();
        let pk_bip32_back = PublicKeyBip32::<TinyCurve64>::from_bytes(bytes).unwrap();
        assert_eq!(pk_bip32, pk_bip32_back);
    }

    #[test]
    fn private_key_roundtrip() {
        let sk = SecretKey::<TinyCurve64>::random(&mut OsRng);

        let sk_bip32 = PrivateKeyBip32::from(sk);
        let bytes = sk_bip32.to_bytes();
        let sk_bip32_back = PrivateKeyBip32::<TinyCurve64>::from_bytes(&bytes).unwrap();
        assert_eq!(sk_bip32, sk_bip32_back);
    }

    #[test]
    fn derivation() {
        let sk = SecretKey::<TinyCurve64>::random(&mut OsRng);
        let pk = sk.public_key();

        let child_number = ChildNumber(123);
        let chain_code = [1u8; 32];

        let sk = PrivateKeyBip32::from(sk);
        let pk = PublicKeyBip32::from(pk);

        let (tweak, _new_chain_code) = pk.derive_tweak(&chain_code, child_number).unwrap();

        let derived_from_sk = sk.derive_child(tweak).unwrap();
        let derived_from_pk = pk.derive_child(tweak).unwrap();

        assert_eq!(derived_from_sk.public_key(), derived_from_pk);
    }
}
