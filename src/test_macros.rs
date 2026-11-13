macro_rules! test_scalar {
    ($curve:tt) => {
        use ::primeorder::elliptic_curve::{Curve, CurveArithmetic};

        type F = <$curve as CurveArithmetic>::Scalar;
        type ReprUint = <$curve as Curve>::Uint;

        ::primefield::test_primefield!(F, ReprUint);

        #[test]
        fn is_high() {
            use ::primeorder::elliptic_curve::{
                Curve, CurveArithmetic,
                ff::{Field, PrimeField},
                scalar::FromUintUnchecked,
            };

            type F = <$curve as CurveArithmetic>::Scalar;
            type ReprUint = <$curve as Curve>::Uint;

            let one = F::ONE;
            assert_eq!(
                ::elliptic_curve::scalar::IsHigh::is_high(&one).unwrap_u8(),
                0
            );

            let modulus_uint = ReprUint::from_be_hex(F::MODULUS);
            let half_modulus_uint = modulus_uint / ReprUint::from(2u64);

            let half_modulus_minus_1 =
                F::from_uint_unchecked(half_modulus_uint - ReprUint::from(1u64));
            assert_eq!(
                ::elliptic_curve::scalar::IsHigh::is_high(&half_modulus_minus_1).unwrap_u8(),
                0
            );

            let half_modulus = F::from_uint_unchecked(half_modulus_uint);
            assert_eq!(
                ::elliptic_curve::scalar::IsHigh::is_high(&half_modulus).unwrap_u8(),
                0
            );

            let half_modulus_plus_1 =
                F::from_uint_unchecked(half_modulus_uint + ReprUint::from(1u64));
            assert_eq!(
                ::elliptic_curve::scalar::IsHigh::is_high(&half_modulus_plus_1).unwrap_u8(),
                1
            );

            let modulus_minus_1 = F::from_uint_unchecked(modulus_uint - ReprUint::from(1u64));
            assert_eq!(
                ::elliptic_curve::scalar::IsHigh::is_high(&modulus_minus_1).unwrap_u8(),
                1
            );
        }

        #[test]
        fn reduce_from_field_bytes() {
            use ::primeorder::{
                Field, PrimeField,
                elliptic_curve::CurveArithmetic,
                elliptic_curve::{
                    Curve, FieldBytes,
                    ops::{Reduce, ReduceNonZero},
                },
            };

            type F = <$curve as CurveArithmetic>::Scalar;
            type ReprUint = <$curve as Curve>::Uint;

            let modulus_uint = ReprUint::from_be_hex(F::MODULUS);
            let modulus_plus_one = modulus_uint + ReprUint::from(1u64);
            let uint_repr = modulus_plus_one.to_be_bytes();

            let mut field_bytes = FieldBytes::<$curve>::default();
            let field_bytes_len = field_bytes.len();
            field_bytes.copy_from_slice(&uint_repr[uint_repr.len() - field_bytes_len..]);

            let x = F::reduce(&field_bytes);
            assert_eq!(x, F::ONE);

            let x = F::reduce_nonzero(&field_bytes);
            assert_eq!(x, F::from(3u64));
        }

        #[test]
        fn mul_vartime() {
            use ::primeorder::{
                Field, elliptic_curve::CurveArithmetic, elliptic_curve::ops::MulVartime,
            };
            type F = <$curve as CurveArithmetic>::Scalar;

            let x = -F::ONE;
            assert_eq!(x.mul_vartime(&x), x * x);
            assert_eq!(x.mul_vartime(x), x * x);
        }

        #[test]
        fn as_ref() {
            use ::primeorder::{Field, elliptic_curve::CurveArithmetic};
            type F = <$curve as CurveArithmetic>::Scalar;

            let x = -F::ONE;
            let ref_x: &F = x.as_ref();
            assert_eq!(ref_x, &x);
        }

        #[test]
        fn constant_time_ops() {
            use ::primeorder::{Field, elliptic_curve::CurveArithmetic};
            type F = <$curve as CurveArithmetic>::Scalar;

            let zero = F::ZERO;
            let one = F::ONE;
            assert_eq!(elliptic_curve::bigint::CtEq::ct_eq(&one, &one).to_u8(), 1);
            assert_eq!(elliptic_curve::bigint::CtEq::ct_eq(&one, &zero).to_u8(), 0);

            assert_eq!(
                elliptic_curve::bigint::CtSelect::ct_select(
                    &zero,
                    &one,
                    elliptic_curve::bigint::Choice::FALSE
                ),
                zero
            );
            assert_eq!(
                elliptic_curve::bigint::CtSelect::ct_select(
                    &zero,
                    &one,
                    elliptic_curve::bigint::Choice::TRUE
                ),
                one
            );
        }
    };
}

pub(crate) use test_scalar;

macro_rules! test_field {
    ($curve:tt) => {
        use ::primeorder::{FieldArithmetic, elliptic_curve::Curve};

        type F = <$curve as FieldArithmetic>::FieldElement;
        type ReprUint = <$curve as Curve>::Uint;

        ::primefield::test_primefield!(F, ReprUint);
    };
}

pub(crate) use test_field;

macro_rules! test_curve {
    ($curve:tt) => {
        use ::primeorder::{
            PrimeField,
            array::typenum::Unsigned,
            elliptic_curve::{
                Curve, CurveArithmetic, Field, FieldBytesSize, Group, ProjectivePoint,
                array::Array, ops::Reduce,
            },
        };
        use ::proptest::prelude::*;
        use ::rand::rngs::SysRng;
        use ::rand_core::UnwrapErr;

        type Scalar = <$curve as CurveArithmetic>::Scalar;
        type Point = ProjectivePoint<$curve>;
        type ReprUint = <$curve as Curve>::Uint;

        #[test]
        fn identity() {
            let x = Scalar::random(&mut UnwrapErr(SysRng));
            let y = Scalar::ZERO - x;
            let p = Point::mul_by_generator(&x) + Point::mul_by_generator(&y);
            assert_eq!(p, Point::IDENTITY);
        }

        #[test]
        fn to_and_from_repr() {
            let mut repr = Array::<u8, FieldBytesSize<$curve>>::default();

            // `s` now contains the value `M - 1`.
            let s = -Scalar::new_unchecked(1);
            let s_uint: ReprUint = s.into();

            // Check that to_repr/from_repr work normally
            let s_uint_repr = s_uint.to_be_bytes();
            repr.copy_from_slice(
                &s_uint_repr[s_uint_repr.len() - FieldBytesSize::<$curve>::USIZE..],
            );
            let s_repr = s.to_repr();
            assert_eq!(repr, s_repr);
            assert_eq!(Scalar::from_repr(repr).unwrap(), s);

            // Now construct a representation of the value `M` (which would be out of range).
            // `M` still fits into the repr since the modulus is smaller than `2^(8 * repr.len())`.
            let x_uint = s_uint.wrapping_add(&ReprUint::ONE);
            let x_uint_repr = x_uint.to_be_bytes();
            repr.copy_from_slice(
                &x_uint_repr[x_uint_repr.len() - FieldBytesSize::<$curve>::USIZE..],
            );
            assert!(bool::from(Scalar::from_repr(repr).is_none()));
        }

        prop_compose! {
            /// Generate a random odd modulus.
            fn scalar()(n in any::<u64>()) -> Scalar {
                Scalar::reduce(&ReprUint::from(n))
            }
        }

        proptest! {
            #[test]
            fn mul_by_generator(x in scalar(), y in scalar()) {
                let p1 = Point::mul_by_generator(&x) + Point::mul_by_generator(&y);
                let p2 = Point::mul_by_generator(&(x + y));
                assert_eq!(p1, p2);
            }
        }

        #[cfg(feature = "ecdsa")]
        mod ecdsa {
            use ::ecdsa::{SigningKey, VerifyingKey};
            use ::primeorder::elliptic_curve::Generate;
            use ::rand::rngs::SysRng;
            use ::rand_core::UnwrapErr;

            use super::$curve;

            #[test]
            fn sign_and_verify() {
                let prehash = b"123456781234567812345678";
                let sk = SigningKey::<$curve>::generate_from_rng(&mut UnwrapErr(SysRng));

                let (signature, recovery_id) = sk.sign_prehash_recoverable(prehash);
                let vk =
                    VerifyingKey::recover_from_prehash(prehash, &signature, recovery_id).unwrap();
                assert_eq!(sk.verifying_key(), &vk);
            }
        }

        #[cfg(feature = "pkcs8")]
        mod pkcs8 {
            use ::primeorder::elliptic_curve::{
                Generate, PublicKey, SecretKey,
                pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
            };
            use ::rand::rngs::SysRng;
            use ::rand_core::UnwrapErr;

            use super::$curve;

            #[test]
            fn serialize_secret_key() {
                let sk = SecretKey::<$curve>::generate_from_rng(&mut UnwrapErr(SysRng));
                let der = sk.to_pkcs8_der().unwrap();
                let sk_back = SecretKey::<$curve>::from_pkcs8_der(der.as_bytes()).unwrap();
                assert_eq!(sk, sk_back);
            }

            #[test]
            fn serialize_public_key() {
                let sk = SecretKey::<$curve>::generate_from_rng(&mut UnwrapErr(SysRng));
                let pk = sk.public_key();
                let der = pk.to_public_key_der().unwrap();
                let pk_back = PublicKey::<$curve>::from_public_key_der(der.as_bytes()).unwrap();
                assert_eq!(pk, pk_back);
            }
        }

        #[cfg(feature = "serde")]
        mod serde {
            use ::primeorder::elliptic_curve::{Generate, PublicKey, SecretKey};
            use ::rand::rngs::SysRng;
            use ::rand_core::UnwrapErr;

            use super::$curve;

            #[test]
            fn serialize_public_key() {
                let sk = SecretKey::<$curve>::generate_from_rng(&mut UnwrapErr(SysRng));
                let pk = sk.public_key();
                let bytes = postcard::to_allocvec(&pk).unwrap();
                let pk_back: PublicKey<$curve> = postcard::from_bytes(&bytes).unwrap();
                assert_eq!(pk, pk_back);
            }

            #[cfg(feature = "ecdsa")]
            #[test]
            fn serialize_verifying_key() {
                let sk = SecretKey::<$curve>::generate_from_rng(&mut UnwrapErr(SysRng));
                let pk = sk.public_key();
                let vk = ecdsa::VerifyingKey::from(&pk);
                let bytes = postcard::to_allocvec(&vk).unwrap();
                let vk_back: ecdsa::VerifyingKey<$curve> = postcard::from_bytes(&bytes).unwrap();
                assert_eq!(vk, vk_back);
            }
        }
    };
}

pub(crate) use test_curve;
