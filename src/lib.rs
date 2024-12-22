#![cfg_attr(not(test), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    missing_docs,
    missing_copy_implementations,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_qualifications
)]
#![cfg_attr(not(test), warn(clippy::unwrap_used))]

/*!
## Features

`serde`: `serde` support for [`elliptic_curve::PublicKey`]
parametrized by the curves from this crate.

`ecdsa`: [`ecdsa`] support for [`ecdsa::SigningKey`] and [`ecdsa::VerifyingKey`]
parametrized by the curves from this crate.

`pkcs8`: [`elliptic_curve::pkcs8`] support for [`elliptic_curve::SecretKey`]
and [`elliptic_curve::PublicKey`] parametrized by the curves from this crate.

`bip32`: [`bip32`](`::bip32`) support via newtypes [`PrivateKeyBip32`] and [`PublicKeyBip32`].
*/

mod curve16;
mod curve32;
mod curve64;
mod hash;
mod prime_field;
mod primitives;
mod prime_field2;
mod reciprocal;
mod traits;

#[cfg(feature = "bip32")]
mod bip32;

pub use curve16::TinyCurve16;
pub use curve32::TinyCurve32;
pub use curve64::TinyCurve64;

#[cfg(feature = "bip32")]
pub use bip32::{PrivateKeyBip32, PublicKeyBip32};
