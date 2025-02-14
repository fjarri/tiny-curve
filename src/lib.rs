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

`serde`: `serde` support for [`primeorder::elliptic_curve::PublicKey`]
parametrized by the curves from this crate.
*/

mod curve16;
mod curve32;
mod curve64;
mod ecdsa;
mod hash;
mod prime_field;
mod primitives;
mod reciprocal;
mod traits;

pub use curve16::TinyCurve16;
pub use curve32::TinyCurve32;
pub use curve64::TinyCurve64;
