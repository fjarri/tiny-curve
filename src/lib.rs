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

//! ## `serde` support
//!
//! When the `serde` feature of this crate is enabled, `Serialize` and
//! `Deserialize` are impl'd for the associated
//! [`CurveArithmetic::Scalar`](primeorder::elliptic_curve::CurveArithmetic::Scalar)
//! types of the curves.

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
