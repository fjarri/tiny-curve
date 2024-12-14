//! Implementation of constant-time division via reciprocal precomputation, as described in
//! "Improved Division by Invariant Integers" by Niels Möller and Torbjorn Granlund
//! (DOI: 10.1109/TC.2010.143, <https://gmplib.org/~tege/division-paper.pdf>).

/// Adds wide numbers represented by pairs of (most significant word, least significant word)
/// and returns the result in the same format `(hi, lo)`.
#[inline(always)]
const fn addhilo(x_hi: u64, x_lo: u64, y_hi: u64, y_lo: u64) -> (u64, u64) {
    let res = (((x_hi as u128) << u64::BITS) | (x_lo as u128))
        + (((y_hi as u128) << u64::BITS) | (y_lo as u128));
    ((res >> u64::BITS) as u64, res as u64)
}

/// Multiplies `x` and `y`, returning the most significant
/// and the least significant words as `(hi, lo)`.
#[inline(always)]
const fn mulhilo(x: u64, y: u64) -> (u64, u64) {
    let res = (x as u128) * (y as u128);
    ((res >> u64::BITS) as u64, res as u64)
}

/// Calculates the reciprocal of the given 64-bit divisor with the highmost bit set.
const fn reciprocal(d: u64) -> u64 {
    debug_assert!(d >= (1 << (u64::BITS - 1)));

    let d0 = d & 1;
    let d9 = d >> 55;
    let d40 = (d >> 24) + 1;
    let d63 = (d >> 1) + d0;
    let v0 = short_div((1 << 19) - 3 * (1 << 8), 19, d9 as u32, 9) as u64;
    let v1 = (v0 << 11) - ((v0 * v0 * d40) >> 40) - 1;
    let v2 = (v1 << 13) + ((v1 * ((1 << 60) - v1 * d40)) >> 47);

    // Checks that the expression for `e` can be simplified in the way we did below.
    debug_assert!(mulhilo(v2, d63).0 == (1 << 32) - 1);
    let e = u64::MAX - v2.wrapping_mul(d63) + 1 + (v2 >> 1) * d0;

    let (hi, _lo) = mulhilo(v2, e);
    let v3 = (v2 << 31).wrapping_add(hi >> 1);

    // The paper has `(v3 + 1) * d / 2^64` (there's another 2^64, but it's accounted for later).
    // If `v3 == 2^64-1` this should give `d`, but we can't achieve this in our wrapping arithmetic.
    // Hence the `ct_select()`.
    let x = v3.wrapping_add(1);
    let (hi, _lo) = mulhilo(x, d);

    let hi = if x > 0 { hi } else { d };

    v3.wrapping_sub(hi).wrapping_sub(d)
}

/// Calculates `dividend / divisor`, given `dividend` and `divisor`
/// along with their maximum bitsizes.
#[inline(always)]
const fn short_div(dividend: u32, dividend_bits: u32, divisor: u32, divisor_bits: u32) -> u32 {
    // TODO: this may be sped up even more using the fact that `dividend` is a known constant.

    // Passing `dividend_bits` and `divisor_bits` because calling `.leading_zeros()`
    // causes a significant slowdown, and we know those values anyway.

    let mut dividend = dividend;
    let mut divisor = divisor << (dividend_bits - divisor_bits);
    let mut quotient: u32 = 0;
    let mut i = dividend_bits - divisor_bits + 1;

    while i > 0 {
        i -= 1;
        if dividend >= divisor {
            dividend = dividend.wrapping_sub(divisor);
            quotient |= 1 << i;
        }
        divisor >>= 1;
    }

    quotient
}

/// A pre-calculated reciprocal for division by a single limb.
#[derive(Copy, Clone, Debug)]
pub struct Reciprocal {
    divisor_normalized: u64,
    shift: u32,
    reciprocal: u64,
}

impl Reciprocal {
    /// Pre-calculates a reciprocal for a known divisor.
    pub const fn new(divisor: u64) -> Self {
        let shift = divisor.leading_zeros();
        let divisor_normalized = divisor << shift;

        Self {
            divisor_normalized,
            shift,
            reciprocal: reciprocal(divisor_normalized),
        }
    }
}

/// Calculate the quotient and the remainder of the division of a wide word
/// (supplied as high and low words) by `d`, with a precalculated reciprocal `v`.
#[inline(always)]
pub(crate) fn div2by1(u1: u64, u0: u64, reciprocal: &Reciprocal) -> (u64, u64) {
    let d = reciprocal.divisor_normalized;
    let rec = reciprocal.reciprocal;

    debug_assert!(d >= (1 << (u64::BITS - 1)));
    debug_assert!(u1 < d);

    let (q1, q0) = mulhilo(rec, u1);
    let (q1, q0) = addhilo(q1, q0, u1, u0);
    let mut q1 = q1.wrapping_add(1);
    let mut r = u0.wrapping_sub(q1.wrapping_mul(d));

    if r > q0 {
        q1 = q1.wrapping_sub(1);
        r = r.wrapping_add(d);
    }

    debug_assert!(r < d || q1 < u64::MAX);
    if r >= d {
        q1 += 1;
        r -= d;
    }

    (q1, r)
}

#[inline(always)]
fn rem_with_reciprocal(hi: u64, lo: u64, reciprocal: &Reciprocal) -> u64 {
    let mut hi = hi << reciprocal.shift;
    if reciprocal.shift > 0 {
        hi |= lo >> (u64::BITS - reciprocal.shift);
    }
    let lo = lo << reciprocal.shift;
    let (_q, r) = div2by1(hi, lo, reciprocal);
    r >> reciprocal.shift
}

/// Calculates the remainder of `x` mod the divisor that was used to create `reciprocal`.
/// Note that the top 64 bits of `x` must be smaller than the divisor.
// In our case this is always true since `x` is a product of two numbers modulo `m`,
// and `m` is what we create the reciprocal for.
#[inline(always)]
pub fn rem_wide_with_reciprocal(x: u128, reciprocal: &Reciprocal) -> u64 {
    let hi = (x >> u64::BITS) as u64;
    let lo = x as u64;
    rem_with_reciprocal(hi, lo, reciprocal)
}

#[cfg(test)]
mod tests {
    use super::{rem_wide_with_reciprocal, Reciprocal};
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn rem(x in any::<u128>(), m in any::<u64>()) {
            let m = if m == 0 {
                1
            }
            else {
                m
            };
            let t = x % ((m as u128) * (m as u128));

            let expected = (t % (m as u128)) as u64;
            let test = rem_wide_with_reciprocal(t, &Reciprocal::new(m));
            assert_eq!(test, expected);
        }
    }
}
