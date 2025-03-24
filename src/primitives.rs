use crate::traits::PrimitiveUint;

pub(crate) fn add<T, const M: u64>(lhs: &T, rhs: &T) -> T
where
    T: PrimitiveUint,
{
    let modulus = T::from_u64(M).expect("the modulus fits into `T`");
    let result = lhs.wrapping_add(rhs);
    if result >= modulus || &result < lhs {
        result.wrapping_sub(&modulus)
    } else {
        result
    }
}

pub(crate) fn sub<T, const M: u64>(lhs: &T, rhs: &T) -> T
where
    T: PrimitiveUint,
{
    let modulus = T::from_u64(M).expect("the modulus fits into `T`");
    let result = lhs.wrapping_sub(rhs);
    if lhs < rhs {
        result.wrapping_add(&modulus)
    } else {
        result
    }
}

pub(crate) fn mul<T, const M: u64>(lhs: &T, rhs: &T) -> T
where
    T: PrimitiveUint,
{
    T::reduce_from_wide::<M>(lhs.to_wide() * rhs.to_wide())
}

pub(crate) fn neg<T, const M: u64>(arg: &T) -> T
where
    T: PrimitiveUint,
{
    if arg == &T::ZERO {
        T::ZERO
    } else {
        T::from_u64(M).expect("the modulus fits into `T`") - *arg
    }
}

/// Calculates modular inverse of `a` modulo `b`.
pub(crate) fn modular_inverse<T, const M: u64>(arg: &T) -> Option<T>
where
    T: PrimitiveUint,
{
    let modulus = T::from_u64(M).expect("the modulus fits into `T`");

    // Using Extended Euclidean algorithm.
    // Essentially, it finds `n` and `m` such that `a * m + b * n = gcd(a, b)`.
    // If `gcd(a, b) = 1` (which is required for there to be an inverse),
    // and we find such nonzero `m` and `n`, it means `m` is our answer
    // since then `a * m = 1 mod b`.

    // A simlpe struct to keep track of the signs, since eGCD requires signed variables,
    // and our values can take the full range of the unsigned ones.
    #[derive(Clone, Copy)]
    struct Signed<T> {
        value: T,
        is_negative: bool,
    }

    if modulus <= T::ONE {
        return None;
    }

    if arg == &T::ZERO {
        return None;
    }

    let mut a = *arg;
    let mut b = modulus;

    let mut x0 = Signed {
        value: T::ZERO,
        is_negative: false,
    }; // b = 1*b + 0*a
    let mut x1 = Signed {
        value: T::ONE,
        is_negative: false,
    }; // a = 0*b + 1*a

    while a > T::ONE {
        if b == T::ZERO {
            // Means that original `a` and `modulus` were not co-prime so there is no answer
            return None;
        }

        // (b, a) := (a % b, b)
        let t = b;
        let q = a / b;
        b = a % b;
        a = t;

        // (x0, x1) := (x1 - q * x0, x0)
        let temp_x0 = x0;
        let qx0 = q * x0.value;
        // Allows us to exclude one branch in the condition below.
        debug_assert!(!(x0.is_negative == x1.is_negative && x1.value == qx0));
        if x0.is_negative != x1.is_negative {
            x0.value = x1.value + qx0;
            x0.is_negative = x1.is_negative;
        } else if x1.value > qx0 {
            x0.value = x1.value - qx0;
            x0.is_negative = x1.is_negative;
        } else {
            x0.value = qx0 - x1.value;
            x0.is_negative = !x0.is_negative;
        }
        x1 = temp_x0;
    }

    Some(if x1.is_negative {
        modulus - x1.value
    } else {
        x1.value
    })
}

#[cfg(test)]
mod tests {
    use super::modular_inverse;
    use proptest::prelude::*;

    #[test]
    fn inverse_of_zero() {
        const M: u64 = 0xfffffffffffffe95u64;
        assert!(modular_inverse::<u64, M>(&0).is_none());
    }

    proptest! {
        #[test]
        fn inverse(x in any::<u64>()) {
            // a prime, so there's always an inverse for non-zero `x`
            const M: u64 = 0xfffffffffffffe95u64;
            let x = if x == 0 {
                1
            }
            else {
                x
            };
            let inv = modular_inverse::<u64, M>(&x).unwrap();
            let should_be_one = ((inv as u128) * (x as u128) % (M as u128)) as u64;
            assert_eq!(should_be_one, 1);
        }
    }
}

type EfficientRepr = [u64; 1];

type CanonicalRepr = [u64; 1];

macro_rules! impl_primitive_ops {
    ($type:tt, $wide:tt) => {
        const fn add<const M: u64>(lhs: &[u64; 1], rhs: &[u64; 1]) -> [u64; 1] {
            let lhs = lhs[0] as $type;
            let rhs = rhs[0] as $type;
            let modulus = M as $type;
            let mut result = lhs.wrapping_add(rhs);
            if result >= modulus || result < lhs {
                result = result.wrapping_sub(modulus);
            }
            [result as u64]
        }

        const fn sub<const M: u64>(lhs: &[u64; 1], rhs: &[u64; 1]) -> [u64; 1] {
            let lhs = lhs[0] as $type;
            let rhs = rhs[0] as $type;
            let modulus = M as $type;
            let mut result = lhs.wrapping_sub(rhs);
            if lhs < rhs {
                result = result.wrapping_add(modulus);
            }
            [result]
        }

        const fn neg<const M: u64>(arg: &[u64; 1]) -> [u64; 1] {
            let arg = arg[0];
            let modulus = M; // T::from_u64(M).expect("the modulus fits into `T`");
            let result = if arg == 0 { arg} else { modulus - arg};
            [result as u64]
        }
    }
}

macro_rules! impl_primitive_mul_naive {
    ($type:tt, $wide:tt) => {
        const fn mul<const M: u64>(lhs: &[u64; 1], rhs: &[u64; 1]) -> [u64; 1] {
            let lhs = lhs[0] as $type;
            let rhs = rhs[0] as $type;
            let modulus = M as $type;
            let result = ((lhs as $wide) * (rhs as $wide) % (modulus as $wide)) as $type;
            [result as u64]
        }
    }
}

macro_rules! impl_primitive_mul_reciprocal {
    ($type:tt, $wide:tt) => {
        const fn mul<const M: u64>(lhs: &[u64; 1], rhs: &[u64; 1]) -> [u64; 1] {
            let lhs = lhs[0] as $type;
            let rhs = rhs[0] as $type;
            let modulus = M as $type;
            // This is the only integer size for which this gives a speed-up.
            const reciprocal = Reciprocal::new(M);
            let result = rem_wide_with_reciprocal(((lhs as $wide) * (rhs as $wide)) as u128, &reciprocal)
            [result as u64]
        }
    }
}
