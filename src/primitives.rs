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
