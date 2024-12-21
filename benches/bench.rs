use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use ecdsa::SigningKey;
use k256::Secp256k1;
use primeorder::elliptic_curve::{ops::MulByGenerator, CurveArithmetic, Field, ProjectivePoint};
use rand_core::OsRng;
use tiny_curve::{TinyCurve16, TinyCurve32, TinyCurve64};

fn bench_arithmetic(c: &mut Criterion) {
    let mut group = c.benchmark_group("arithmetic");

    group.bench_function("Curve16, mul_by_generator", |b| {
        b.iter_batched(
            || <TinyCurve16 as CurveArithmetic>::Scalar::random(&mut OsRng),
            |scalar| ProjectivePoint::<TinyCurve16>::mul_by_generator(&scalar),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("Curve32, mul_by_generator", |b| {
        b.iter_batched(
            || <TinyCurve32 as CurveArithmetic>::Scalar::random(&mut OsRng),
            |scalar| ProjectivePoint::<TinyCurve32>::mul_by_generator(&scalar),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("Curve64, mul_by_generator", |b| {
        b.iter_batched(
            || <TinyCurve64 as CurveArithmetic>::Scalar::random(&mut OsRng),
            |scalar| ProjectivePoint::<TinyCurve64>::mul_by_generator(&scalar),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("k256, mul_by_generator", |b| {
        b.iter_batched(
            || <Secp256k1 as CurveArithmetic>::Scalar::random(&mut OsRng),
            |scalar| ProjectivePoint::<Secp256k1>::mul_by_generator(&scalar),
            BatchSize::SmallInput,
        )
    });

    group.finish()
}

fn bench_ecdsa(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDSA");

    let prehash = b"12345678";
    group.bench_function("Curve16, sign", |b| {
        b.iter_batched(
            || SigningKey::<TinyCurve16>::random(&mut OsRng),
            |sk| sk.sign_prehash_recoverable(prehash),
            BatchSize::SmallInput,
        )
    });

    let prehash = b"12345678";
    group.bench_function("Curve32, sign", |b| {
        b.iter_batched(
            || SigningKey::<TinyCurve32>::random(&mut OsRng),
            |sk| sk.sign_prehash_recoverable(prehash),
            BatchSize::SmallInput,
        )
    });

    let prehash = b"12345678";
    group.bench_function("Curve64, sign", |b| {
        b.iter_batched(
            || SigningKey::<TinyCurve64>::random(&mut OsRng),
            |sk| sk.sign_prehash_recoverable(prehash),
            BatchSize::SmallInput,
        )
    });

    let prehash = b"01234567890123456789012345678901";
    group.bench_function("k256, sign", |b| {
        b.iter_batched(
            || SigningKey::<Secp256k1>::random(&mut OsRng),
            |sk| sk.sign_prehash_recoverable(prehash),
            BatchSize::SmallInput,
        )
    });

    group.finish()
}

criterion_group!(benches, bench_arithmetic, bench_ecdsa);

criterion_main!(benches);
