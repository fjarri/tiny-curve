use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
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

criterion_group!(benches, bench_arithmetic);

criterion_main!(benches);
