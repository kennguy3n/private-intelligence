//! Resource governor benchmarks.
//!
//! Measures governor check_resources, acquire/release semaphore,
//! and timeout enforcement overhead.

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use zk_ai_core::governor::{ResourceGovernor, GovernorConfig};
use zk_ai_core::profiler::{DeviceTier, ThermalState};
use std::time::Duration;

fn bench_check_resources(c: &mut Criterion) {
    let mut group = c.benchmark_group("governor/check_resources");

    let tiers = [
        ("high_end", DeviceTier::HighEnd),
        ("mid_range", DeviceTier::MidRange),
        ("low_end", DeviceTier::LowEnd),
        ("throttled", DeviceTier::Throttled),
    ];

    for (name, tier) in tiers {
        let config = GovernorConfig::from_tier(&tier);
        let governor = ResourceGovernor::new(config);

        group.bench_with_input(BenchmarkId::new("tier", name), &governor, |b, gov| {
            b.iter(|| {
                gov.check_resources()
            });
        });
    }
    group.finish();
}

fn bench_acquire_release(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("governor/acquire_release");

    let tiers = [
        ("high_end", DeviceTier::HighEnd),
        ("mid_range", DeviceTier::MidRange),
        ("low_end", DeviceTier::LowEnd),
    ];

    for (name, tier) in tiers {
        let config = GovernorConfig::from_tier(&tier);
        let governor = ResourceGovernor::new(config);

        group.bench_with_input(BenchmarkId::new("tier", name), &governor, |b, gov| {
            b.to_async(&rt).iter(|| async {
                let permit = gov.acquire().await.unwrap();
                drop(permit);
            });
        });
    }
    group.finish();
}

fn bench_thermal_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("governor/thermal");

    let states = [
        ("nominal", ThermalState::Nominal),
        ("fair", ThermalState::Fair),
        ("serious", ThermalState::Serious),
        ("critical", ThermalState::Critical),
    ];

    for (name, state) in states {
        let config = GovernorConfig::from_tier(&DeviceTier::HighEnd);
        let mut governor = ResourceGovernor::new(config);
        governor.update_thermal(state);

        group.bench_with_input(BenchmarkId::new("state", name), &governor, |b, gov| {
            b.iter(|| {
                gov.is_paused()
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_check_resources,
    bench_acquire_release,
    bench_thermal_check,
);
criterion_main!(benches);
