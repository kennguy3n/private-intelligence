//! Swarm coordination latency benchmarks.
//!
//! Measures device election, capability update, and task dispatch
//! overhead in the SwarmCoordinator.

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use zk_ai_core::swarm::{SwarmCoordinator, DeviceCapability, SwarmTransport, InferenceRequest, InferenceResult};
use zk_ai_core::profiler::DeviceTier;
use zk_ai_core::{Result, ZkAiError};
use async_trait::async_trait;

struct MockTransport;

#[async_trait]
impl SwarmTransport for MockTransport {
    async fn broadcast_capability(&self, _cap: &DeviceCapability) -> Result<()> { Ok(()) }
    async fn send_request(&self, _req: &InferenceRequest) -> Result<()> { Ok(()) }
    async fn send_result(&self, _result: &InferenceResult) -> Result<()> { Ok(()) }
    async fn recv_request(&self) -> Result<InferenceRequest> {
        Err(ZkAiError::Swarm("mock".to_string()))
    }
    async fn recv_result(&self) -> Result<InferenceResult> {
        Err(ZkAiError::Swarm("mock".to_string()))
    }
    async fn recv_capability(&self) -> Result<DeviceCapability> {
        Err(ZkAiError::Swarm("mock".to_string()))
    }
}

fn make_device(id: &str, name: &str, tier: DeviceTier, idle: bool, models: Vec<&str>) -> DeviceCapability {
    DeviceCapability {
        device_id: id.to_string(),
        device_name: name.to_string(),
        tier,
        available_models: models.iter().map(|s| s.to_string()).collect(),
        battery_level: Some(80),
        is_idle: idle,
    }
}

fn bench_device_election(c: &mut Criterion) {
    let mut group = c.benchmark_group("swarm/elect_device");

    let configs: &[(usize, &[DeviceTier])] = &[
        (3, &[DeviceTier::HighEnd, DeviceTier::MidRange, DeviceTier::LowEnd]),
        (10, &[DeviceTier::HighEnd, DeviceTier::MidRange, DeviceTier::LowEnd, DeviceTier::HighEnd, DeviceTier::MidRange,
               DeviceTier::LowEnd, DeviceTier::HighEnd, DeviceTier::MidRange, DeviceTier::LowEnd, DeviceTier::Throttled]),
        (20, &[DeviceTier::HighEnd, DeviceTier::MidRange, DeviceTier::LowEnd, DeviceTier::Throttled]),
    ];

    for &(count, tiers) in configs {
        let local = make_device("local", "Local", DeviceTier::HighEnd, false, vec!["mt5-small"]);
        let mut coord = SwarmCoordinator::new(MockTransport, local);

        for i in 0..count {
            let tier = tiers[i % tiers.len()];
            coord.update_device(make_device(
                &format!("dev_{}", i),
                &format!("Device {}", i),
                tier,
                true,
                vec!["mt5-small", "e5-small"],
            ));
        }

        group.bench_with_input(BenchmarkId::new("devices", count), &count, |b, _| {
            b.iter(|| {
                coord.elect_device("mt5-small")
            });
        });
    }
    group.finish();
}

fn bench_capability_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("swarm/update_device");

    let device_counts = [2, 5, 10, 20, 50];

    for &count in &device_counts {
        let local = make_device("local", "Local", DeviceTier::HighEnd, false, vec!["mt5-small"]);
        let mut coord = SwarmCoordinator::new(MockTransport, local);

        for i in 0..count {
            coord.update_device(make_device(
                &format!("dev_{}", i),
                &format!("Device {}", i),
                DeviceTier::MidRange,
                true,
                vec!["mt5-small"],
            ));
        }

        group.bench_with_input(BenchmarkId::new("update_existing", count), &count, |b, _| {
            b.iter(|| {
                coord.update_device(make_device("dev_0", "Device 0 Updated", DeviceTier::HighEnd, true, vec!["mt5-small", "e5-small"]))
            });
        });

        group.bench_with_input(BenchmarkId::new("add_new", count), &count, |b, _| {
            b.iter(|| {
                coord.update_device(make_device("new_dev", "New Device", DeviceTier::LowEnd, true, vec!["e5-small"]))
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_device_election, bench_capability_update);
criterion_main!(benches);
