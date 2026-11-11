//! What one egress decision costs (#74). `compiled` is the request path (a `CompiledZone` built once
//! per run); `uncompiled` is `evaluate(&ZoneSpec, …)`, which compiles the zone first.
//!
//!   cargo bench -p wicket-core --bench evaluate

use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use wicket_core::{evaluate, CompiledZone, Manifest, Op, RunId, TenantId, ZoneSpec};

fn zone(file: &str) -> ZoneSpec {
    let path = format!("{}/../../examples/{file}", env!("CARGO_MANIFEST_DIR"));
    Manifest::from_yaml(&std::fs::read_to_string(path).unwrap()).unwrap().zone
}

fn bench(c: &mut Criterion) {
    let (t, r) = (TenantId::single(), RunId("run_bench".into()));
    let cases = [
        ("allowed read", zone("self-hosting/manifest.yaml"), "GET", "api.github.com", "/repos/public/wicket/issues/12"),
        ("outside reach", zone("self-hosting/manifest.yaml"), "GET", "example.com", "/"),
        ("forbid hit", zone("remote-control/manifest.yaml"), "GET", "api.anthropic.com", "/v1/mcp_servers"),
    ];
    for (name, z, m, h, p) in cases {
        let op = Op::egress(&t, &r, &z.name, m, h, p);
        let compiled = CompiledZone::new(z.clone()).unwrap();
        c.bench_function(&format!("{name}/compiled"), |b| b.iter(|| black_box(compiled.evaluate(black_box(&op)))));
        c.bench_function(&format!("{name}/uncompiled"), |b| b.iter(|| black_box(evaluate(black_box(&z), black_box(&op)))));
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
