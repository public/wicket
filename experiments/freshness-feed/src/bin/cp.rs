use freshness_feed::{arg, cp};

fn main() -> std::io::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let n = |k: &str, d: &str| arg(&a, k, d).parse::<i64>().expect(k);
    cp::run(cp::CpCfg {
        dir: arg(&a, "--dir", "cp-state").into(),
        feed: arg(&a, "--feed", "n1"),
        feed_port: n("--feed-port", "47100") as u16,
        admin_port: n("--admin-port", "47101") as u16,
        ttl_ms: n("--ttl-ms", "30000"),
        refresh_ms: n("--refresh-ms", "5000") as u64,
        grace_ms: n("--grace-ms", "120000"),
        retain: n("--retain", "1000") as u64,
    })
}
