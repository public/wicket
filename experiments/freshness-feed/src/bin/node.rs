use freshness_feed::feed::Replica;
use freshness_feed::node::{run, Node, NodeCfg};
use freshness_feed::arg;

fn main() -> std::io::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let n = |k: &str, d: &str| arg(&a, k, d).parse::<u64>().expect(k);
    let root_hex = std::fs::read_to_string(arg(&a, "--root", "cp-state/root.pub"))?;
    let root: [u8; 32] = hex::decode(root_hex.trim()).ok().and_then(|b| b.try_into().ok()).expect("root.pub");
    let root = ed25519_dalek::VerifyingKey::from_bytes(&root).expect("root key");
    let node = Node::new(Replica::new(&arg(&a, "--node", "n1"), root));
    run(node, NodeCfg {
        cp: arg(&a, "--cp", "127.0.0.1:47100").parse().expect("--cp"),
        query_port: n("--query-port", "47200") as u16,
        push: arg(&a, "--push", "on") == "on",
        poll_ms: n("--poll-ms", "1000"),
        retry_ms: n("--retry-ms", "200"),
        idle_ms: n("--idle-ms", "15000"),
    })
}
