//! examples/services/npm-cache (#579 step 3): `wicket service add` snapshots it whole, its
//! program's files with it. The example's own settings and decisions are checked in wicket-core's
//! examples test (`tests/integration/npm_cache_example.rs`); this is the part only the control host
//! does.

#[test]
fn the_npm_cache_example_snapshots_with_its_files() {
    let path = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/services/npm-cache/manifest.yaml"));
    let root = std::env::temp_dir().join(format!("wicket-svc-example-{}", std::process::id()));
    let snap = wicket_control::services::snapshot(path, &root).unwrap();
    for f in ["config.yaml", "package.json", "package-lock.json", "start.sh"] {
        assert!(snap.path.parent().unwrap().join("source").join(f).is_file(), "{f} in the snapshot");
    }
    let _ = std::fs::remove_dir_all(&root);
}
