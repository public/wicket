//! examples/services/npm-cache (#579 step 3, #664): a per-tenant pull-through cache whose zone
//! reaches the public registry read-only, and decides npm's scoped-package spelling
//! (`/@scope%2fname`) as `/@scope/name` because its rule asks for it (`decode_slash: [1]`), not
//! because core knows npm.

use wicket_core::service::Tenancy;
use wicket_core::{canonical_path_decoding, CompiledZone, Manifest, Op, RunId, TenantId, Verdict};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/services/npm-cache");

fn manifest() -> Manifest {
    Manifest::from_yaml(include_str!("../../../../examples/services/npm-cache/manifest.yaml")).expect("the example parses")
}

#[test]
fn the_npm_cache_example_is_a_per_tenant_read_only_service() {
    let m = manifest();
    let s = m.service.as_ref().expect("a service");
    assert_eq!((s.port, s.tenancy, s.public_only), (4873, Tenancy::PerTenant, false));
    assert_eq!(s.user_env("npm-cache")["npm_config_registry"], "http://npm-cache.wicket.internal:4873/");
    assert!(m.zone.reach.iter().all(|r| r.host == "registry.npmjs.org" && r.methods.iter().all(|x| x == "GET" || x == "HEAD")));
    // What `wicket service add` snapshots with it.
    for f in ["config.yaml", "package.json", "package-lock.json", "start.sh"] {
        assert!(std::path::Path::new(DIR).join(f).is_file(), "{f} beside the manifest");
    }
}

/// Its zone decides `/@scope%2fname` as `/@scope/name` on the registry, and only there: the rule
/// asks for the first segment; any other encoded slash is refused.
#[test]
fn the_npm_cache_zone_decides_scoped_packages_decoded() {
    let m = manifest();
    let segs = m.zone.decode_slash_for("registry.npmjs.org");
    assert_eq!(segs, [1]);
    assert!(m.zone.decode_slash_for("example.com").is_empty());
    let z = CompiledZone::new(m.zone).unwrap();
    let decide = |raw: &str| {
        let path = canonical_path_decoding(raw, &segs).ok()?;
        Some(z.evaluate(&Op::egress(&TenantId::single(), &RunId("run_x".into()), "npm-cache", "GET", "registry.npmjs.org", &path)))
    };
    for p in ["/@types%2fnode", "/@types%2Fnode", "/@babel%2fcore/7.0.0", "/left-pad", "/@types/node"] {
        assert!(matches!(decide(p), Some(Verdict::AllowByReach(0))), "{p}: {:?}", decide(p));
    }
    for p in ["/-/package/@scope%2fname/dist-tags", "/@scope%2fname%2fmore", "/@scope%252fname", "/@scope%2f.."] {
        assert!(decide(p).is_none(), "{p}: refused");
    }
}
