#!/bin/sh
# Code lines (not blank, not comment-only) per piece of each design's trusted path. Run from this directory.
code() { grep -v -E '^\s*(//.*)?$' "$@" | wc -l; }
section() { awk -v a="$2" -v b="$3" 'index($0,a){on=1} b!="" && index($0,b){on=0} on' "$1" | grep -v -E '^\s*(//.*)?$' | wc -l; }
fn_body() { awk -v a="$2" 'index($0,a){on=1} on{print} on && /^}/{exit}' "$1" | grep -v -E '^\s*(//.*)?$' | wc -l; }
echo "design A"
echo "  generator: bisc.rs compile + grant_code + helpers: $(section src/bisc.rs 'fn q(' 'pub struct Keys')"
echo "  gate: lint.rs: $(code src/lint.rs)"
echo "  fork, prepared.rs (steps 1-2): $(code ../biscuit-fast/vendor/biscuit-auth/src/token/authorizer/prepared.rs)"
echo "  fork, compiled.rs (step 3): $(code ../biscuit-fast/vendor/biscuit-auth/src/datalog/compiled.rs)"
echo "  fork, edits to upstream files: 199 added lines (biscuit-fast logs/fork.diff)"
echo "  upstream biscuit-auth src (Datalog engine, parser, format, crypto): $(find ../biscuit-fast/vendor/biscuit-auth/src -name '*.rs' -not -path '*/compiled.rs' -not -path '*/prepared.rs' | xargs cat | grep -v -E '^\s*(//.*)?$' | wc -l)"
echo "design B"
echo "  generator: zf.rs generator section: $(section src/zf.rs '// ===== generator' '// ===== extractor')"
echo "  gate: zf.rs extractor section (shape, caps, canonical JSON, compile): $(section src/zf.rs '// ===== extractor' '// ===== evaluator')"
echo "  evaluator: zf.rs evaluator section (intersection, grants, liveness): $(section src/zf.rs '// ===== evaluator' '')"
echo "  fork patch needed: Biscuit::block_datalog + BlockDatalog: $(section ../biscuit-fast/vendor/biscuit-auth/src/token/mod.rs 'pub fn block_datalog' 'gets the datalog version') + $(section ../biscuit-fast/vendor/biscuit-auth/src/token/mod.rs 'pub struct BlockDatalog' 'pub use third_party') lines"
echo "  wicket-core reused: CompiledZone (op.rs) $(section ../../crates/wicket-core/src/op.rs 'pub struct CompiledZone' 'pub fn evaluate(zone') lines, plus manifest.rs host_matches/compile_glob $(section ../../crates/wicket-core/src/manifest.rs 'pub(crate) fn compile_glob' '#[cfg(test)]') lines"
echo "  second line (optional): plain.rs narrows: $(fn_body src/plain.rs 'pub fn narrows')"
echo "design C: A's pieces plus B's generator and extractor (and B's evaluator for the cross-check)"
