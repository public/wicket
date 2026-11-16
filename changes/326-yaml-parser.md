---
area: Manifests
type: Security
---
- wicket reads YAML (manifests, policies, operator files) with serde-saphyr, a parser in safe Rust,
  in place of serde_yaml, whose unsafe-libyaml is unmaintained (RUSTSEC-2024-0449). The parser
  refuses input that is too large or too costly to read: more than 4 MiB, more than one document,
  nesting deeper than 64, or more than 1000 anchors or aliases (so an alias bomb fails fast). A
  duplicate key is an error. Parse errors give the line and column with the offending source line.
  An empty key for a list or map (`reach:` with nothing under it) still reads as empty
  ([#326](https://github.com/public/wicket/issues/326)).
