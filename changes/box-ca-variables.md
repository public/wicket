---
area: Boxes and the egress path
type: Changed
---
- A box's start also points `PIP_CERT`, `AWS_CA_BUNDLE`, `CARGO_HTTP_CAINFO`, `DENO_CERT`,
  `CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE` and `NIX_SSL_CERT_FILE` at the run's CA bundle, and sets a
  JVM's proxy properties in `JAVA_TOOL_OPTIONS` (after any the manifest's env sets), so those tools
  work through the egress proxy without manifest settings. Needs the rebuilt image
  ([#366](https://github.com/public/wicket/issues/366)).
