# The workload image for wicket working on its own source: the PoC agent image plus a Rust toolchain.
# This is the project's configuration, not part of wicket. Any project describes its own image.
# `wicket image --dir` sets BASE to the installation's own agent image (wicket/claude-code:<build id>
# on an installed version); a plain `docker build` gets the PoC tag.
ARG BASE=wicket/claude-code:poc
FROM ${BASE}

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential pkg-config \
 && rm -rf /var/lib/apt/lists/*

ARG RUST_VERSION=1.99.1
ENV RUSTUP_HOME=/opt/rustup PATH=/opt/cargo/bin:$PATH
RUN curl -sSf https://sh.rustup.rs | CARGO_HOME=/opt/cargo sh -s -- -y --no-modify-path \
      --profile minimal --default-toolchain "${RUST_VERSION}" --component rustfmt,clippy \
 && chmod -R a+rX /opt/rustup /opt/cargo \
 && rustc --version
