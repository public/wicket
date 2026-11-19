# wicket agent image: Claude Code plus the tools a coding agent expects, and the in-box forwarder.
# Nothing secret is ever baked in or mounted: the box gets placeholders and routes only.
#
# Build it with `wicket image`: it assembles the build context from this directory plus the
# wicket-fwd crate's source (under wicket-fwd/), which a plain `docker build` of this directory lacks.

# The in-box forwarder (crates/wicket-fwd): std only, so it builds offline. Statically linked, so it
# runs whatever the final image's C library is. It resolves no names, so static glibc's NSS caveat
# doesn't apply.
FROM rust:1.99.1-slim-bookworm AS fwd
COPY wicket-fwd /src/wicket-fwd
WORKDIR /src/wicket-fwd
RUN RUSTFLAGS="-C target-feature=+crt-static -C strip=symbols" \
      cargo build --release --target "$(rustc -vV | sed -n 's/^host: //p')" \
 && cp target/*/release/wicket-fwd /wicket-fwd \
 && /wicket-fwd --help >/dev/null

FROM node:22-bookworm-slim

ARG CLAUDE_CODE_VERSION=2.1.319

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates git curl jq ripgrep less procps python3 iproute2 \
 && rm -rf /var/lib/apt/lists/*

RUN npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
 && npm cache clean --force \
 && claude --version

COPY --from=fwd /wicket-fwd /usr/local/bin/wicket-fwd
COPY wicket-entry /usr/local/bin/wicket-entry
RUN chmod 0755 /usr/local/bin/wicket-entry /usr/local/bin/wicket-fwd

# Git inside the box never runs repository hooks.
RUN git config --system core.hooksPath /dev/null \
 && git config --system advice.detachedHead false

WORKDIR /workspace

# No entrypoint of node's: its docker-entrypoint.sh is a shell, and a fork for `$(command -v …)`,
# before every box's own entry, about 10-25 ms of each start under gVisor (#287). wicket always
# starts a box with a command (`wicket-entry …`), which that script would only have exec'd. Without
# one, the box still runs node, as `docker-entrypoint.sh node` did. ENTRYPOINT resets CMD, so this
# order.
ENTRYPOINT []
CMD ["node"]
