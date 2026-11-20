# wicket agent image: Claude Code plus the tools a coding agent expects, and the in-box forwarder.
# Nothing secret is ever baked in or mounted: the box gets placeholders and routes only.
#
# Build it with `wicket image`: it assembles the build context from this directory plus the
# wicket-fwd crate's source (under wicket-fwd/), which a plain `docker build` of this directory lacks.

# The in-box forwarder (crates/wicket-fwd): std only, so it builds offline. Statically linked, so it
# runs whatever the final image's C library is. It resolves no names, so static glibc's NSS caveat
# doesn't apply.
#
# Base images are pinned by digest (#720): a tag can be pushed again, a digest can't. The tag before
# the digest says which release it is; Docker uses only the digest. Renovate proposes new digests.
FROM rust:1.99.1-slim-bookworm@sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd AS fwd
COPY wicket-fwd /src/wicket-fwd
WORKDIR /src/wicket-fwd
RUN RUSTFLAGS="-C target-feature=+crt-static -C strip=symbols" \
      cargo build --release --target "$(rustc -vV | sed -n 's/^host: //p')" \
 && cp target/*/release/wicket-fwd /wicket-fwd \
 && /wicket-fwd --help >/dev/null

# Node's Active LTS line (#732): 26, LTS from 2026-10-28, maintained to 2029-04-30.
FROM node:26.13.1-bookworm-slim@sha256:5df79989ed685e09f0a98019db4cebfb22fb9df1a53c0161664a011f7ff6b0f1

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates git curl jq ripgrep less procps python3 iproute2 \
 && rm -rf /var/lib/apt/lists/*

# Claude Code, from tarballs checked against the registry's sha512 integrity recorded here, with no
# package's install script run (#721). Its npm package is a wrapper whose postinstall script copies
# the native binary from a per-platform package over a stub. This unpacks the checked wrapper where
# `npm install -g` puts it, puts the checked platform tarball's binary in the stub's place (that
# script's one job), and links `claude` as npm would. npm itself isn't used: a global install fetches
# the platform package from the registry, unchecked, even with --omit=optional. A new version changes
# all three hashes (`npm view @anthropic-ai/claude-code@<v> dist.integrity`, and the same for
# @anthropic-ai/claude-code-linux-x64 and -linux-arm64); the build fails on any mismatch.
ARG CLAUDE_CODE_VERSION=2.1.319
ARG CLAUDE_CODE_SHA512=sha512-XoyAxGXBmNsb9ahz0xLAtyz/I6b1j+4lyLpucyTQIq4FcKUxrMDM2AzA2sHipHoN1DdMJINQQrLZxRZRq7FqBA==
ARG CLAUDE_CODE_LINUX_X64_SHA512=sha512-FO4Sd23BO1VCQPiJe5vG3bNnmV5+YiTau7o1lqK3Fr5VlE4TLdKiyYpwQRwEXO91kE2l12Ep2i7J19T8Md2oOQ==
ARG CLAUDE_CODE_LINUX_ARM64_SHA512=sha512-PlyxaZTAuU0VF3P/ERF4+deMRjT57cr90SHCrYms3HTebr3eItEWJozw6zq9cs88tc8XoF9ESAIghKXfq9HACg==
RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
      amd64) platform=linux-x64; sum=$CLAUDE_CODE_LINUX_X64_SHA512 ;; \
      arm64) platform=linux-arm64; sum=$CLAUDE_CODE_LINUX_ARM64_SHA512 ;; \
      *) echo "no Claude Code build for $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac; \
    dl=$(mktemp -d); \
    fetch() { \
      curl -fsSL --proto '=https' -o "$dl/$1.tgz" \
        "https://registry.npmjs.org/@anthropic-ai/$1/-/$1-${CLAUDE_CODE_VERSION}.tgz"; \
      echo "$(printf '%s' "${2#sha512-}" | base64 -d | od -An -v -tx1 | tr -d ' \n')  $dl/$1.tgz" \
        | sha512sum -c --quiet || { echo "$1-${CLAUDE_CODE_VERSION}.tgz: not the recorded sha512" >&2; exit 1; }; \
    }; \
    fetch claude-code "$CLAUDE_CODE_SHA512"; \
    fetch "claude-code-$platform" "$sum"; \
    pkg=$(npm root -g)/@anthropic-ai/claude-code; \
    mkdir -p "$pkg"; \
    tar -xzf "$dl/claude-code.tgz" -C "$pkg" --strip-components=1 --no-same-owner; \
    tar -xzf "$dl/claude-code-$platform.tgz" -C "$dl" --no-same-owner package/claude; \
    install -m 0755 "$dl/package/claude" "$pkg/bin/claude.exe"; \
    ln -s ../lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe /usr/local/bin/claude; \
    rm -rf "$dl"; \
    claude --version

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
