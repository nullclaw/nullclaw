# syntax=docker/dockerfile:1

# ── Stage 1: Build ────────────────────────────────────────────
# Build natively on the runner architecture and cross-compile per TARGETARCH.
FROM --platform=$BUILDPLATFORM alpine:3.23 AS builder

ARG ZIG_VERSION=0.16.0

RUN apk add --no-cache bash curl git musl-dev python3

WORKDIR /app
COPY .github/scripts/install-zig.sh .github/scripts/install-zig.sh
COPY build.zig build.zig.zon ./
COPY src/ src/
COPY vendor/sqlite3/ vendor/sqlite3/

RUN set -eu; \
    mkdir -p /tmp/zig-path; \
    GITHUB_PATH=/tmp/zig-path/path RUNNER_TEMP=/opt bash .github/scripts/install-zig.sh "${ZIG_VERSION}"; \
    ln -sf "$(cat /tmp/zig-path/path)/zig" /usr/local/bin/zig; \
    test "$(zig version)" = "0.16.0"

ARG TARGETARCH
ARG VERSION=dev
RUN --mount=type=cache,target=/root/.cache/zig \
    --mount=type=cache,target=/app/.zig-cache \
    set -eu; \
    arch="${TARGETARCH:-}"; \
    if [ -z "${arch}" ]; then \
      case "$(uname -m)" in \
        x86_64) arch="amd64" ;; \
        aarch64|arm64) arch="arm64" ;; \
        *) echo "Unsupported host arch: $(uname -m)" >&2; exit 1 ;; \
      esac; \
    fi; \
    case "${arch}" in \
      amd64) zig_target="x86_64-linux-musl" ;; \
      arm64) zig_target="aarch64-linux-musl" ;; \
      *) echo "Unsupported TARGETARCH: ${arch}" >&2; exit 1 ;; \
    esac; \
    zig build -Dtarget="${zig_target}" -Doptimize=ReleaseSmall -Dversion="${VERSION}"

# ── Stage 2: Config Prep ─────────────────────────────────────
FROM busybox:1.38 AS config

# Keep config.json at the volume root so existing compose volumes remain readable.
RUN mkdir -p /nullclaw-data/workspace

RUN cat > /nullclaw-data/config.json << 'EOF'
{
  "agents": {
    "defaults": {
      "model": {
        "primary": "openrouter/anthropic/claude-sonnet-4"
      }
    }
  },
  "models": {
    "providers": {
      "openrouter": {}
    }
  },
  "gateway": {
    "port": 3000,
    "host": "::",
    "allow_public_bind": true
  }
}
EOF

# Default runtime runs as non-root (uid/gid 65534).
# Keep writable ownership for HOME/workspace in safe mode.
RUN chown -R 65534:65534 /nullclaw-data

# ── Stage 3: Runtime Base (shared) ────────────────────────────
FROM alpine:3.23 AS release-base

LABEL org.opencontainers.image.source=https://github.com/nullclaw/nullclaw

RUN apk add --no-cache ca-certificates curl git tzdata

COPY --from=builder /app/zig-out/bin/nullclaw /usr/local/bin/nullclaw
COPY --from=config /nullclaw-data /nullclaw-data

ENV NULLCLAW_WORKSPACE=/nullclaw-data/workspace
ENV NULLCLAW_HOME=/nullclaw-data
ENV HOME=/nullclaw-data
ENV SHELL=/bin/sh
ENV NULLCLAW_GATEWAY_PORT=3000

WORKDIR /nullclaw-data
EXPOSE 3000
ENTRYPOINT ["nullclaw"]
CMD ["gateway", "--port", "3000", "--host", "::"]

# Optional autonomous mode (explicit opt-in):
#   make build DOCKER_TARGET=release-root IMAGE=nullclaw:root
FROM release-base AS release-root
USER 0:0

# Safe default image (used when no --target is provided)
FROM release-base AS release
USER 65534:65534
