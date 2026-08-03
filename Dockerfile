# Production/benchmark image for scandiaca (plain HTTP client API on 8008).
#
# Multi-stage: build the release binary with the Rust toolchain, then run it on a
# slim Debian base. Unlike Dockerfile.complement there is no TLS/federation
# listener or entrypoint script — the benchmark harness only drives the
# Client-Server API over HTTP on 8008.

# icu (via reqwest) needs rustc ≥ 1.86, so build with a newer toolchain than the
# crate's own rust-version floor (1.85).
FROM rust:1.88-slim AS builder
RUN apt-get update && apt-get install -y pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/
COPY tests/ ./tests/
RUN cargo build --release --bin scandiaca

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y curl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /build/target/release/scandiaca /usr/local/bin/scandiaca

EXPOSE 8008
ENV PORT=8008
ENV STORAGE=memory
ENV DISABLE_RATE_LIMIT=1
HEALTHCHECK --interval=1s --timeout=5s --start-period=10s \
    CMD curl -sf http://localhost:8008/_matrix/client/versions || exit 1

CMD ["scandiaca"]
