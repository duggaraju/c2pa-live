# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder
WORKDIR /app

# Build dependency graph first for better layer caching.
COPY Cargo.toml ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim AS runtime
WORKDIR /app

# ffmpeg is required at runtime; ca-certificates are useful for TSA/trust URL fetches.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/c2pa-live /usr/local/bin/c2pa-live

# Default optional settings file path used by the app when present.
RUN printf '%s\n' \
    '[verify]' \
    'verify_after_sign = true' \
    'verify_after_sign_hash = true' \
    'verify_trust = true' \
    > /app/setting.toml

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/c2pa-live"]
