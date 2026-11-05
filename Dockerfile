# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder
WORKDIR /app

# Build dependency graph first for better layer caching.
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
RUN cargo build --release --locked

FROM debian:bookworm-slim AS runtime
WORKDIR /app

# ffmpeg is required at runtime; ca-certificates are useful for TSA/trust URL fetches.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/c2pa-live /usr/local/bin/c2pa-live

COPY src/client ./src/client
COPY settings.toml ./settings.toml

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/c2pa-live"]
