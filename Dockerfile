# syntax=docker/dockerfile:1

FROM rust:1.89-slim-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo
COPY crates ./crates

RUN cargo build --release --locked -p relay-server

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /app/target/release/relay-server /usr/local/bin/relay-server

ENV BIND_ADDR=0.0.0.0
ENV PORT=8080
ENV ALLOWED_ORIGIN=https://geistr.pages.dev
ENV ALLOW_LOCALHOST_DEV=false
ENV INVITE_TTL_SECS=300
ENV KEEPALIVE_INTERVAL_SECS=20
ENV KEEPALIVE_TIMEOUT_SECS=15
ENV MAX_CONCURRENT_ROOMS=256
ENV MAX_CONNECTIONS_PER_IP=16
ENV MAX_CONNECT_RATE_PER_IP_PER_MIN=60
ENV MAX_FRAME_BYTES=32768
ENV MAX_OUTBOUND_QUEUE=64
ENV MAX_OUTBOUND_BYTES_PER_MIN=1048576

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/relay-server"]
