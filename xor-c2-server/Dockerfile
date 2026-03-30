# Stage 1: Build
FROM rust:1.83-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./

RUN mkdir src && echo "fn main() {}" > src/main.rs

RUN cargo build --release && rm -rf src

COPY src ./src

RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libcap2-bin \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN groupadd -r xor-c2 && useradd -r -g xor-c2 xor-c2

COPY --from=builder --chown=xor-c2:xor-c2 /app/target/release/xor-c2-server .

RUN setcap 'cap_net_bind_service=+ep' /app/xor-c2-server

RUN mkdir -p config && chown -R xor-c2:xor-c2 /app
COPY --chown=xor-c2:xor-c2 config/config.json ./config/

ENV JWT_EXP_HOURS=24

USER xor-c2

EXPOSE 8088 80 443 8443

CMD ["./xor-c2-server"]
