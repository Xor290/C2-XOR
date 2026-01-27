# Stage 1: Build
FROM rust:1.83-bookworm AS builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies only (cached layer)
RUN cargo build --release && rm -rf src

# Copy actual source code
COPY src ./src

# Build the application
RUN touch src/main.rs && cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create non-root user
RUN groupadd -r xor-c2 && useradd -r -g xor-c2 xor-c2

# Copy binary with correct ownership
COPY --from=builder --chown=xor-c2:xor-c2 /app/target/release/xor-c2-server .

# Set capabilities for binding to privileged ports
RUN setcap 'cap_net_bind_service=+ep' /app/xor-c2-server

# Create config directory
RUN mkdir -p config && chown -R xor-c2:xor-c2 /app
COPY --chown=xor-c2:xor-c2 config/config.json ./config/

# Set environment variables
ENV JWT_EXP_HOURS=24

# Set user to non-root
USER xor-c2

# Expose ports (Admin API + default listener)
EXPOSE 8088 80 443

# Run the server
CMD ["./xor-c2-server"]
