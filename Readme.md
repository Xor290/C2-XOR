# XOR C2

**An educational C2 (Command & Control) framework written in Rust (server) and C++ (Windows agent).**

This project demonstrates the core principles of a modern C2 framework with support for advanced anti-detection and obfuscation techniques.

## Prerequisites

- Rust (1.70+)
- Cargo

## Installation

```bash
# Build the client
cd xor-c2-client
cargo build --release

# Build the server
cd ../c2-xor-server
cargo build --release
```

## Getting Started

### 1. Start the server

```bash
cd c2-xor-server
cargo run
# Or with the binary
./target/release/xor-c2-server
```

### 2. Start the client

```bash
cd xor-c2-client
cargo run
# Or with the binary
./target/release/xor-c2-client
```

### 3. Start the server with Docker

```bash
docker build -t xor-c2-server .
```

Then run the container:

```bash
docker run -d \
-p 8088:8088 \
-p 80:80 \
--secret jwt_secret=THIS_IS_A_SECRET_SEEEEEEECRET \
-v $(pwd)/xor_c2.db:/app/xor_c2.db \
--name c2-server \
xor-c2-server
```

# Disclaimer

This project is for educational purposes only. Use it responsibly and ethically.
