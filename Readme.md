# XOR C2

## Documentation

- [Documentation Backend](../docs/BACKEND.md)
- [Documentation Agent](../docs/AGENT.md)

## Prérequis

- Rust (1.70+)
- Cargo

## Installation

```bash
# Compiler le client
cd xor-c2-client
cargo build --release

# Compiler le serveur
cd ../c2-xor-server
cargo build --release
```

## Démarrage

### 1. Lancer le serveur

```bash
cd c2-xor-server
cargo run
# Ou avec le binaire
./target/release/xor-c2-server
```

### 2. Lancer le client

```bash
cd xor-c2-client
cargo run
# Ou avec le binaire
./target/release/xor-c2-client
```

### 3. Lancer le serveur avec docker

```bash
docker build -t xor-c2-server .
```

puis lancer le container

```bash
docker run -d \
-p 8088:8088 \
-p 80:80 \
--secret jwt_secret=CECI_EST_UN_SECRET_SEEEEEEECRET \
-v $(pwd)/xor_c2.db:/app/xor_c2.db \
--name c2-server \
xor-c2-server
```

# Disclaimer

This project is for educational purposes only. Use it responsibly and ethically.
