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

# Disclaimer

This project is for educational purposes only. Use it responsibly and ethically.
