# Volchock C2 Client

Client graphique pour Volchock C2.

## Documentation

- [Documentation Backend](../docs/BACKEND.md)
- [Documentation Agent](../docs/AGENT.md)

## Prérequis

- Rust (1.70+)
- Cargo

## Installation

```bash
# Compiler le client
cd volchock-c2-client
cargo build --release

# Compiler le serveur
cd ../c2-volchock
cargo build --release
```

## Démarrage

### 1. Lancer le serveur

```bash
cd c2-volchock
cargo run
# Ou avec le binaire
./target/release/c2-volchock
```

### 2. Lancer le client

```bash
cd volchock-c2-client
cargo run
# Ou avec le binaire
./target/release/volchock-c2-client
```
