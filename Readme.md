# XOR C2

**Un framework C2 (Command & Control) éducatif écrit en Rust (serveur) et C++ (agent Windows).**

Ce projet démontre les principes fondamentaux d'un C2 moderne avec support de techniques avancées d'anti-détection et d'obfuscation.

## Documentation

- [📘 Documentation Backend](../docs/BACKEND.md) - Serveur, API, listeners, génération d'agents
- [📗 Documentation Agent](../docs/AGENT.md) - Agent Windows, commandes, configuration, anti-détection

### Nouveautés - Fonctionnalités Anti-Détection ⭐

**Depuis les dernières mises à jour, XOR C2 supporte :**

1. **Anti-Debug** (`anti_debug` parameter)
   - Détection de débogage via `IsDebuggerPresent()`
   - Vérification du PEB (Process Environment Block)
   - Termination silencieuse si debugger détecté
   - [📖 Documentation complète →](docs/AGENT.md#anti-détection-avancée)

2. **Sleep Obfuscation** (`sleep_obfuscation` + `jitter_percent`)
   - Remplace `Sleep()` classique par thread pools Windows
   - Ajoute une variation aléatoire (jitter) au beacon interval
   - Chiffrement mémoire optional pendant le sleep (XOR 256-bit)
   - Évite les breakpoints et signatures trafic
   - [📖 Documentation complète →](docs/AGENT.md#sleep-obfuscation-obfuscation-du-beacon)

### Exemple d'agent avec protections complètes

```json
{
  "listener_name": "http_protected",
  "payload_type": "exe",
  "config": {
    "host": "c2.example.com",
    "port": 80,
    "uri_path": "/api/beacon",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "xor_key": "secure_encryption_key_here",
    "beacon_interval": 300,
    "anti_vm": true,
    "anti_debug": true,
    "sleep_obfuscation": true,
    "jitter_percent": 0.15,
    "headers": [["Accept", "application/json"]]
  }
}
```

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
