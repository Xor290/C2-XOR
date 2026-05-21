# AWS Infrastructure — XOR-C2

## Overview

```mermaid
graph TD
    OP([Operator])
    AG([Agent / Target])

    subgraph AWS
        APIGW["API Gateway\nlambda-ec2-proxy-api\nstage: prod\nANY /{proxy+}"]
        LMB["Lambda\nlambda-ec2-proxy-proxy\nPython 3.12 · 15s timeout"]
        subgraph EC2["EC2 t2.medium · Ubuntu 24.04 · Docker"]
            ADMIN["Admin API\n:8088"]
            HTTP["HTTP Listener\n:80"]
            HTTPS["HTTPS Listener\n:443"]
            DB[(SQLite\nxor_c2.db)]
        end
    end

    OP -->|"HTTPS :8088 (direct)\nor HTTPS via APIGW"| ADMIN
    OP -->|SSH :22| EC2
    AG -->|"HTTPS → APIGW → Lambda → :80"| HTTP
    AG -->|"HTTPS :443"| HTTPS
    APIGW -->|"AWS_PROXY POST"| LMB
    LMB -->|"HTTP :80"| HTTP
    ADMIN --- DB
    HTTP --- DB
    HTTPS --- DB
```

---

## AWS Components

### EC2

| Attribute | Value |
|---|---|
| Type | `t2.medium` |
| AMI | Ubuntu 24.04 LTS (`ami-0e86e20dae9224db8`, us-east-1) |
| Region | `us-east-1` |
| Network | Default VPC, assigned public IP |
| Key pair | `redteam` |
| Name | `lambda-ec2-proxy-backend` |

The C2 server runs inside a Docker container exposing ports 80, 443, 8088, and 8443.

### API Gateway

| Attribute | Value |
|---|---|
| Name | `lambda-ec2-proxy-api` |
| Stage | `prod` |
| Resource | `/{proxy+}` — catch-all |
| Methods | `ANY` (all HTTP verbs) |
| Integration | `AWS_PROXY` → Lambda |
| Authentication | None (public) |
| URL | `https://{api_id}.execute-api.us-east-1.amazonaws.com/prod/` |

### Lambda

| Attribute | Value |
|---|---|
| Name | `lambda-ec2-proxy-proxy` |
| Runtime | Python 3.12 |
| Timeout | 15 s (10 s for internal HTTP requests) |
| IAM Role | `LabRole` (pre-existing) |
| Env variable | `EC2_URL = http://{EC2_PUBLIC_IP}:80` |

---

## IAM & Permissions

```mermaid
graph LR
    APIGW["apigateway.amazonaws.com"]
    LMB["Lambda\nlambda-ec2-proxy-proxy"]
    LABROLE["IAM Role\nLabRole"]

    APIGW -->|"lambda:InvokeFunction\nsource: execute-api:{id}/*/*"| LMB
    LABROLE -->|"assume role"| LMB
```

| Principal | Action | Resource |
|---|---|---|
| `apigateway.amazonaws.com` | `lambda:InvokeFunction` | `function:lambda-ec2-proxy-proxy` |
| `LabRole` | Learner Lab permissions (EC2, Lambda, APIGW) | — |

Only the API Gateway is explicitly allowed to invoke the Lambda. No other resource holds invocation rights.

---

## Network & Security Group

### Network topology

```mermaid
graph TD
    INET(["Internet\n0.0.0.0/0"])

    subgraph VPC["Default VPC · 172.31.0.0/16"]
        subgraph SG["SG: lambda-ec2-proxy-sg-ec2"]
            EC2["EC2\nPublic IP"]
        end
    end

    INET -->|":22 TCP — SSH\nsrc: ssh_allowed_cidr"| SG
    INET -->|":80 TCP — HTTP"| SG
    INET -->|":443 TCP — HTTPS"| SG
    INET -->|":8088 TCP — Admin API"| SG
    SG -->|"all outbound\n0.0.0.0/0"| INET
```

### Inbound rules

| Port | Proto | Source | Purpose |
|---|---|---|---|
| 22 | TCP | `var.ssh_allowed_cidr` (default `0.0.0.0/0`) | Operator SSH |
| 80 | TCP | `0.0.0.0/0` | Agent HTTP listener + Lambda relay |
| 443 | TCP | `0.0.0.0/0` | Agent HTTPS listener |
| 8088 | TCP | `0.0.0.0/0` | Operator Admin API |

### Outbound rules

| Port | Proto | Destination |
|---|---|---|
| All | All | `0.0.0.0/0` |

---

## Agent ↔ C2 Traffic Flow

### Full beacon cycle

```mermaid
sequenceDiagram
    participant A as Agent (target)
    participant GW as API Gateway
    participant L as Lambda
    participant C2 as EC2 :80
    participant DB as SQLite

    loop Every N seconds (± jitter)
        A->>GW: POST /api/update<br/>XOR+B64({agent_id, hostname, ip, user, process})
        GW->>L: AWS_PROXY forward
        L->>C2: HTTP POST /api/update
        C2->>DB: Upsert agent record
        C2-->>L: 200 OK
        L-->>GW: 200 OK
        GW-->>A: 200 OK

        A->>GW: POST /api/command<br/>XOR+B64({agent_id})
        GW->>L: AWS_PROXY forward
        L->>C2: HTTP POST /api/command
        C2->>DB: SELECT pending commands
        C2-->>L: XOR+B64({commands:[...]})
        L-->>GW: response
        GW-->>A: XOR+B64({commands:[...]})

        Note over A: Local command execution

        A->>GW: POST /api/result<br/>XOR+B64({agent_id, command_id, output, success, types})
        GW->>L: AWS_PROXY forward
        L->>C2: HTTP POST /api/result
        C2->>DB: INSERT result
        C2-->>A: 200 OK
    end
```

### In-memory binary execution (PE-Exec)

```mermaid
sequenceDiagram
    participant OP as Operator
    participant C2 as EC2 Admin :8088
    participant DB as SQLite
    participant A as Agent
    participant MEM as Agent memory

    OP->>C2: POST /api/task {type: pe-exec, binary: ...}
    C2->>DB: INSERT PE command
    C2-->>OP: {command_id}

    A->>C2: GET /api/pe-data/{command_id}
    C2->>DB: SELECT binary
    C2-->>A: octet-stream (raw PE)
    A->>MEM: Reflective loading (loader.rs)<br/>NtAllocateVirtualMemory → copy sections<br/>→ fix imports → relocations → NtCreateThreadEx
```

### Channel encryption

```mermaid
graph LR
    subgraph Send
        D1["plaintext"] -->|"XOR key[i % len]"| X1["XOR data"] -->|Base64| W["wire payload"]
    end
    subgraph Receive
        W2["wire payload"] -->|Base64 decode| X2["XOR data"] -->|"XOR key[i % len]"| D2["plaintext"]
    end
```

The XOR key is injected at agent compile time and must match the key configured on the C2 listener side.

---

## C2 Server Ports (EC2)

| Port | Service | Consumers |
|---|---|---|
| 8088 | Admin REST API (login, generate, task, results, victims) | Operator |
| 80 | HTTP agent listener | Agents via Lambda relay or direct |
| 443 | HTTPS agent listener | Agents (direct) |
| 8443 | Alternate HTTPS listener | Agents (direct) |

---

## Terraform Outputs

| Output | Description |
|---|---|
| `api_gateway_url` | Public entry point URL for agents |
| `ec2_public_ip` | EC2 public IP (SSH + direct admin) |
| `ec2_private_ip` | EC2 private IP |
| `lambda_function_name` | Lambda proxy function name |
