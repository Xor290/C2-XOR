# XOR C2 Packer — Documentation technique

## Vue d'ensemble

Le packer est un outil Rust composé de deux parties distinctes :

- **`packer-cli`** : l'outil de packing (côté builder), qui prend un PE en entrée et produit un binaire protégé.
- **`stub`** : le loader embarqué (pré-compilé séparément), qui sera exécuté au moment du lancement et qui reconstruit le PE original en mémoire.

---

## Pipeline de packing

```mermaid
flowchart TD
    A[agent.exe\nPE original] --> B[pe_parser\nValidation MZ + PE sig]
    B --> C[compress\nLZ4 compression]
    C --> D{Algorithme\nde chiffrement}
    D -->|--encryption aes| E[encrypt_aes256gcm\nAES-256-GCM\nclé 32B + nonce 12B aléatoires]
    D -->|--encryption xor| F[encrypt_xor\nXOR 32B key aléatoire]
    E --> G[stub_builder]
    F --> G
    L{--loader} -->|nt_section 0| G
    L -->|nt_virtual_memory 1| G
    L -->|classic 2| G
    G --> H[stub.exe\npré-compilé]
    G --> I[packed.exe\nbinaire final]

    style A fill:#2d2d2d,color:#fff
    style I fill:#1a472a,color:#fff
    style H fill:#1a3a5c,color:#fff
```

---

## Structure du binaire final

Le binaire produit est une concaténation de trois blocs :

```mermaid
block-beta
    columns 1
    block:exe["packed.exe"]:1
        A["stub.exe\n(PE Windows exécutable)"]
        B["Header XORPACK\n(106 octets, little-endian)"]
        C["Payload chiffré\n(PE compressé + chiffré)"]
    end
```

### Détail du header (106 octets)

```mermaid
packet-beta
    0-7: "magic[8]\n= XORPACK\\0"
    8-11: "version\nu32 LE"
    12-12: "enc_mode\nu8"
    13-13: "loader_mode\nu8 (0/1/2)"
    14-21: "original_size\nu64 LE"
    22-29: "payload_size\nu64 LE"
    30-61: "key[32]\n(AES ou XOR)"
    62-73: "nonce[12]\n(AES-GCM)"
    74-105: "checksum[32]\nSHA-256 payload"
    106-137: "header_checksum[32]\nSHA-256 des 74 octets"
```

> Le magic `XORPACK\x00` permet au stub de localiser l'overlay en fin de fichier.

---

## Algorithmes de chiffrement

### AES-256-GCM (défaut)

```mermaid
flowchart LR
    A[données compressées] --> C[AES-256-GCM]
    B1[clé 32B\nCSPRNG] --> C
    B2[nonce 12B\nCSPRNG] --> C
    C --> D[ciphertext + auth tag 16B]
```

- Clé et nonce générés aléatoirement via `rand::thread_rng()`
- Le tag d'authentification GCM est inclus dans le ciphertext
- Fournit confidentialité **et** intégrité

### XOR (mode alternatif)

```mermaid
flowchart LR
    A[données compressées] --> C[XOR cyclique]
    B[clé 32B\nCSPRNG] --> C
    C --> D[ciphertext]
```

- XOR cyclique sur 32 octets : `byte[i] ^ key[i % 32]`
- Nonce = `[0u8; 12]` (non utilisé)
- Moins robuste, présent comme alternative légère

---

## Intégrité et vérifications

```mermaid
flowchart TD
    A[payload chiffré] -->|SHA-256| B[checksum\nstocké dans header]
    C[74 premiers octets\ndu header] -->|SHA-256| D[header_checksum\nstocké après le header]

    style B fill:#4a3728,color:#fff
    style D fill:#4a3728,color:#fff
```

Deux niveaux de vérification SHA-256 :
1. **`checksum`** : intégrité du payload chiffré
2. **`header_checksum`** : intégrité du header lui-même (anti-tamper)

---

## Le Loader (stub) — fonctionnement détaillé

Le stub est un PE Windows autonome (`#![windows_subsystem = "windows"]`) compilé séparément. Il joue le rôle de loader réflectif : il reconstruit et exécute le PE original entièrement en mémoire, sans jamais le poser sur disque.

### Vue d'ensemble du stub

```mermaid
flowchart TD
    A([Exécution stub.exe]) --> B[anti_debug\nVérification debugger]
    B -->|debugger détecté| Z([exit 1])
    B -->|OK| C[overlay\nGetModuleFileNameW\nLecture du fichier sur disque]
    C --> D[overlay\nRecherche magic XORPACK\0]
    D -->|non trouvé| Z
    D -->|trouvé| E[overlay\nParsing header 106 octets]
    E --> F[checksum\nVérif header_checksum SHA-256]
    F -->|invalide| Z
    F -->|OK| G[checksum\nVérif payload checksum SHA-256]
    G -->|invalide| Z
    G -->|OK| H[decrypt\nDéchiffrement AES-256-GCM ou XOR]
    H -->|échec| Z
    H -->|OK| I[decompress\nDécompression LZ4]
    I -->|échec| Z
    I -->|OK| J[loader\nload_and_run]
    J --> K([PE original en mémoire\nCreateThread entry point])

    style A fill:#1a3a5c,color:#fff
    style K fill:#1a472a,color:#fff
    style Z fill:#5c1a1a,color:#fff
```

---

### Anti-debug (`anti_debug.rs`)

Avant toute opération, le stub vérifie qu'il n'est pas analysé dans un debugger via deux méthodes complémentaires :

```mermaid
flowchart LR
    A[is_being_debugged] --> B[IsDebuggerPresent\nWinAPI]
    A --> C[Lecture PEB directe\ngs:0x60 → PEB+0x2\nBeingDebugged]
    B -->|true| D([exit 1])
    C -->|true| D
```

| Méthode | Mécanisme |
|---|---|
| `IsDebuggerPresent()` | WinAPI standard, consulte `PEB->BeingDebugged` |
| Lecture PEB inline ASM | `gs:[0x60]` → pointeur PEB, lecture de `PEB+0x2` directement en assembleur x86-64 |

Les deux méthodes consultent in fine le même flag `BeingDebugged` du PEB mais par des chemins différents : l'une passe par la WinAPI (hookable), l'autre lit directement le segment GS via `asm!` (plus difficile à intercepter).

---

### Localisation de l'overlay (`overlay.rs`)

Le stub se lit lui-même depuis le disque pour localiser ses données embarquées :

```mermaid
sequenceDiagram
    participant Stub
    participant WinAPI as Windows API
    participant Disk as Disque

    Stub->>WinAPI: GetModuleFileNameW(NULL)
    WinAPI-->>Stub: chemin absolu du binaire en cours
    Stub->>WinAPI: CreateFileW + ReadFile
    WinAPI->>Disk: lecture
    Disk-->>Stub: octets bruts du fichier
    Stub->>Stub: scan des 4 derniers Mo\nrecherche magic XORPACK\0 (rposition)
    Stub->>Stub: parse_header : vérif header_checksum
    Stub->>Stub: vérif checksum payload
    Stub-->>Stub: (OverlayHeader, &[payload])
```

**Détail de la recherche du magic** : la recherche part de la fin du fichier (limitée aux 4 derniers Mo) avec `rposition` — c'est plus efficace car l'overlay est toujours en fin de fichier. Si le `header_checksum` ou le `checksum` du payload ne correspond pas, le stub termine silencieusement (`exit 1`).

---

### Loader PE réflectif (`loader.rs`)

C'est la partie centrale : charger et exécuter un PE64 depuis un buffer mémoire, sans passer par le chargeur Windows standard (`LoadLibrary`). Le loader est sélectionné via le champ `loader_mode` de l'overlay header, défini au moment du packing avec `--loader`.

#### Sélection du loader

```mermaid
flowchart TD
    A[loader_mode\nheader.compression] -->|0 défaut| B[NtSection\nNtCreateSection\n+ NtMapViewOfSection]
    A -->|1| C[NtVirtualMemory\nNtAllocateVirtualMemory\ntout NT API]
    A -->|2| D[Classic\nVirtualAlloc\n+ CreateThread WinAPI]

    style B fill:#1a3a5c,color:#fff
    style C fill:#2d4a1a,color:#fff
    style D fill:#4a3728,color:#fff
```

| Valeur | Variante | Allocation | Thread | Fix imports | Type mémoire |
|--------|----------|-----------|--------|-------------|--------------|
| `0` | `NtSection` | `NtCreateSection` + `NtMapViewOfSection` | `NtCreateThreadEx` | `LdrLoadDll` + `LdrGetProcedureAddress` | `MEM_MAPPED` |
| `1` | `NtVirtualMemory` | `NtAllocateVirtualMemory` | `NtCreateThreadEx` | `LdrLoadDll` + `LdrGetProcedureAddress` | `MEM_PRIVATE` |
| `2` | `Classic` | `VirtualAlloc` | `CreateThread` | `LoadLibraryA` + `GetProcAddress` | `MEM_PRIVATE` |

**`NtSection` (0)** — La région est de type `MEM_MAPPED` (comme une DLL normale) plutôt que `MEM_PRIVATE`, ce qui rend le scan mémoire plus discret. Toutes les résolutions passent par des fonctions NT indirectes sans passer par les stubs de la WinAPI haute couche.

**`NtVirtualMemory` (1)** — Allocation via `NtAllocateVirtualMemory` (syscall NT direct), résolution des imports via `LdrLoadDll`/`LdrGetProcedureAddress`. Évite `VirtualAlloc` qui est souvent hookée par les EDR.

**`Classic` (2)** — Approche standard : `VirtualAlloc`, `LoadLibraryA`, `GetProcAddress`, `CreateThread`. Compatible maximale, mais plus détectable.

#### Pipeline commun aux 3 loaders

```mermaid
flowchart TD
    A[pe_bytes en mémoire] --> B[Valider DOS header\ne_magic == MZ]
    B --> C[Valider NT headers\nsignature == PE\\0\\0]
    C --> D{loader_mode}
    D -->|NtSection| D1[NtCreateSection SEC_COMMIT\n+ NtMapViewOfSection\n→ MEM_MAPPED]
    D -->|NtVirtualMemory| D2[NtAllocateVirtualMemory\n→ MEM_PRIVATE]
    D -->|Classic| D3[VirtualAlloc\n→ MEM_PRIVATE]
    D1 & D2 & D3 --> E[Copier headers PE]
    E --> F[Mapper les sections]
    F --> G{fix_imports}
    G -->|NtSection / NtVirtMem| G1[LdrLoadDll\n+ LdrGetProcedureAddress]
    G -->|Classic| G2[LoadLibraryA\n+ GetProcAddress]
    G1 & G2 --> H[apply_relocations\ndelta patching DIR64]
    H --> I[run_tls_callbacks\nDLL_PROCESS_ATTACH]
    I --> J{thread}
    J -->|NtSection / NtVirtMem| J1[NtCreateThreadEx\n+ NtWaitForSingleObject]
    J -->|Classic| J2[CreateThread\n+ WaitForSingleObject INFINITE]
    J1 & J2 --> K([exit 0])
```

#### Étape fix imports — détail NT (`NtSection` / `NtVirtualMemory`)

```mermaid
flowchart TD
    A[IMAGE_DIRECTORY_ENTRY_IMPORT] --> B[Parcours des ImageImportDescriptor]
    B --> C[Convertir nom DLL → UNICODE_STRING\nwide buffer UTF-16]
    C --> D[LdrLoadDll → handle module]
    D --> E{Type d'import}
    E -->|Par ordinal| F[LdrGetProcedureAddress\nordinal]
    E -->|Par nom| G[NtAnsiString\nLdrGetProcedureAddress\nnom]
    F & G --> H[Patch IAT FirstThunk]
    B -->|suivant| B
```

#### Étape fix imports — détail Classic

```mermaid
flowchart TD
    A[IMAGE_DIRECTORY_ENTRY_IMPORT] --> B[Parcours des ImageImportDescriptor]
    B --> C[LoadLibraryA\nnom de la DLL]
    C --> D{Type d'import}
    D -->|Par ordinal\nIMAGE_ORDINAL_FLAG64| E[GetProcAddress\nordinal & 0xFFFF]
    D -->|Par nom\nIMAGE_IMPORT_BY_NAME| F[GetProcAddress\nHint+2 = char* Name]
    E & F --> G[Patch IAT FirstThunk]
    B -->|suivant| B
```

- Fallback : si `OriginalFirstThunk == 0` (cas MinGW/certains linkers), utilise `FirstThunk` comme source

#### Étape 7 — Relocations (`apply_relocations`)

```mermaid
flowchart LR
    A[delta = base_allouée\n− image_base_préférée] --> B[Parcours blocs\nImageBaseRelocation]
    B --> C{Type entrée >> 12}
    C -->|IMAGE_REL_BASED_DIR64| D[patch: *addr += delta\ncorrection 64-bit absolute]
    C -->|autre| E[ignoré]
    B -->|bloc suivant| B
```

Si le PE n'est pas chargé à son `ImageBase` préféré, toutes les adresses absolues encodées dans la table de relocations sont corrigées en ajoutant `delta`.

#### Étape 8 — TLS Callbacks (`run_tls_callbacks`)

Si le PE déclare une section TLS avec des callbacks (`IMAGE_DIRECTORY_ENTRY_TLS`), ceux-ci sont appelés avec `DLL_PROCESS_ATTACH` avant le lancement de l'entry point — comportement identique au chargeur Windows natif.

#### Étape 9 — Exécution

```mermaid
flowchart LR
    A[entry_point\n= img_base + AddressOfEntryPoint] --> B[CreateThread\ntransmute en LPTHREAD_START_ROUTINE]
    B --> C[WaitForSingleObject INFINITE]
    C --> D([exit 0])
```

L'entry point est lancé dans un nouveau thread via `CreateThread` (avec `transmute` de l'adresse), le stub attend sa fin avec `WaitForSingleObject(INFINITE)`.

---

### Séquence complète packing → exécution

```mermaid
sequenceDiagram
    participant Dev as Opérateur
    participant CLI as packer-cli
    participant Disk as Disque
    participant Stub as stub.exe (runtime)
    participant Mem as Mémoire virtuelle

    Dev->>CLI: packer -i agent.exe --stub stub.exe -o packed.exe --loader nt_section
    CLI->>Disk: lecture agent.exe
    CLI->>CLI: Validation PE (MZ + NT sig)
    CLI->>CLI: Compression LZ4
    CLI->>CLI: Chiffrement AES-256-GCM (clé+nonce aléatoires)
    CLI->>CLI: Calcul SHA-256 payload + header
    CLI->>CLI: loader_mode = 0 (nt_section) → champ compression header
    CLI->>Disk: stub.exe + header XORPACK + payload → packed.exe

    Note over Dev,Disk: Plus tard, sur la cible...

    Dev->>Stub: Exécution packed.exe
    Stub->>Stub: Vérif anti-debug (IsDebuggerPresent + PEB)
    Stub->>Disk: GetModuleFileNameW + ReadFile (lecture de soi-même)
    Stub->>Stub: Scan magic XORPACK\0, parse header
    Stub->>Stub: Vérif header_checksum + payload checksum (SHA-256)
    Stub->>Stub: Déchiffrement AES-256-GCM
    Stub->>Stub: Décompression LZ4
    Stub->>Stub: LoaderType::from(header.compression) → NtSection
    Stub->>Mem: NtCreateSection SEC_COMMIT + NtMapViewOfSection (MEM_MAPPED)
    Stub->>Mem: Copie headers + sections
    Stub->>Mem: Fix IAT (LdrLoadDll / LdrGetProcedureAddress)
    Stub->>Mem: Apply relocations (delta patching)
    Stub->>Mem: TLS callbacks
    Stub->>Mem: NtCreateThreadEx(entry_point)
    Mem-->>Stub: NtWaitForSingleObject
```

---

## Structure des sources (mise à jour)

```
packer/
├── packer-cli/          # Outil de packing (Rust)
│   └── src/
│       ├── main.rs          # Point d'entrée CLI (clap)
│       ├── pe_parser.rs     # Validation signature MZ + PE
│       ├── compress.rs      # Compression LZ4 (lz4_flex)
│       ├── encrypt.rs       # AES-256-GCM + XOR
│       ├── checksum.rs      # SHA-256 (sha2)
│       └── stub_builder.rs  # Assemblage final + sérialisation header
└── stub/                # Loader runtime (Rust, compilé séparément)
    └── src/
        ├── main.rs          # Orchestration : anti-debug → overlay → decrypt → load
        ├── anti_debug.rs    # IsDebuggerPresent + lecture PEB (asm x86-64)
        ├── overlay.rs       # Lecture du fichier, scan magic, parse + vérif header
        ├── decrypt.rs       # Déchiffrement AES-256-GCM + XOR
        ├── decompress.rs    # Décompression LZ4
        ├── checksum.rs      # SHA-256 compute + verify
        └── loader.rs        # 3 loaders PE réflectifs : NtSection / NtVirtualMemory / Classic
```

---

## Usage CLI

```
packer --input agent.exe --stub stub.exe --output packed.exe [--encryption aes|xor] [--loader nt_section|nt_virtual_memory|classic]
```

| Argument | Description | Défaut |
|---|---|---|
| `-i, --input` | PE d'entrée à protéger | — |
| `-o, --output` | Fichier de sortie | — |
| `--stub` | Stub Windows pré-compilé | — |
| `-e, --encryption` | Algorithme : `aes` ou `xor` | `aes` |
| `--loader` | Technique de chargement en mémoire : `nt_section`, `nt_virtual_memory` ou `classic` | `nt_virtual_memory` |

### Exemples

```bash
# Loader NT section (MEM_MAPPED, le plus discret)
cargo run -p packer-cli -- -i agent.exe --stub stub.exe -o packed.exe --loader nt_section

# Loader NT VirtualMemory (NtAllocateVirtualMemory, évite les hooks EDR sur VirtualAlloc)
cargo run -p packer-cli -- -i agent.exe --stub stub.exe -o packed.exe --loader nt_virtual_memory

# Loader classique (VirtualAlloc + CreateThread, compatibilité maximale)
cargo run -p packer-cli -- -i agent.exe --stub stub.exe -o packed.exe --loader classic --encryption xor
```

---

## Dépendances

| Crate | Version | Rôle |
|---|---|---|
| `clap` | 4 | Parsing des arguments CLI |
| `aes-gcm` | 0.10 | Chiffrement AES-256-GCM |
| `sha2` | 0.10 | Calcul SHA-256 (intégrité) |
| `lz4_flex` | 0.11 | Compression/décompression LZ4 |
| `rand` | 0.8 | Génération aléatoire clé/nonce |
| `anyhow` | 1 | Gestion d'erreurs |
