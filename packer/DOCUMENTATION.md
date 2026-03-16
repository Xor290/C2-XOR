# XOR C2 Packer — Technical Documentation

## Overview

The packer is a Rust tool composed of two distinct parts:

- **`packer-cli`**: the packing tool (builder side), which takes a PE as input and produces a protected binary.
- **`stub`**: the embedded loader (pre-compiled separately), which is executed at launch time and reconstructs the original PE in memory.

---

## Packing Pipeline

```mermaid
flowchart TD
    A[agent.exe\nOriginal PE] --> B[pe_parser\nMZ + PE sig validation]
    B --> C[compress\nLZ4 compression]
    C --> D{Encryption\nalgorithm}
    D -->|--encryption aes| E[encrypt_aes256gcm\nAES-256-GCM\n32B key + 12B random nonce]
    D -->|--encryption xor| F[encrypt_xor\nXOR 32B random key]
    D -->|--encryption rc4| R[encrypt_rc4\nRC4 32B random key]
    D -->|--encryption chacha20| CH[encrypt_chacha20poly1305\nChaCha20-Poly1305\n32B key + 12B random nonce]
    E --> G[stub_builder]
    F --> G
    R --> G
    CH --> G
    L{--loader} -->|nt_section 0| G
    L -->|nt_virtual_memory 1| G
    L -->|classic 2| G
    G --> H[stub.exe\npre-compiled]
    G --> I[packed.exe\nfinal binary]

    style A fill:#2d2d2d,color:#fff
    style I fill:#1a472a,color:#fff
    style H fill:#1a3a5c,color:#fff
```

---

## Final Binary Structure

The produced binary is a concatenation of three blocks:

```mermaid
block-beta
    columns 1
    block:exe["packed.exe"]:1
        A["stub.exe\n(Windows executable PE)"]
        B["XORPACK Header\n(106 bytes, little-endian)"]
        C["Encrypted payload\n(compressed + encrypted PE)"]
    end
```

### Header detail (106 bytes)

```mermaid
packet-beta
    0-7: "magic[8]\n= XORPACK\\0"
    8-11: "version\nu32 LE"
    12-12: "enc_mode\nu8"
    13-13: "loader_mode\nu8 (0/1/2)"
    14-21: "original_size\nu64 LE"
    22-29: "payload_size\nu64 LE"
    30-61: "key[32]\n(AES / XOR / RC4 / ChaCha20)"
    62-73: "nonce[12]\n(AES-GCM / ChaCha20)"
    74-105: "checksum[32]\nSHA-256 payload"
    106-137: "header_checksum[32]\nSHA-256 of first 74 bytes"
```

> The magic `XORPACK\x00` allows the stub to locate the overlay at the end of the file.

---

## Encryption Algorithms

### AES-256-GCM

```mermaid
flowchart LR
    A[compressed data] --> C[AES-256-GCM]
    B1[32B key\nCSPRNG] --> C
    B2[12B nonce\nCSPRNG] --> C
    C --> D[ciphertext + 16B auth tag]
```

- Key and nonce randomly generated via `rand::thread_rng()`
- GCM authentication tag included in the ciphertext
- Provides both confidentiality **and** integrity

### XOR

```mermaid
flowchart LR
    A[compressed data] --> C[cyclic XOR]
    B[32B key\nCSPRNG] --> C
    C --> D[ciphertext]
```

- Cyclic XOR over 32 bytes: `byte[i] ^ key[i % 32]`
- Nonce = `[0u8; 12]` (unused)
- Lightweight alternative, less robust

### RC4

```mermaid
flowchart LR
    A[compressed data] --> C[RC4 KSA + PRGA]
    B[32B key\nCSPRNG] --> C
    C --> D[ciphertext]
```

- Standard RC4 stream cipher (KSA + PRGA), implemented inline (no external crate)
- Nonce = `[0u8; 12]` (unused)
- Fast, symmetric — decryption is the same operation as encryption

### ChaCha20-Poly1305

```mermaid
flowchart LR
    A[compressed data] --> C[ChaCha20-Poly1305]
    B1[32B key\nCSPRNG] --> C
    B2[12B nonce\nCSPRNG] --> C
    C --> D[ciphertext + 16B auth tag]
```

- Key and nonce randomly generated via `rand::thread_rng()`
- Poly1305 authentication tag included in the ciphertext
- Provides both confidentiality **and** integrity
- Fast in software (no AES hardware requirement)

### Encryption mode summary

| Mode | Value | Algorithm | Integrity | Nonce used |
|------|-------|-----------|-----------|------------|
| `xor` | `0` | Cyclic XOR 32B | No | No |
| `aes` | `1` | AES-256-GCM | Yes (GCM tag) | Yes |
| `rc4` | `2` | RC4 stream cipher | No | No |
| `chacha20` | `3` | ChaCha20-Poly1305 | Yes (Poly1305) | Yes |

---

## Integrity Checks

```mermaid
flowchart TD
    A[encrypted payload] -->|SHA-256| B[checksum\nstored in header]
    C[first 74 bytes\nof header] -->|SHA-256| D[header_checksum\nstored after header]

    style B fill:#4a3728,color:#fff
    style D fill:#4a3728,color:#fff
```

Two levels of SHA-256 verification:
1. **`checksum`**: integrity of the encrypted payload
2. **`header_checksum`**: integrity of the header itself (anti-tamper)

---

## The Loader (stub) — Detailed Operation

The stub is a standalone Windows PE (`#![windows_subsystem = "windows"]`) compiled separately. It acts as a reflective loader: it reconstructs and executes the original PE entirely in memory, without ever writing it to disk.

### Stub overview

```mermaid
flowchart TD
    A([stub.exe execution]) --> B[anti_debug\nDebugger check]
    B -->|debugger detected| Z([exit 1])
    B -->|OK| C[overlay\nGetModuleFileNameW\nRead file from disk]
    C --> D[overlay\nSearch for XORPACK\0 magic]
    D -->|not found| Z
    D -->|found| E[overlay\nParse 106-byte header]
    E --> F[checksum\nVerify header_checksum SHA-256]
    F -->|invalid| Z
    F -->|OK| G[checksum\nVerify payload checksum SHA-256]
    G -->|invalid| Z
    G -->|OK| H[decrypt\nDecrypt AES-256-GCM / XOR / RC4 / ChaCha20]
    H -->|failure| Z
    H -->|OK| I[decompress\nLZ4 decompression]
    I -->|failure| Z
    I -->|OK| J[loader\nload_and_run]
    J --> K([Original PE in memory\nCreateThread entry point])

    style A fill:#1a3a5c,color:#fff
    style K fill:#1a472a,color:#fff
    style Z fill:#5c1a1a,color:#fff
```

---

### Anti-debug (`anti_debug.rs`)

Before any operation, the stub checks that it is not being analyzed in a debugger via two complementary methods:

```mermaid
flowchart LR
    A[is_being_debugged] --> B[IsDebuggerPresent\nWinAPI]
    A --> C[Direct PEB read\ngs:0x60 → PEB+0x2\nBeingDebugged]
    B -->|true| D([exit 1])
    C -->|true| D
```

| Method | Mechanism |
|--------|-----------|
| `IsDebuggerPresent()` | Standard WinAPI, reads `PEB->BeingDebugged` |
| Inline ASM PEB read | `gs:[0x60]` → PEB pointer, reads `PEB+0x2` directly via x86-64 `asm!` |

Both methods ultimately check the same `BeingDebugged` flag in the PEB but via different paths: one goes through the WinAPI (hookable), the other reads the GS segment directly (harder to intercept).

---

### Overlay location (`overlay.rs`)

The stub reads itself from disk to locate its embedded data:

```mermaid
sequenceDiagram
    participant Stub
    participant WinAPI as Windows API
    participant Disk

    Stub->>WinAPI: GetModuleFileNameW(NULL)
    WinAPI-->>Stub: absolute path of running binary
    Stub->>WinAPI: CreateFileW + ReadFile
    WinAPI->>Disk: read
    Disk-->>Stub: raw file bytes
    Stub->>Stub: scan last 4 MB\nsearch for XORPACK\0 magic (rposition)
    Stub->>Stub: parse_header: verify header_checksum
    Stub->>Stub: verify payload checksum
    Stub-->>Stub: (OverlayHeader, &[payload])
```

**Magic search detail**: the search starts from the end of the file (limited to the last 4 MB) using `rposition` — more efficient since the overlay is always at the end. If `header_checksum` or payload `checksum` does not match, the stub exits silently (`exit 1`).

---

### Reflective PE Loader (`loader.rs`)

This is the core component: loading and executing a PE64 from a memory buffer, without going through the standard Windows loader (`LoadLibrary`). The loader is selected via the `loader_mode` field in the overlay header, set at packing time with `--loader`.

#### Loader selection

```mermaid
flowchart TD
    A[loader_mode\nheader field] -->|0 default| B[NtSection\nNtCreateSection\n+ NtMapViewOfSection]
    A -->|1| C[NtVirtualMemory\nNtAllocateVirtualMemory\nfull NT API]
    A -->|2| D[Classic\nVirtualAlloc\n+ CreateThread WinAPI]

    style B fill:#1a3a5c,color:#fff
    style C fill:#2d4a1a,color:#fff
    style D fill:#4a3728,color:#fff
```

| Value | Variant | Allocation | Thread | Import fix | Memory type |
|-------|---------|-----------|--------|------------|-------------|
| `0` | `NtSection` | `NtCreateSection` + `NtMapViewOfSection` | `NtCreateThreadEx` | `LdrLoadDll` + `LdrGetProcedureAddress` | `MEM_MAPPED` |
| `1` | `NtVirtualMemory` | `NtAllocateVirtualMemory` | `NtCreateThreadEx` | `LdrLoadDll` + `LdrGetProcedureAddress` | `MEM_PRIVATE` |
| `2` | `Classic` | `VirtualAlloc` | `CreateThread` | `LoadLibraryA` + `GetProcAddress` | `MEM_PRIVATE` |

**`NtSection` (0)** — The region is `MEM_MAPPED` (like a normal DLL) rather than `MEM_PRIVATE`, making memory scanning less suspicious. All resolutions go through indirect NT functions without touching high-level WinAPI stubs.

**`NtVirtualMemory` (1)** — Allocation via `NtAllocateVirtualMemory` (direct NT syscall), import resolution via `LdrLoadDll`/`LdrGetProcedureAddress`. Avoids `VirtualAlloc` which is often hooked by EDRs.

**`Classic` (2)** — Standard approach: `VirtualAlloc`, `LoadLibraryA`, `GetProcAddress`, `CreateThread`. Maximum compatibility, but more detectable.

#### Common pipeline for all 3 loaders

```mermaid
flowchart TD
    A[pe_bytes in memory] --> B[Validate DOS header\ne_magic == MZ]
    B --> C[Validate NT headers\nsignature == PE\\0\\0]
    C --> D{loader_mode}
    D -->|NtSection| D1[NtCreateSection SEC_COMMIT\n+ NtMapViewOfSection\n→ MEM_MAPPED]
    D -->|NtVirtualMemory| D2[NtAllocateVirtualMemory\n→ MEM_PRIVATE]
    D -->|Classic| D3[VirtualAlloc\n→ MEM_PRIVATE]
    D1 & D2 & D3 --> E[Copy PE headers]
    E --> F[Map sections]
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

#### Import fix step — NT detail (`NtSection` / `NtVirtualMemory`)

```mermaid
flowchart TD
    A[IMAGE_DIRECTORY_ENTRY_IMPORT] --> B[Walk ImageImportDescriptors]
    B --> C[Convert DLL name → UNICODE_STRING\nUTF-16 wide buffer]
    C --> D[LdrLoadDll → module handle]
    D --> E{Import type}
    E -->|By ordinal| F[LdrGetProcedureAddress\nordinal]
    E -->|By name| G[NtAnsiString\nLdrGetProcedureAddress\nname]
    F & G --> H[Patch IAT FirstThunk]
    B -->|next| B
```

#### Import fix step — Classic detail

```mermaid
flowchart TD
    A[IMAGE_DIRECTORY_ENTRY_IMPORT] --> B[Walk ImageImportDescriptors]
    B --> C[LoadLibraryA\nDLL name]
    C --> D{Import type}
    D -->|By ordinal\nIMAGE_ORDINAL_FLAG64| E[GetProcAddress\nordinal & 0xFFFF]
    D -->|By name\nIMAGE_IMPORT_BY_NAME| F[GetProcAddress\nHint+2 = char* Name]
    E & F --> G[Patch IAT FirstThunk]
    B -->|next| B
```

- Fallback: if `OriginalFirstThunk == 0` (MinGW/some linkers), uses `FirstThunk` as source

#### Step 7 — Relocations (`apply_relocations`)

```mermaid
flowchart LR
    A[delta = allocated base\n− preferred image base] --> B[Walk\nImageBaseRelocation blocks]
    B --> C{Entry type >> 12}
    C -->|IMAGE_REL_BASED_DIR64| D[patch: *addr += delta\n64-bit absolute correction]
    C -->|other| E[ignored]
    B -->|next block| B
```

If the PE is not loaded at its preferred `ImageBase`, all absolute addresses encoded in the relocation table are corrected by adding `delta`.

#### Step 8 — TLS Callbacks (`run_tls_callbacks`)

If the PE declares a TLS section with callbacks (`IMAGE_DIRECTORY_ENTRY_TLS`), they are called with `DLL_PROCESS_ATTACH` before launching the entry point — identical behavior to the native Windows loader.

#### Step 9 — Execution

```mermaid
flowchart LR
    A[entry_point\n= img_base + AddressOfEntryPoint] --> B[CreateThread\ntransmute to LPTHREAD_START_ROUTINE]
    B --> C[WaitForSingleObject INFINITE]
    C --> D([exit 0])
```

The entry point is launched in a new thread via `CreateThread` (with address `transmute`), the stub waits for it to finish with `WaitForSingleObject(INFINITE)`.

---

### Full packing → execution sequence

```mermaid
sequenceDiagram
    participant Dev as Operator
    participant CLI as packer-cli
    participant Disk
    participant Stub as stub.exe (runtime)
    participant Mem as Virtual Memory

    Dev->>CLI: packer -i agent.exe --stub stub.exe -o packed.exe --loader nt_section
    CLI->>Disk: read agent.exe
    CLI->>CLI: PE validation (MZ + NT sig)
    CLI->>CLI: LZ4 compression
    CLI->>CLI: AES-256-GCM encryption (random key+nonce)
    CLI->>CLI: SHA-256 payload + header
    CLI->>CLI: loader_mode = 0 (nt_section) → header compression field
    CLI->>Disk: stub.exe + XORPACK header + payload → packed.exe

    Note over Dev,Disk: Later, on the target...

    Dev->>Stub: Execute packed.exe
    Stub->>Stub: Anti-debug check (IsDebuggerPresent + PEB)
    Stub->>Disk: GetModuleFileNameW + ReadFile (read self)
    Stub->>Stub: Scan XORPACK\0 magic, parse header
    Stub->>Stub: Verify header_checksum + payload checksum (SHA-256)
    Stub->>Stub: Decrypt AES-256-GCM / XOR / RC4 / ChaCha20
    Stub->>Stub: LZ4 decompression
    Stub->>Stub: LoaderType::from(header.compression) → NtSection
    Stub->>Mem: NtCreateSection SEC_COMMIT + NtMapViewOfSection (MEM_MAPPED)
    Stub->>Mem: Copy headers + sections
    Stub->>Mem: Fix IAT (LdrLoadDll / LdrGetProcedureAddress)
    Stub->>Mem: Apply relocations (delta patching)
    Stub->>Mem: TLS callbacks
    Stub->>Mem: NtCreateThreadEx(entry_point)
    Mem-->>Stub: NtWaitForSingleObject
```

---

## Source Structure

```
packer/
├── packer-cli/          # Packing tool (Rust)
│   └── src/
│       ├── main.rs          # CLI entry point (clap)
│       ├── pe_parser.rs     # MZ + PE signature validation
│       ├── compress.rs      # LZ4 compression (lz4_flex)
│       ├── encrypt.rs       # AES-256-GCM + XOR + RC4 + ChaCha20-Poly1305
│       ├── checksum.rs      # SHA-256 (sha2)
│       └── stub_builder.rs  # Final assembly + header serialization
└── stub/                # Runtime loader (Rust, compiled separately)
    └── src/
        ├── main.rs          # Orchestration: anti-debug → overlay → decrypt → load
        ├── anti_debug.rs    # IsDebuggerPresent + PEB read (x86-64 asm)
        ├── overlay.rs       # File read, magic scan, parse + verify header
        ├── decrypt.rs       # AES-256-GCM + XOR + RC4 + ChaCha20-Poly1305 decryption
        ├── decompress.rs    # LZ4 decompression
        ├── checksum.rs      # SHA-256 compute + verify
        └── loader.rs        # 3 reflective PE loaders: NtSection / NtVirtualMemory / Classic
```

---

## CLI Usage

```
packer --input agent.exe --stub stub.exe --output packed.exe [--encryption aes|xor|rc4|chacha20] [--loader nt_section|nt_virtual_memory|classic]
```

| Argument | Description | Default |
|----------|-------------|---------|
| `-i, --input` | Input PE to protect | — |
| `-o, --output` | Output file | — |
| `--stub` | Pre-compiled Windows stub | — |
| `-e, --encryption` | Algorithm: `aes`, `xor`, `rc4`, or `chacha20` | `aes` |
| `--loader` | Memory loading technique: `nt_section`, `nt_virtual_memory`, or `classic` | `nt_virtual_memory` |

### Examples

```bash
# NT Section loader (MEM_MAPPED, most stealthy)
cargo run -p packer-cli -- -i agent.exe --stub stub.exe -o packed.exe --loader nt_section

# NT VirtualMemory loader (NtAllocateVirtualMemory, avoids EDR hooks on VirtualAlloc)
cargo run -p packer-cli -- -i agent.exe --stub stub.exe -o packed.exe --loader nt_virtual_memory

# Classic loader with RC4 encryption
cargo run -p packer-cli -- -i agent.exe --stub stub.exe -o packed.exe --loader classic --encryption rc4

# NT Section with ChaCha20-Poly1305
cargo run -p packer-cli -- -i agent.exe --stub stub.exe -o packed.exe --loader nt_section --encryption chacha20

# Classic loader with XOR (maximum compatibility)
cargo run -p packer-cli -- -i agent.exe --stub stub.exe -o packed.exe --loader classic --encryption xor
```

---

## Dependencies

### packer-cli

| Crate | Version | Role |
|-------|---------|------|
| `clap` | 4 | CLI argument parsing |
| `aes-gcm` | 0.10 | AES-256-GCM encryption |
| `chacha20poly1305` | 0.10 | ChaCha20-Poly1305 encryption |
| `sha2` | 0.10 | SHA-256 integrity checks |
| `lz4_flex` | 0.11 | LZ4 compression |
| `rand` | 0.8 | Random key/nonce generation |
| `anyhow` | 1 | Error handling |

### stub

| Crate | Version | Role |
|-------|---------|------|
| `aes-gcm` | 0.10 | AES-256-GCM decryption |
| `chacha20poly1305` | 0.10 | ChaCha20-Poly1305 decryption |
| `sha2` | 0.10 | SHA-256 integrity verification |
| `lz4_flex` | 0.11 | LZ4 decompression |
| `winapi` | 0.3 | Windows NT API bindings |
