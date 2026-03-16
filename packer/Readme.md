# Packer

## Compiler le stub

```bash
cargo build -p stub --release --target x86_64-pc-windows-gnu
```

## Compiler le packer

```bash
cargo build --release -p packer-cli
```

## Packer l'agent

```bash
./target/release/packer \
    --input agent.exe \
    --output agent_packed.exe \
    --stub ./target/x86_64-pc-windows-gnu/release/stub.exe \
    --encryption aes
```
