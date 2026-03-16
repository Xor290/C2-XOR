use crate::checksum::compute_sha256;
use crate::encrypt::EncryptionMode;
use anyhow::Result;
use std::path::Path;

/// Magic permettant au stub de localiser son overlay en fin de fichier
pub const MAGIC: &[u8; 8] = b"XORPACK\x00";

/// Header binaire sérialisé en little-endian, taille fixe : 106 octets
///
/// Disposition :
///   magic[8] | version:u32 | enc_mode:u8 | compression:u8 |
///   original_size:u64 | payload_size:u64 |
///   key[32] | nonce[12] | checksum[32] | header_checksum[32]
pub struct PackedHeader {
    pub version: u32,
    pub encryption_mode: EncryptionMode,
    pub loader_mode: u8,
    pub original_size: u64,
    pub payload_size: u64,
    pub key: [u8; 32],
    pub nonce: [u8; 12],
    pub checksum: [u8; 32],   // SHA-256 du payload chiffré
    pub header_checksum: [u8; 32], // SHA-256 de tous les champs précédents
}

pub struct PackInput {
    pub encryption_mode: EncryptionMode,
    pub loader_mode: u8,
    pub original_size: usize,
    pub payload: Vec<u8>,
    pub key: [u8; 32],
    pub nonce: [u8; 12],
}

fn serialize_header_body(h: &PackedHeader) -> Vec<u8> {
    // Tout sauf header_checksum
    let mut buf = Vec::with_capacity(74);
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&h.version.to_le_bytes());
    buf.push(h.encryption_mode as u8);
    buf.push(h.loader_mode);
    buf.extend_from_slice(&h.original_size.to_le_bytes());
    buf.extend_from_slice(&h.payload_size.to_le_bytes());
    buf.extend_from_slice(&h.key);
    buf.extend_from_slice(&h.nonce);
    buf.extend_from_slice(&h.checksum);
    buf
}

pub fn build_packed_exe(stub_path: &Path, input: PackInput, output_path: &Path) -> Result<()> {
    let stub_bytes = std::fs::read(stub_path)
        .map_err(|e| anyhow::anyhow!("Impossible de lire le stub '{}': {}", stub_path.display(), e))?;

    let checksum = compute_sha256(&input.payload);

    let header = PackedHeader {
        version: 1,
        encryption_mode: input.encryption_mode,
        loader_mode: input.loader_mode,
        original_size: input.original_size as u64,
        payload_size: input.payload.len() as u64,
        key: input.key,
        nonce: input.nonce,
        checksum,
        header_checksum: [0u8; 32], // calculé après
    };

    let body = serialize_header_body(&header);
    let hdr_checksum = compute_sha256(&body);

    let mut out = Vec::with_capacity(stub_bytes.len() + body.len() + 32 + input.payload.len());
    out.extend_from_slice(&stub_bytes);
    out.extend_from_slice(&body);
    out.extend_from_slice(&hdr_checksum);
    out.extend_from_slice(&input.payload);

    std::fs::write(output_path, &out)
        .map_err(|e| anyhow::anyhow!("Impossible d'écrire '{}': {}", output_path.display(), e))?;

    println!(
        "[+] Binaire protégé : {} ({} octets)",
        output_path.display(),
        out.len()
    );
    Ok(())
}
