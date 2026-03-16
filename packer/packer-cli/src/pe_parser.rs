use anyhow::{bail, Context, Result};
use std::path::Path;

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x00004550;

pub fn validate_pe(data: &[u8]) -> Result<()> {
    if data.len() < 64 {
        bail!("Fichier trop petit pour être un PE valide");
    }
    let e_magic = u16::from_le_bytes([data[0], data[1]]);
    if e_magic != IMAGE_DOS_SIGNATURE {
        bail!("Signature DOS invalide (attendu MZ)");
    }
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew + 4 > data.len() {
        bail!("e_lfanew hors limites");
    }
    let pe_sig = u32::from_le_bytes([
        data[e_lfanew],
        data[e_lfanew + 1],
        data[e_lfanew + 2],
        data[e_lfanew + 3],
    ]);
    if pe_sig != IMAGE_NT_SIGNATURE {
        bail!("Signature NT invalide (attendu PE\\0\\0)");
    }
    Ok(())
}

pub fn read_pe_file(path: &Path) -> Result<Vec<u8>> {
    let data = std::fs::read(path)
        .with_context(|| format!("Impossible de lire {}", path.display()))?;
    validate_pe(&data).with_context(|| "Fichier PE invalide")?;
    Ok(data)
}
