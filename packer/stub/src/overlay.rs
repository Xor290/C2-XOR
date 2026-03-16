/// Localise l'overlay XORPACK dans le fichier du stub lui-même.
/// Le stub lit son propre fichier depuis le disque via GetModuleFileNameW
/// puis scanne les octets après les sections PE pour trouver le magic.

const MAGIC: &[u8; 8] = b"XORPACK\x00";

/// Header lu depuis l'overlay, taille fixe 106 octets :
/// magic[8] | version:u32 | enc_mode:u8 | compression:u8 |
/// original_size:u64 | payload_size:u64 |
/// key[32] | nonce[12] | checksum[32] | header_checksum[32]
pub struct OverlayHeader {
    pub version: u32,
    pub encryption_mode: u8,
    pub compression: u8,
    pub original_size: u64,
    pub payload_size: u64,
    pub key: [u8; 32],
    pub nonce: [u8; 12],
    pub checksum: [u8; 32],
    pub header_checksum: [u8; 32],
}

const HEADER_BODY_SIZE: usize = 8 + 4 + 1 + 1 + 8 + 8 + 32 + 12 + 32; // 106 octets avant header_checksum
const HEADER_TOTAL_SIZE: usize = HEADER_BODY_SIZE + 32; // + header_checksum

#[cfg(target_os = "windows")]
pub fn read_own_file() -> Option<Vec<u8>> {
    use winapi::um::fileapi::{CreateFileW, GetFileSize, ReadFile, OPEN_EXISTING};
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use winapi::um::libloaderapi::GetModuleFileNameW;
    use winapi::um::winnt::{FILE_SHARE_READ, GENERIC_READ};
    const INVALID_FILE_SIZE: u32 = 0xFFFFFFFF;

    unsafe {
        let mut path = [0u16; 32768];
        let len = GetModuleFileNameW(core::ptr::null_mut(), path.as_mut_ptr(), path.len() as u32);
        if len == 0 {
            return None;
        }

        let h = CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            core::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            core::ptr::null_mut(),
        );
        if h == INVALID_HANDLE_VALUE {
            return None;
        }

        let size = GetFileSize(h, core::ptr::null_mut());
        if size == INVALID_FILE_SIZE || size == 0 {
            CloseHandle(h);
            return None;
        }

        let mut buf = vec![0u8; size as usize];
        let mut bytes_read: u32 = 0;
        let ok = ReadFile(
            h,
            buf.as_mut_ptr() as *mut _,
            size,
            &mut bytes_read,
            core::ptr::null_mut(),
        );
        CloseHandle(h);

        if ok == 0 || bytes_read != size {
            return None;
        }
        Some(buf)
    }
}

#[cfg(not(target_os = "windows"))]
pub fn read_own_file() -> Option<Vec<u8>> {
    None
}

/// Cherche le magic XORPACK dans les octets du fichier et retourne
/// (OverlayHeader, payload_slice) si trouvé et valide.
pub fn find_overlay(file_bytes: &[u8]) -> Option<(OverlayHeader, &[u8])> {
    // Recherche du magic en partant de la fin (plus efficace)
    let search_from = if file_bytes.len() > 4 * 1024 * 1024 {
        file_bytes.len() - 4 * 1024 * 1024
    } else {
        0
    };

    let window = &file_bytes[search_from..];
    let magic_pos = window
        .windows(8)
        .rposition(|w| w == MAGIC)?;
    let abs_pos = search_from + magic_pos;

    let header_end = abs_pos + HEADER_TOTAL_SIZE;
    if header_end > file_bytes.len() {
        return None;
    }

    let hdr_bytes = &file_bytes[abs_pos..header_end];
    parse_header(hdr_bytes, file_bytes, abs_pos)
}

fn parse_header<'a>(
    hdr: &[u8],
    file_bytes: &'a [u8],
    abs_pos: usize,
) -> Option<(OverlayHeader, &'a [u8])> {
    use crate::checksum::{compute_sha256, verify_sha256};

    // Vérifier header_checksum : SHA-256 des 106 premiers octets
    let body = &hdr[..HEADER_BODY_SIZE];
    let expected_hdr_checksum: [u8; 32] = hdr[HEADER_BODY_SIZE..HEADER_BODY_SIZE + 32]
        .try_into()
        .ok()?;
    if compute_sha256(body) != expected_hdr_checksum {
        return None;
    }

    let mut off = 8; // après magic

    let version = u32::from_le_bytes(body[off..off + 4].try_into().ok()?);
    off += 4;
    let encryption_mode = body[off];
    off += 1;
    let compression = body[off];
    off += 1;
    let original_size = u64::from_le_bytes(body[off..off + 8].try_into().ok()?);
    off += 8;
    let payload_size = u64::from_le_bytes(body[off..off + 8].try_into().ok()?);
    off += 8;
    let key: [u8; 32] = body[off..off + 32].try_into().ok()?;
    off += 32;
    let nonce: [u8; 12] = body[off..off + 12].try_into().ok()?;
    off += 12;
    let checksum: [u8; 32] = body[off..off + 32].try_into().ok()?;

    let payload_start = abs_pos + HEADER_TOTAL_SIZE;
    let payload_end = payload_start + payload_size as usize;
    if payload_end > file_bytes.len() {
        return None;
    }
    let payload = &file_bytes[payload_start..payload_end];

    // Vérifier checksum du payload
    if !verify_sha256(payload, &checksum) {
        return None;
    }

    Some((
        OverlayHeader {
            version,
            encryption_mode,
            compression,
            original_size,
            payload_size,
            key,
            nonce,
            checksum,
            header_checksum: expected_hdr_checksum,
        },
        payload,
    ))
}
