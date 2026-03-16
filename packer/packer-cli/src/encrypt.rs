use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::Result;
use rand::RngCore;

#[derive(Debug, Clone, Copy)]
pub enum EncryptionMode {
    Xor = 0,
    Aes256Gcm = 1,
}

pub struct EncryptResult {
    pub ciphertext: Vec<u8>,
    pub key: [u8; 32],
    pub nonce: [u8; 12],
    pub mode: EncryptionMode,
}

pub fn encrypt_aes256gcm(plaintext: &[u8]) -> Result<EncryptResult> {
    let mut key_bytes = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("AES-GCM chiffrement échoué: {}", e))?;

    Ok(EncryptResult {
        ciphertext,
        key: key_bytes,
        nonce: nonce_bytes,
        mode: EncryptionMode::Aes256Gcm,
    })
}

pub fn encrypt_xor(plaintext: &[u8]) -> EncryptResult {
    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);

    let ciphertext: Vec<u8> = plaintext
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key_bytes[i % key_bytes.len()])
        .collect();

    EncryptResult {
        ciphertext,
        key: key_bytes,
        nonce: [0u8; 12],
        mode: EncryptionMode::Xor,
    }
}
