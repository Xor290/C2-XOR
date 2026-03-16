use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::Result;
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};
use rand::RngCore;

#[derive(Debug, Clone, Copy)]
pub enum EncryptionMode {
    Xor = 0,
    Aes256Gcm = 1,
    Rc4 = 2,
    ChaCha20Poly1305 = 3,
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

fn rc4_crypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }
    let mut i = 0usize;
    let mut j = 0usize;
    data.iter()
        .map(|&b| {
            i = (i + 1) % 256;
            j = (j + s[i] as usize) % 256;
            s.swap(i, j);
            b ^ s[(s[i] as usize + s[j] as usize) % 256]
        })
        .collect()
}

pub fn encrypt_rc4(plaintext: &[u8]) -> EncryptResult {
    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);

    let ciphertext = rc4_crypt(plaintext, &key_bytes);

    EncryptResult {
        ciphertext,
        key: key_bytes,
        nonce: [0u8; 12],
        mode: EncryptionMode::Rc4,
    }
}

pub fn encrypt_chacha20poly1305(plaintext: &[u8]) -> Result<EncryptResult> {
    let mut key_bytes = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let key = ChaChaKey::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = ChaChaNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("ChaCha20Poly1305 chiffrement échoué: {}", e))?;

    Ok(EncryptResult {
        ciphertext,
        key: key_bytes,
        nonce: nonce_bytes,
        mode: EncryptionMode::ChaCha20Poly1305,
    })
}
