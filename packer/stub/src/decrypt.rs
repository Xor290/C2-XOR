use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};

pub const ENC_XOR: u8 = 0;
pub const ENC_AES_GCM: u8 = 1;

pub fn decrypt_payload(
    ciphertext: &[u8],
    mode: u8,
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Option<Vec<u8>> {
    match mode {
        ENC_AES_GCM => {
            let k = Key::<Aes256Gcm>::from_slice(key);
            let cipher = Aes256Gcm::new(k);
            let n = Nonce::from_slice(nonce);
            cipher.decrypt(n, ciphertext).ok()
        }
        ENC_XOR => {
            let plain: Vec<u8> = ciphertext
                .iter()
                .enumerate()
                .map(|(i, &b)| b ^ key[i % key.len()])
                .collect();
            Some(plain)
        }
        _ => None,
    }
}
