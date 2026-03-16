use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};

pub const ENC_XOR: u8 = 0;
pub const ENC_AES_GCM: u8 = 1;
pub const ENC_RC4: u8 = 2;
pub const ENC_CHACHA20: u8 = 3;

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
        ENC_RC4 => Some(rc4_crypt(ciphertext, key)),
        ENC_CHACHA20 => {
            let k = ChaChaKey::from_slice(key);
            let cipher = ChaCha20Poly1305::new(k);
            let n = ChaChaNonce::from_slice(nonce);
            cipher.decrypt(n, ciphertext).ok()
        }
        _ => None,
    }
}
