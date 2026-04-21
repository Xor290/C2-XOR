use base64::{engine::general_purpose::STANDARD, Engine};

pub fn xor_data(data: &[u8], key: &str) -> Vec<u8> {
    let key_bytes = key.as_bytes();
    let key_len = key_bytes.len();
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key_bytes[i % key_len])
        .collect()
}

pub fn b64_encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    STANDARD.decode(s.trim()).map_err(|e| e.to_string())
}

/// Encrypt a plaintext string: XOR then base64
pub fn encrypt(plaintext: &str, key: &str) -> String {
    let xored = xor_data(plaintext.as_bytes(), key);
    b64_encode(&xored)
}

/// Decrypt a base64+XOR ciphertext back to a UTF-8 string
pub fn decrypt(ciphertext: &str, key: &str) -> Result<String, String> {
    let decoded = b64_decode(ciphertext)?;
    let xored = xor_data(&decoded, key);
    String::from_utf8(xored).map_err(|e| e.to_string())
}
