use sha2::{Digest, Sha256};

pub fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn verify_sha256(data: &[u8], expected: &[u8; 32]) -> bool {
    compute_sha256(data) == *expected
}
