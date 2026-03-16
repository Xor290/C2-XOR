use anyhow::Result;
use lz4_flex::compress_prepend_size;

pub struct CompressResult {
    pub compressed: Vec<u8>,
    pub original_size: usize,
}

pub fn compress_payload(data: &[u8]) -> Result<CompressResult> {
    let original_size = data.len();
    let compressed = compress_prepend_size(data);
    Ok(CompressResult { compressed, original_size })
}
