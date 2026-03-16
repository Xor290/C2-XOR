use lz4_flex::decompress_size_prepended;

pub fn decompress_lz4(data: &[u8]) -> Option<Vec<u8>> {
    decompress_size_prepended(data).ok()
}
