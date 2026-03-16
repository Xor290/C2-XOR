#![windows_subsystem = "windows"]

mod checksum;
mod decompress;
mod decrypt;
mod loader;
mod overlay;

fn main() {
    let file_bytes = match overlay::read_own_file() {
        Some(b) => b,
        None => std::process::exit(1),
    };

    let (header, payload) = match overlay::find_overlay(&file_bytes) {
        Some(r) => r,
        None => std::process::exit(1),
    };

    let compressed =
        match decrypt::decrypt_payload(payload, header.encryption_mode, &header.key, &header.nonce)
        {
            Some(d) => d,
            None => std::process::exit(1),
        };

    let pe_bytes = match decompress::decompress_lz4(&compressed) {
        Some(d) => d,
        None => std::process::exit(1),
    };

    unsafe {
        loader::load_and_run(&pe_bytes, loader::LoaderType::from(header.compression));
    }
}
