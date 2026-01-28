use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};

pub fn decode_base64_if_needed(input: &str) -> String {
    match STANDARD.decode(input) {
        Ok(bytes) => match String::from_utf8(bytes.clone()) {
            Ok(text) => {
                println!(
                    "✅ Base64 décodé en UTF-8: {} chars -> {} chars",
                    input.len(),
                    text.len()
                );
                text
            }
            Err(_) => match encoding_rs::WINDOWS_1252.decode(&bytes) {
                (text, _, false) => {
                    println!(
                        "✅ Base64 décodé en Windows-1252: {} chars -> {} chars",
                        input.len(),
                        text.len()
                    );
                    text.into_owned()
                }
                _ => {
                    let lossy_text = String::from_utf8_lossy(&bytes);
                    println!(
                        "⚠️  Base64 décodé avec perte: {} chars -> {} chars",
                        input.len(),
                        lossy_text.len()
                    );
                    lossy_text.into_owned()
                }
            },
        },
        Err(_) => {
            println!(
                "⚠️  Pas du Base64, gardant l'original: {} chars",
                input.len()
            );
            input.to_string()
        }
    }
}

pub fn format_timestamp(timestamp: u64) -> String {
    let dt = DateTime::<Utc>::from_timestamp(timestamp as i64, 0).unwrap_or_else(|| Utc::now());
    dt.format("%Y-%m-%d %H:%M:%S").to_string()
}
