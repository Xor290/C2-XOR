use crate::config::{HEADER_NAME, HEADER_VALUE, USE_HTTPS, XOR_PORT, XOR_SERVER};
use std::{io::Read, path::Path};

fn base_url() -> String {
    let scheme = if USE_HTTPS { "https" } else { "http" };
    format!("{}://{}:{}", scheme, XOR_SERVER, XOR_PORT)
}

pub fn http_post(path: &str, user_agent: &str, body: &str) -> Result<String, String> {
    let url = format!("{}{}", base_url(), path);
    let response = ureq::post(&url)
        .set("User-Agent", user_agent)
        .set("Content-Type", "text/plain")
        .set(HEADER_NAME, HEADER_VALUE)
        .send_string(body)
        .map_err(|e| e.to_string())?;

    response.into_string().map_err(|e| e.to_string())
}

pub fn http_get(path: &str, user_agent: &str) -> Result<String, String> {
    let url = format!("{}{}", base_url(), path);
    let response = ureq::get(&url)
        .set("User-Agent", user_agent)
        .set(HEADER_NAME, HEADER_VALUE)
        .call()
        .map_err(|e| e.to_string())?;

    response.into_string().map_err(|e| e.to_string())
}

pub fn http_post_file(
    path: &Path,
    user_agent: &str,
    body: &[u8],
    endpoint: &str,
) -> Result<String, String> {
    let url = format!("{}{}", base_url(), endpoint);
    let response = ureq::post(&url)
        .set("User-Agent", user_agent)
        .set("Content-Type", "application/octet-stream")
        .set(
            "X-Filename",
            path.file_name().and_then(|n| n.to_str()).unwrap_or(""),
        )
        .send_bytes(body)
        .map_err(|e| e.to_string())?;

    response.into_string().map_err(|e| e.to_string())
}
