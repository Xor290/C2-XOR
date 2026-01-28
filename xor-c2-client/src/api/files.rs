use std::fs;
use std::path::Path;
use std::time::Duration;

pub async fn download_result_file(
    server_url: &str,
    token: &str,
    result_id: Option<i64>,
    save_dir: &str,
) -> Result<String, String> {
    let id = result_id.ok_or("No result ID provided")?;
    let url = format!("{}/api/download/{}", server_url, id);

    println!("📡 Downloading from: {}", url);

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .bearer_auth(token)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Request error: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let error_body = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(format!("Download failed ({}) - {}", status, error_body));
    }

    let filename = response
        .headers()
        .get(reqwest::header::CONTENT_DISPOSITION)
        .and_then(|h| h.to_str().ok())
        .and_then(|v| {
            if let Some(start) = v.find("filename=") {
                let filename_part = &v[start + 9..];
                let clean = filename_part
                    .trim_matches(|c| c == '"' || c == '\'' || c == ' ')
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .to_string();
                if !clean.is_empty() {
                    Some(clean)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .unwrap_or_else(|| format!("download_{}.bin", id));

    println!("📝 Filename: {}", filename);

    let bytes = response.bytes().await.map_err(|e| e.to_string())?;

    println!("📦 File size: {} bytes", bytes.len());

    fs::create_dir_all(save_dir).map_err(|e| format!("Failed to create directory: {}", e))?;
    let path = Path::new(save_dir).join(&filename);

    fs::write(&path, &bytes).map_err(|e| format!("Failed to write file: {}", e))?;

    println!("✅ File saved to: {}", path.display());

    Ok(path.display().to_string())
}
