use crate::models;
use std::time::Duration;

pub async fn fetch_results(
    server_url: &str,
    token: &str,
    agent_id: &str,
    save_dir: &str,
) -> Result<Vec<models::CommandResult>, String> {
    let url = format!("{}/api/results/{}", server_url, agent_id);
    let client = reqwest::Client::new();

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| format!("Fetch results error: {}", e))?;

    let results: Vec<serde_json::Value> = response
        .json()
        .await
        .map_err(|e| format!("Parse results error: {}", e))?;

    let mut processed_results = Vec::new();

    for r in results {
        let raw_content = r
            .get("output")
            .or_else(|| r.get("content"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let timestamp = r
            .get("received_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let result_type = r.get("types").and_then(|v| v.as_str()).unwrap_or("text");
        let result_id = r.get("id").and_then(|v| v.as_i64());

        let is_command = result_type == "command";

        let is_downloadable_file = result_type == "file";
        let is_upload_confirmation = result_type == "upload_file";

        println!(
            "Frontend Debug - type: {}, downloadable: {}, upload_confirm: {}",
            result_type, is_downloadable_file, is_upload_confirmation
        );

        if is_downloadable_file {
            if let Some(id) = result_id {
                println!("Frontend Debug - FICHIER À TÉLÉCHARGER détecté! ID: {}", id);

                match super::files::download_result_file(server_url, token, Some(id), save_dir)
                    .await
                {
                    Ok(path) => {
                        println!("✅ Fichier téléchargé: {}", path);
                        processed_results.push(models::CommandResult {
                            timestamp,
                            is_command,
                            content: format!("📥 File downloaded: {}", path),
                            result_id: Some(id),
                            is_file: true,
                        });
                        continue;
                    }
                    Err(e) => {
                        eprintln!("❌ Erreur téléchargement: {}", e);
                        processed_results.push(models::CommandResult {
                            timestamp,
                            is_command,
                            content: format!("❌ Download failed: {}", e),
                            result_id: Some(id),
                            is_file: true,
                        });
                        continue;
                    }
                }
            }
        }

        let content = if is_upload_confirmation {
            println!("✅ Confirmation d'upload détectée");
            super::utils::decode_base64_if_needed(&raw_content)
        } else {
            super::utils::decode_base64_if_needed(&raw_content)
        };

        processed_results.push(models::CommandResult {
            timestamp,
            is_command,
            content,
            result_id,
            is_file: is_downloadable_file,
        });
    }

    Ok(processed_results)
}
