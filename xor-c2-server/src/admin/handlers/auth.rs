use crate::admin::models::{ApiResponse, HealthResponse, LoginRequest, LoginResponse};
use crate::admin::routes::AppState;
use actix_web::{get, post, web::Data, web::Json, HttpRequest, HttpResponse, Responder};

#[get("/health")]
pub async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(HealthResponse {
        status: "ok".to_string(),
        service: "xor-c2".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

#[post("/api/login")]
pub async fn login(
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
pub async fn logout(state: Data<AppState>, req: HttpRequest) -> impl Responder {
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
