use crate::admin::cert_generator;
use crate::admin::models::{ApiResponse, GenerateListenerRequest};
use crate::admin::routes::AppState;
use actix_web::{
    post,
    web::{Data, Json},
    HttpRequest, HttpResponse, Responder,
};

#[post("/api/add/listener")]
pub async fn add_listener(
    state: Data<AppState>,
    body: Json<GenerateListenerRequest>,
    req: HttpRequest,
) -> impl Responder {
    if let Err(e) = state.jwt_manager.authenticate(&req, &state.database) {
        return HttpResponse::Unauthorized().json(ApiResponse {
            success: false,
            message: e.to_string(),
        });
    }

    let headers_json = serde_json::to_string(&body.headers).unwrap_or_default();

    if body.listener_type == "https" {
        return add_https_listener(&state, &body, &headers_json);
    }

    add_http_listener(&state, &body, &headers_json)
}

fn add_https_listener(
    state: &Data<AppState>,
    body: &GenerateListenerRequest,
    headers_json: &str,
) -> HttpResponse {
    let (tls_cert, tls_key, tls_cert_chain, cert_auto_generated) = if body.tls_cert.is_empty()
        || body.tls_key.is_empty()
    {
        log::info!(
            "[*] No certificate provided, generating self-signed certificate for '{}'",
            body.listener_name
        );

        match cert_generator::generate_cert_for_listener(&body.listener_name, &body.listener_ip) {
            Ok(generated) => {
                log::info!(
                    "[+] Self-signed certificate generated for listener '{}'",
                    body.listener_name
                );
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

    let port = 443;

    if let Err(e) = state.database.add_listener_https(
        &body.listener_name,
        &body.listener_type,
        &body.listener_ip,
        port,
        &body.xor_key,
        &body.user_agent,
        &body.uri_paths,
        headers_json,
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
        port,
        cert_info
    );

    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": format!(
            "HTTPS Listener '{}' added successfully{}. Restart server to activate.",
            body.listener_name,
            cert_info
        ),
        "cert_auto_generated": cert_auto_generated
    }))
}

fn add_http_listener(
    state: &Data<AppState>,
    body: &GenerateListenerRequest,
    headers_json: &str,
) -> HttpResponse {
    if let Err(e) = state.database.add_listener(
        &body.listener_name,
        &body.listener_type,
        &body.listener_ip,
        body.listener_port,
        &body.xor_key,
        &body.user_agent,
        &body.uri_paths,
        headers_json,
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
