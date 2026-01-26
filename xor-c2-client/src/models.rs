use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginResponse {
    pub success: bool,
    pub token: Option<String>,
    pub message: String,
}

#[derive(Serialize)]
pub struct TaskCommand {
    pub agent_id: String,
    pub command: String,
}

#[derive(Deserialize)]
pub struct ApiResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Deserialize, Clone)]
pub struct AgentDto {
    pub agent_id: String,
    pub hostname: Option<String>,
    pub username: Option<String>,
    pub process_name: Option<String>,
    pub ip: Option<String>,
    pub last_seen: u64,
    pub payload_type: String,
    pub listener_name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
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

#[derive(Serialize)]
pub struct GenerateAgentRequest {
    pub listener_name: String,
    pub payload_type: String,
    pub config: AgentConfig,
}

#[derive(Clone, Debug)]
pub struct Agent {
    pub id: String,
    pub hostname: Option<String>,
    pub username: Option<String>,
    pub process_name: Option<String>,
    pub ip: Option<String>,
    pub last_seen: Option<String>,
    pub payload_type: String,
    pub listener_name: String,
}

#[derive(Clone, Debug)]
pub struct CommandResult {
    pub timestamp: String,
    pub is_command: bool,
    pub content: String,
    pub result_id: Option<i64>,
    pub is_file: bool,
}

#[derive(Clone, Debug)]
pub struct GenerateAgentDialog {
    pub is_open: bool,
    pub listener_name: String,
    pub payload_type: String,
    pub status_message: String,
    pub is_generating: bool,

    pub host: String,
    pub port: u16,
    pub uri_path: String,
    pub user_agent: String,
    pub xor_key: String,
    pub beacon_interval: u32,
    pub anti_vm: bool,
    pub headers: Vec<(String, String)>,
}

#[derive(Clone, Debug)]
pub struct GenerateListenerDialog {
    pub is_open: bool,
    pub listener_name: String,
    pub listener_type: String,
    pub listener_ip: String,
    pub listener_port: u16,
    pub uri_paths: String,
    pub user_agent: String,
    pub xor_key: String,
    pub headers: Vec<(String, String)>,
    pub status_message: String,
}

#[derive(Serialize)]
pub struct ListenerConfig {
    pub listener_name: String,
    pub listener_type: String,
    pub listener_ip: String,
    pub listener_port: u16,
    pub xor_key: String,
    pub user_agent: String,
    pub uri_paths: String,
    pub headers: Vec<(String, String)>,
}
