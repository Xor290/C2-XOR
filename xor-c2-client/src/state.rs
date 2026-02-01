use crate::models::*;
use std::sync::Arc;
use std::time::Instant;

impl Default for GenerateAgentDialog {
    fn default() -> Self {
        Self {
            is_open: false,
            listener_name: "default".to_string(),
            payload_type: "exe".to_string(),
            status_message: String::new(),
            is_generating: false,
            host: "localhost".to_string(),
            port: 8088,
            uri_path: "/api/update".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            xor_key: "mysupersecretkey".to_string(),
            beacon_interval: 5,
            anti_vm: true,
            anti_debug: true,
            headers: vec![
                ("Accept".to_string(), "*/*".to_string()),
                ("Cache-Control".to_string(), "no-cache".to_string()),
            ],
        }
    }
}

impl Default for GenerateListenerDialog {
    fn default() -> Self {
        Self {
            is_open: false,
            listener_name: "default".to_string(),
            listener_type: "http".to_string(),
            listener_ip: "0.0.0.0".to_string(),
            listener_port: 80,
            uri_paths: "/api/update".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            xor_key: "mysupersecretkey".to_string(),
            headers: vec![
                ("Accept".to_string(), "*/*".to_string()),
                ("Cache-Control".to_string(), "no-cache".to_string()),
            ],
            status_message: String::new(),
        }
    }
}

pub struct C2Client {
    // Configuration
    pub server_url: String,

    // Authentication
    pub username: String,
    pub password: String,
    pub token: Option<String>,
    pub is_authenticated: bool,
    pub login_error: String,

    // Agents
    pub agents: Vec<Agent>,
    pub selected_agent: Option<Agent>,

    // Commands & Results
    pub command_input: String,
    pub results: Vec<CommandResult>,
    pub command_error: String,

    // Generate Agent Dialog
    pub generate_dialog: GenerateAgentDialog,

    pub generate_listener_dialog: GenerateListenerDialog,
    // UI State
    pub auto_refresh: bool,
    pub loading: bool,
    pub last_refresh: Instant,

    // Runtime
    pub rt: Arc<tokio::runtime::Runtime>,
}

impl Default for C2Client {
    fn default() -> Self {
        Self {
            server_url: "http://localhost:8088".to_string(),
            username: "admin".to_string(),
            password: String::new(),
            token: None,
            is_authenticated: false,
            login_error: String::new(),
            agents: Vec::new(),
            selected_agent: None,
            command_input: String::new(),
            results: Vec::new(),
            command_error: String::new(),
            generate_dialog: GenerateAgentDialog::default(),
            generate_listener_dialog: GenerateListenerDialog::default(),
            auto_refresh: true,
            loading: false,
            last_refresh: Instant::now(),
            rt: Arc::new(tokio::runtime::Runtime::new().unwrap()),
        }
    }
}

// Fonction utilitaire pour obtenir l'extension de fichier
pub fn get_file_extension(payload_type: &str) -> &str {
    match payload_type.to_lowercase().as_str() {
        "exe" => "exe",
        "dll" => "dll",
        "elf" => "elf",
        "macho" => "macho",
        "shellcode" => "bin",
        _ => "bin",
    }
}
