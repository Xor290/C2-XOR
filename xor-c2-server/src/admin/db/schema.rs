use super::Database;
use bcrypt::{hash, DEFAULT_COST};
use rusqlite::Result as SqlResult;
use std::collections::HashMap;

use crate::admin::models::Listener;

impl Database {
    pub fn init(&self) -> SqlResult<()> {
        let conn = self.conn()?;

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
                tls_cert TEXT NOT NULL,
                tls_key TEXT NOT NULL,
                tls_cert_chain TEXT NOT NULL,
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
        let conn = self.conn()?;

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

    fn create_default_admin(&self) -> SqlResult<()> {
        let conn = self.conn()?;

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

    pub fn add_default_listener(&self) -> SqlResult<()> {
        let conn = self.conn()?;

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
            "INSERT OR IGNORE INTO listeners (name, listener_type, host, port, xor_key, user_agent, uri_paths, http_headers, tls_cert, tls_key, tls_cert_chain)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, '', '', '')",
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
}
