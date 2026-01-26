// src/admin/mod.rs

pub mod auth;
pub mod command_formatter;
pub mod db;
pub mod error;
pub mod models;
pub mod routes; // ← AJOUTER CETTE LIGNE

pub use db::Database; // ← AJOUTER CETTE LIGNE

pub mod admin_server {
    use crate::agents::agent_handler::AgentHandler;
    use crate::config::Config;

    pub async fn start(config: Config, agent_handler: AgentHandler) {
        super::routes::start_server(config, agent_handler).await;
    }
}
