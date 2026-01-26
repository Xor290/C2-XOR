mod admin;
mod agents;
mod config;
mod encryption;
mod listener;

use crate::admin::Database;
use crate::listener::ListenerProfile;
use admin::admin_server;
use agents::agent_handler::AgentHandler;
use listener::http_listener;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    log::info!("===========================================");
    log::info!("    XOR C2 Teamserver v0.1.0");
    log::info!("===========================================");
    log::info!("[+] Starting Teamserver...");

    // --------- Load configuration ---------
    let config = match config::Config::load("config/config.json") {
        Ok(cfg) => {
            log::info!("[+] Configuration loaded successfully");
            cfg
        }
        Err(e) => {
            log::error!("[!] Failed to load configuration: {}", e);
            return;
        }
    };

    // --------- Initialize database ---------
    let db = Arc::new(Database::new("xor_c2.db"));
    if let Err(e) = db.init() {
        log::error!("[!] Failed to initialize database: {}", e);
        return;
    }
    if let Err(e) = db.add_default_listener() {
        log::error!("[!] Failed to add default listener: {}", e);
    }

    // --------- Initialize agent handler ---------
    let agent_handler = AgentHandler::new();
    log::info!("[+] Agent handler initialized");

    // --------- Load listeners from DB ---------
    let listeners = match db.get_listeners() {
        Ok(list) => {
            log::info!("[+] Loaded {} listener(s) from database", list.len());
            list
        }
        Err(e) => {
            log::error!("[!] Failed to load listeners from DB: {}", e);
            return;
        }
    };

    let mut listener_handles = Vec::new();

    for listener in listeners {
        if listener.listener_type.to_lowercase() == "http" {
            log::info!(
                "[+] Starting HTTP listener '{}' on {}:{}",
                listener.name,
                listener.host,
                listener.port
            );

            let handler = agent_handler.clone();
            let db_clone = Arc::clone(&db);
            let listener_clone = listener.clone();

            let listener_profile = ListenerProfile {
                name: listener_clone.name,
                host: listener_clone.host,
                listener_type: listener_clone.listener_type,
                port: listener_clone.port,
                user_agent: listener_clone.user_agent,
                xor_key: listener_clone.xor_key,
                uri_paths: listener_clone.uri_paths,
                http_headers: listener_clone.http_headers,
            };

            let handle = tokio::spawn(async move {
                http_listener::start(listener_profile, handler, db_clone).await;
            });

            listener_handles.push(handle);
        }
    }

    // --------- Start admin server ---------
    let admin_port = config.get_server_port();
    log::info!("[+] Starting admin server on port {}", admin_port);

    let config_clone = config.clone();
    let agent_clone = agent_handler.clone();

    let admin_handle = std::thread::spawn(move || {
        actix_web::rt::System::new()
            .block_on(async { admin_server::start(config_clone, agent_clone).await });
    });

    log::info!("===========================================");
    log::info!("[+] Teamserver is fully operational");
    log::info!("===========================================");

    // --------- Wait for all listener tasks ---------
    for handle in listener_handles {
        let _ = handle.await;
    }

    // --------- Wait for admin server thread ---------
    let _ = admin_handle.join();

    log::info!("[+] Teamserver shutting down...");
}
