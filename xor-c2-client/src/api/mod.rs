mod agents;
mod auth;
mod files;
mod listeners;
mod results;
mod tasks;
mod utils;

pub struct ApiClient;

impl ApiClient {
    pub async fn login(server_url: &str, username: &str, password: &str) -> Result<String, String> {
        auth::login(server_url, username, password).await
    }

    pub async fn logout(server_url: &str, token: &str) -> Result<(), String> {
        auth::logout(server_url, token).await
    }

    pub async fn fetch_agents(
        server_url: &str,
        token: &str,
    ) -> Result<Vec<crate::models::Agent>, String> {
        agents::fetch_agents(server_url, token).await
    }

    pub async fn send_command(
        server_url: &str,
        token: &str,
        agent_id: &str,
        command: &str,
    ) -> Result<(), String> {
        tasks::send_command(server_url, token, agent_id, command).await
    }

    pub async fn generate_agent_with_config(
        server_url: &str,
        token: &str,
        config: &crate::models::GenerateAgentDialog,
    ) -> Result<Vec<u8>, String> {
        agents::generate_agent_with_config(server_url, token, config).await
    }

    pub async fn fetch_results(
        server_url: &str,
        token: &str,
        agent_id: &str,
        save_dir: &str,
    ) -> Result<Vec<crate::models::CommandResult>, String> {
        results::fetch_results(server_url, token, agent_id, save_dir).await
    }

    pub async fn add_listener(
        server_url: &str,
        token: &str,
        config: &crate::models::GenerateListenerDialog,
    ) -> Result<String, String> {
        listeners::add_listener(server_url, token, config).await
    }
}
