use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ListenerProfile {
    pub name: String,
    pub host: String,
    pub listener_type: String,
    pub port: u16,
    pub user_agent: String,
    pub xor_key: String,
    pub uri_paths: String,
    pub http_headers: HashMap<String, String>,
}

impl ListenerProfile {
    pub fn from_db(listener: crate::admin::models::Listener) -> Self {
        Self {
            name: listener.name,
            host: listener.host,
            listener_type: listener.listener_type,
            port: listener.port,
            user_agent: listener.user_agent,
            xor_key: listener.xor_key,
            uri_paths: listener.uri_paths, 
            http_headers: listener.http_headers,
        }
    }
}
