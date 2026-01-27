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

#[derive(Debug, Clone)]
pub struct ListenerProfileHttps {
    pub name: String,
    pub host: String,
    pub listener_type: String,
    pub port: u16,
    pub user_agent: String,
    pub xor_key: String,
    pub uri_paths: String,
    pub http_headers: HashMap<String, String>,
    pub tls_cert: String,
    pub tls_key: String,
    pub tls_cert_chain: String,
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

impl ListenerProfileHttps {
    pub fn from_db(listernerHttps: crate::admin::models::ListenerHttps) -> Self {
        Self {
            name: listernerHttps.name,
            host: listernerHttps.host,
            listener_type: listernerHttps.listener_type,
            port: listernerHttps.port,
            user_agent: listernerHttps.user_agent,
            xor_key: listernerHttps.xor_key,
            uri_paths: listernerHttps.uri_paths,
            http_headers: listernerHttps.http_headers,
            tls_cert: listernerHttps.tls_cert,
            tls_key: listernerHttps.tls_key,
            tls_cert_chain: listernerHttps.tls_cert_chain,
        }
    }
}
