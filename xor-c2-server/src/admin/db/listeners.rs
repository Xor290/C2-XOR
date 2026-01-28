use super::Database;
use crate::admin::models::{Listener, ListenerHttps};
use rusqlite::Result as SqlResult;
use std::collections::HashMap;

impl Database {
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
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO listeners (name, listener_type, host, port, xor_key, user_agent, uri_paths, http_headers, tls_cert, tls_key, tls_cert_chain)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, '', '', '')",
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

    pub fn add_listener_https(
        &self,
        name: &str,
        listener_type: &str,
        host: &str,
        port: u16,
        xor_key: &str,
        user_agent: &str,
        uri_paths: &str,
        http_headers: &str,
        tls_cert: &str,
        tls_key: &str,
        tls_cert_chain: &str,
    ) -> SqlResult<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO listeners (name, listener_type, host, port, xor_key, user_agent, uri_paths, http_headers, tls_cert, tls_key, tls_cert_chain)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                name,
                listener_type,
                host,
                port,
                xor_key,
                user_agent,
                uri_paths,
                http_headers,
                tls_cert,
                tls_key,
                tls_cert_chain
            ],
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
        let conn = self.conn()?;

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
        let conn = self.conn()?;
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

    pub fn get_listeners_https(&self) -> SqlResult<Vec<ListenerHttps>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT name, listener_type, host, port, xor_key, user_agent, uri_paths, http_headers, tls_cert, tls_key, tls_cert_chain
             FROM listeners
             WHERE listener_type = 'https'"
        )?;

        let rows = stmt.query_map([], |row| {
            let http_headers_str: String = row.get(7)?;
            let http_headers: HashMap<String, String> =
                serde_json::from_str(&http_headers_str).unwrap_or_else(|_| HashMap::new());

            Ok(ListenerHttps {
                name: row.get(0)?,
                listener_type: row.get(1)?,
                host: row.get(2)?,
                port: row.get(3)?,
                xor_key: row.get(4)?,
                user_agent: row.get(5)?,
                uri_paths: row.get(6)?,
                http_headers,
                tls_cert: row.get(8)?,
                tls_key: row.get(9)?,
                tls_cert_chain: row.get(10)?,
            })
        })?;

        rows.collect()
    }
}
