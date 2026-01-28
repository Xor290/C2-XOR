use super::Database;
use crate::admin::models::VictimAgentDetails;
use rusqlite::Result as SqlResult;

impl Database {
    pub fn update_victim_info(
        &self,
        agent_id: &str,
        hostname: &str,
        username: &str,
        os: &str,
        ip_address: &str,
        process_name: &str,
    ) -> SqlResult<()> {
        let conn = self.conn()?;

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
        let conn = self.conn()?;

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
        let conn = self.conn()?;

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

    pub fn log_agent_action(
        &self,
        agent_id: &str,
        action: &str,
        details: Option<&str>,
        username: Option<&str>,
    ) -> SqlResult<()> {
        let conn = self.conn()?;
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
        let conn = self.conn()?;
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
        let conn = self.conn()?;
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
}
