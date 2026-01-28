use super::Database;
use crate::admin::models::ResultDetail;
use rusqlite::Result as SqlResult;

impl Database {
    pub fn store_result(
        &self,
        agent_id: &str,
        command_id: Option<i64>,
        output: &str,
        success: bool,
        result_type: Option<&str>,
    ) -> SqlResult<i64> {
        let conn = self.conn()?;

        let result_type = result_type.unwrap_or("text");

        let mut filename: Option<String> = None;

        if let Some(cmd_id) = command_id {
            if let Ok(Some(cmd_str)) = self.get_command_by_id(cmd_id) {
                if let Some(parsed_filename) = Self::extract_filename_from_command(&cmd_str) {
                    filename = Some(parsed_filename);
                    log::info!(
                        "[DB] Extracted filename from command {}: {:?}",
                        cmd_id,
                        filename
                    );
                }
            }
        }

        conn.execute(
            "INSERT INTO results (agent_id, command_id, output, success, types, filename) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![agent_id, command_id, output, success, result_type, filename],
        )?;

        let result_id = conn.last_insert_rowid();

        if let Some(cmd_id) = command_id {
            if success {
                self.mark_command_completed(cmd_id)?;
            } else {
                self.mark_command_failed(cmd_id)?;
            }
        }

        log::info!(
            "[+] Result stored (Base64) for agent {} (command_id: {:?}, success: {}, types: {}, filename: {:?}, result_id: {}, length: {})",
            agent_id, command_id, success, result_type, filename, result_id, output.len()
        );

        Ok(result_id)
    }

    pub fn extract_filename_from_command(command: &str) -> Option<String> {
        let trimmed = command.trim().trim_matches(|c| c == '{' || c == '}');

        if !trimmed.contains("download") && !trimmed.contains("upload") {
            return None;
        }

        let colon_pos = trimmed.find(':')?;

        let after_colon = &trimmed[colon_pos + 1..].trim();

        let filename = after_colon
            .trim_matches(|c| c == '\'' || c == '"' || c == ' ')
            .to_string();

        if !filename.is_empty() {
            Some(filename)
        } else {
            None
        }
    }

    pub fn extract_filename_from_command_id(&self, command_id: i64) -> Option<String> {
        match self.get_command_by_id(command_id) {
            Ok(Some(cmd_str)) => Self::extract_filename_from_command(&cmd_str),
            _ => None,
        }
    }

    pub fn get_result_by_id(&self, result_id: i64) -> SqlResult<Option<ResultDetail>> {
        let conn = self.conn()?;

        match conn.query_row(
            "SELECT id, agent_id, command_id, output, success, received_at, types, filename
            FROM results
            WHERE id = ?1",
            [result_id],
            |row| {
                Ok(ResultDetail {
                    id: row.get(0)?,
                    agent_id: row.get(1)?,
                    command_id: row.get(2)?,
                    output: row.get(3)?,
                    success: row.get(4)?,
                    received_at: row.get(5)?,
                    r#types: row.get(6).ok(),
                    filename: row.get(7).ok(),
                })
            },
        ) {
            Ok(result) => Ok(Some(result)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn get_agent_results(
        &self,
        agent_id: &str,
    ) -> SqlResult<Vec<(i64, Option<i64>, String, bool, String, String)>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, command_id, output, success, types, received_at FROM results
            WHERE agent_id = ?1
            ORDER BY received_at DESC",
        )?;

        let results = stmt
            .query_map([agent_id], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(results)
    }

    pub fn get_upload_data_for_command(&self, command_id: i64) -> SqlResult<Option<String>> {
        let conn = self.conn()?;

        match conn.query_row(
            "SELECT output FROM results
            WHERE command_id = ?1 AND types = 'file_upload'
            ORDER BY received_at DESC LIMIT 1",
            [command_id],
            |row| row.get(0),
        ) {
            Ok(data) => {
                log::debug!("[DB] Upload data found for command {}", command_id);
                Ok(Some(data))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                log::debug!("[DB] No upload data found for command {}", command_id);
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}
