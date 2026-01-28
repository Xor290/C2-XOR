use super::Database;
use chrono::Utc;
use rusqlite::Result as SqlResult;

impl Database {
    pub fn verify_user(&self, username: &str, password: &str) -> SqlResult<bool> {
        let conn = self.conn()?;

        let password_hash: String = match conn.query_row(
            "SELECT password_hash FROM users WHERE username = ?1",
            [username],
            |row| row.get(0),
        ) {
            Ok(hash) => hash,
            Err(_) => return Ok(false),
        };

        match bcrypt::verify(password, &password_hash) {
            Ok(valid) => {
                if valid {
                    let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
                    let _ = conn.execute(
                        "UPDATE users SET last_login = ?1 WHERE username = ?2",
                        rusqlite::params![now, username],
                    );
                }
                Ok(valid)
            }
            Err(_) => Ok(false),
        }
    }

    pub fn store_session(
        &self,
        token: &str,
        username: &str,
        expires_at: &str,
        ip: Option<&str>,
    ) -> SqlResult<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO sessions (token, username, expires_at, ip_address) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![token, username, expires_at, ip],
        )?;
        Ok(())
    }

    pub fn is_session_valid(&self, token: &str) -> bool {
        let conn = match self.conn() {
            Ok(c) => c,
            Err(_) => return false,
        };

        let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sessions WHERE token = ?1 AND expires_at > ?2)",
            rusqlite::params![token, now],
            |row| row.get(0),
        )
        .unwrap_or(false)
    }

    pub fn clean_expired_sessions(&self) -> SqlResult<usize> {
        let conn = self.conn()?;
        let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        conn.execute("DELETE FROM sessions WHERE expires_at < ?1", [&now])
    }

    pub fn delete_session(&self, token: &str) -> SqlResult<usize> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM sessions WHERE token = ?1", [token])
    }
}
