mod agents;
mod commands;
mod listeners;
mod results;
mod schema;
mod users;

use rusqlite::{Connection, Result as SqlResult};

pub struct Database {
    pub(crate) path: String,
}

impl Database {
    pub fn new(path: &str) -> Self {
        Database {
            path: path.to_string(),
        }
    }

    pub(crate) fn conn(&self) -> SqlResult<Connection> {
        Connection::open(&self.path)
    }
}
