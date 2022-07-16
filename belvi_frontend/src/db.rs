// SPDX-License-Identifier: Apache-2.0
use rusqlite::Connection;
use std::{env, path::PathBuf};

// SPDX-License-Identifier: Apache-2.0
fn get_data_path() -> PathBuf {
    let mut args = env::args_os();
    args.nth(1).unwrap().into()
}

pub fn connect() -> Connection {
    let db_path = get_data_path().join("data.db");
    // OPEN_CREATE isn't passed, so we don't create the DB if it doesn't exist
    let mut db = Connection::open(db_path).unwrap();
    // this can write to the database so we can't open it as readonly
    db.execute_batch(include_str!("../../shared_sql/init_db.sql"))
        .unwrap();
    crate::exts::register(&mut db);
    db
}
