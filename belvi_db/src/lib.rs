// SPDX-License-Identifier: Apache-2.0
use log::debug;
use rusqlite::{Connection, OpenFlags};
use std::{env, path::PathBuf};

mod exts;

fn get_data_path() -> PathBuf {
    let mut args = env::args_os();
    args.nth(1).unwrap().into()
}

pub fn connect_readonly() -> Connection {
    let db_path = get_data_path().join("data.db");
    // OPEN_CREATE isn't passed, so we don't create the DB if it doesn't exist
    let mut db = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    exts::register(&mut db);
    db
}

pub fn connect() -> Connection {
    let db_path = get_data_path().join("data.db");
    let mut db = Connection::open(db_path).unwrap();
    exts::register(&mut db);
    debug!("SQLite version is {}", rusqlite::version());
    db.execute_batch(include_str!("init_db.sql")).unwrap();
    db
}
