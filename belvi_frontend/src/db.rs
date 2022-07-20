// SPDX-License-Identifier: Apache-2.0
use rusqlite::{Connection, OpenFlags};
use std::{env, path::PathBuf};

fn get_data_path() -> PathBuf {
    let mut args = env::args_os();
    args.nth(1).unwrap().into()
}

pub fn connect() -> Connection {
    let db_path = get_data_path().join("data.db");
    // OPEN_CREATE isn't passed, so we don't create the DB if it doesn't exist
    let mut db = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    crate::exts::register(&mut db);
    db
}
