// SPDX-License-Identifier: Apache-2.0

use axum::{routing::get, Router};
use log::info;
use rusqlite::{Connection, OpenFlags};
use std::{env, path::PathBuf};

#[tokio::main]
async fn main() {
    env_logger::init();

    let mut args = env::args_os();
    let data_path: PathBuf = args.nth(1).unwrap().into();
    let db_path = data_path.clone().join("data.db");
    // OPEN_CREATE isn't passed, so we don't create the DB if it doesn't exist
    let db_conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();

    let count: usize = db_conn
        .query_row("SELECT count(domain) FROM domains", [], |row| row.get(0))
        .unwrap();
    info!("Currently {} certs", count);

    let app = Router::new().route("/", get(|| async { "Hello world" }));

    axum::Server::bind(&"0.0.0.0:47371".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
