// SPDX-License-Identifier: Apache-2.0

use axum::{routing::get, Router};
use rusqlite::{Connection, OpenFlags};
use std::{env, path::PathBuf};

// TODO: use tokio::task_local instead?
thread_local! {
    static DB_CONN: Connection = {
        let mut args = env::args_os();
        let data_path: PathBuf = args.nth(1).unwrap().into();
        let db_path = data_path.clone().join("data.db");
        // OPEN_CREATE isn't passed, so we don't create the DB if it doesn't exist
        Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap()
    };
}

async fn get_root() -> String {
    DB_CONN.with(|db| {
        let count: usize = db
            .query_row("SELECT count(domain) FROM domains", [], |row| row.get(0))
            .unwrap();
        format!("Currently {} certs", count)
    })
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    env_logger::init();

    let app = Router::new().route("/", get(get_root));

    axum::Server::bind(&"0.0.0.0:47371".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}