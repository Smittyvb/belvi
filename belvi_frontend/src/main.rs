// SPDX-License-Identifier: Apache-2.0

use axum::{
    http::StatusCode,
    response::{Headers, IntoResponse},
    routing::get,
    Router,
};
use rusqlite::{Connection, OpenFlags};
use std::{env, path::PathBuf};

const PRODUCT_NAME: &str = "Belvi";

// TODO: use tokio::task_local instead?
thread_local! {
    static DB_CONN: Connection = {
        let mut args = env::args_os();
        let data_path: PathBuf = args.nth(1).unwrap().into();
        let db_path = data_path.join("data.db");
        // OPEN_CREATE isn't passed, so we don't create the DB if it doesn't exist
        Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap()
    };
}

async fn get_root() -> impl IntoResponse {
    DB_CONN.with(|db| {
        let count: usize = db
            .prepare_cached("SELECT count(domain) FROM domains")
            .unwrap()
            .query_row([], |row| row.get(0))
            .unwrap();
        (
            StatusCode::OK,
            Headers([
                ("Server", "belvi_frontend/1.0"),
                ("Content-Type", "text/html"),
            ]),
            format!(
                include_str!("tmpl/base.html"),
                title = PRODUCT_NAME,
                product_name = PRODUCT_NAME,
                content = format_args!("{} certs", count)
            ),
        )
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
