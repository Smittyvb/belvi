// SPDX-License-Identifier: Apache-2.0

use axum::{routing::get, Router};

#[tokio::main]
async fn main() {
    env_logger::init();

    let app = Router::new().route("/", get(|| async { "Hello world" }));

    axum::Server::bind(&"0.0.0.0:47371".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
