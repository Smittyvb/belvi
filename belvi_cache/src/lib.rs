// SPDX-License-Identifier: Apache-2.0
use std::{fmt, pin::Pin};

use redis::aio::AsyncStream;

pub struct Connection {
    inner: redis::aio::Connection<Pin<Box<dyn AsyncStream + Send + Sync>>>,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("inner", &"[redis connection]".to_string())
            .finish()
    }
}

impl Connection {
    pub async fn new() -> Self {
        let client = redis::Client::open("redis://127.0.0.1/").unwrap();
        let con = client.get_tokio_connection().await.unwrap();
        Self {
            inner: con,
        }
    }
}
