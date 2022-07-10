// SPDX-License-Identifier: Apache-2.0
use redis::{aio::AsyncStream, Cmd};
use std::{fmt, pin::Pin};

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
        Self { inner: con }
    }

    pub async fn get_cert(&mut self, id: &[u8]) -> Option<Vec<u8>> {
        match Cmd::get(id).query_async(&mut self.inner).await {
            Ok(v) => v,
            Err(e) => panic!("TODO: handle cache miss: {:#?}", e),
        }
    }
}
