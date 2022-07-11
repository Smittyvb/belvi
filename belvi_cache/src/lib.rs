// SPDX-License-Identifier: Apache-2.0
use log::trace;
use redis_async::{client::paired, resp_array};
use std::fmt;

pub struct Connection {
    inner: paired::PairedConnection,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("inner", &"[redis connection]".to_string())
            .finish()
    }
}

const OBJECT_PREFIX: &[u8] = b"o:";

impl Connection {
    pub async fn new() -> Self {
        let client = paired::paired_connect("127.0.0.1:6379").await.unwrap();
        Self { inner: client }
    }

    pub async fn get_cert(&mut self, id: &[u8]) -> Option<Vec<u8>> {
        self.inner
            .send(resp_array!["GET", [OBJECT_PREFIX, id].concat()])
            .await
            .unwrap()
    }

    pub fn new_cert(&mut self, id: &[u8], content: &[u8]) {
        trace!("adding cert to Redis: {:?}, {} bytes", id, content.len());
        self.inner
            .send_and_forget(resp_array!["SET", [OBJECT_PREFIX, id].concat(), content]);
        trace!("added cert to Redis: {:?}, {} bytes", id, content.len());
    }
}
