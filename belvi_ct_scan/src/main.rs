// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::cmp;

use belvi_log_list::{Log, LogList};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LogSth {
    tree_size: u64,
    timestamp: u64,
    sha256_root_hash: String,
    tree_head_signature: String,
}

impl PartialOrd for LogSth {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.tree_size.partial_cmp(&other.tree_size)
    }
}

impl Ord for LogSth {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.tree_size.cmp(&other.tree_size)
    }
}

struct Fetcher {
    client: reqwest::Client,
}

impl Fetcher {
    fn new() -> Self {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "From",
            reqwest::header::HeaderValue::from_static("belvi@smitop.com"),
        );
        Self {
            client: reqwest::Client::builder()
                .user_agent("belvi/0.1 (belvi@smitop.com)")
                .default_headers(headers)
                .brotli(true)
                .gzip(true)
                .https_only(true)
                .build()
                .unwrap(),
        }
    }
    async fn fetch_sth(&self, log: &Log) -> Result<LogSth, reqwest::Error> {
        self.client
            .get(log.get_sth_url())
            .send()
            .await?
            .json()
            .await
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let google_log = LogList::google();
    let argon2021 = &google_log.operators[0].logs[0];
    let fetcher = Fetcher::new();
    let resp = fetcher.fetch_sth(argon2021).await?;
    println!("{:#?}", resp);
    Ok(())
}
