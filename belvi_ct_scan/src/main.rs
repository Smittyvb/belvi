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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let google_log = LogList::google();
    let argon2021 = &google_log.operators[0].logs[0];
    let resp = reqwest::get(argon2021.get_sth_url())
        .await?
        .json::<LogSth>()
        .await?;
    println!("{:#?}", resp);
    Ok(())
}
