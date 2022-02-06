// SPDX-License-Identifier: Apache-2.0

use std::cmp;
use serde::{Serialize, Deserialize};

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
    let resp = reqwest::get("https://ct.googleapis.com/logs/argon2021/ct/v1/get-sth")
        .await?
        .json::<LogSth>()
        .await?;
    println!("{:#?}", resp);
    Ok(())
}


