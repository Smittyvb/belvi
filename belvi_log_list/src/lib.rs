// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod log_test;

#[cfg(test)]
mod log_list_test;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogList {
    version: String,
    log_list_timestamp: String,
    operators: Vec<LogListOperator>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogListOperator {
    name: String,
    email: Vec<String>,
    logs: Vec<Log>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Log {
    description: String,
    log_id: String,
    key: String,
    url: String,
    mmd: u32,
    state: LogState,
    temporal_interval: Option<TemporalInterval>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum LogState {
    #[serde(rename = "usable")]
    Usable { timestamp: String },

    #[serde(rename = "retired")]
    Retired { timestamp: String },

    #[serde(rename = "readonly")]
    ReadOnly {
        timestamp: String,
        final_tree_head: TreeHead,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalInterval {
    start_inclusive: String,
    end_exclusive: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeHead {
    sha256_root_hash: String,
    tree_size: u64,
}

macro_rules! api_endpoint {
    ($path:literal , $fname:ident) => {
        pub fn $fname(&self) -> String {
            format!("{}{}", self.url, concat!("ct/v1/", $path))
        }
    };
}

impl Log {
    api_endpoint!("add-chain", add_chain_url);
    api_endpoint!("add-pre-chain", add_pre_chain_url);
    api_endpoint!("get-sth", get_sth_url);
    api_endpoint!("get-sth-consistency", get_sth_consistency_url);
    api_endpoint!("get-proof-by-hash", get_proof_by_hash_url);
    api_endpoint!("get-entries", get_entries_url);
    api_endpoint!("get-roots", get_roots_url);
    api_endpoint!("get-entry-and-proof", get_entry_and_proof_url);
}
