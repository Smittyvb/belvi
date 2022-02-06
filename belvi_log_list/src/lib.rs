// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod log_test;

#[cfg(test)]
mod log_list_test;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LogList {
    version: String,
    log_list_timestamp: String,
    operators: Vec<LogListOperator>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LogListOperator {
    name: String,
    email: Vec<String>,
    logs: Vec<Log>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Log {
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
struct TemporalInterval {
    start_inclusive: String,
    end_exclusive: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TreeHead {
    sha256_root_hash: String,
    tree_size: u64,
}
