// SPDX-License-Identifier: Apache-2.0
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod log_test;

#[cfg(test)]
mod log_list_test;

type TreeSize = u64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogList {
    pub version: String,
    pub log_list_timestamp: String,
    pub operators: Vec<LogListOperator>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogListOperator {
    pub name: String,
    pub email: Vec<String>,
    pub logs: Vec<Log>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Log {
    pub description: String,
    pub log_id: String,
    pub key: String,
    pub url: String,
    pub mmd: u32,
    pub state: LogState,
    pub temporal_interval: Option<TemporalInterval>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogState {
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
    pub start_inclusive: String,
    pub end_exclusive: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeHead {
    pub sha256_root_hash: String,
    pub tree_size: TreeSize,
}

macro_rules! api_endpoint {
    ($path:literal , $fname:ident) => {
        pub fn $fname(&self) -> String {
            format!("{}{}", self.url, concat!("ct/v1/", $path))
        }
    };
}

impl Log {
    // No URL parameters
    api_endpoint!("add-chain", add_chain_url);
    api_endpoint!("add-pre-chain", add_pre_chain_url);
    api_endpoint!("get-sth", get_sth_url);
    api_endpoint!("get-roots", get_roots_url);

    pub fn get_sth_consistency_url(&self, first: TreeSize, second: TreeSize) -> String {
        format!(
            "{}ct/v1/get-sth-consistency?first={}&second={}",
            self.url, first, second
        )
    }
    pub fn get_entries_url(&self, start: TreeSize, end: u64) -> String {
        format!("{}ct/v1/get-entries?start={}&end={}", self.url, start, end)
    }
    pub fn get_proof_by_hash_url(&self, hash: String, tree_size: TreeSize) -> String {
        format!(
            "{}ct/v1/get-proof-by-hash?hash={}&tree_size={}",
            self.url, hash, tree_size
        )
    }
    pub fn get_entry_and_proof_url(&self, leaf_index: u32, tree_size: TreeSize) -> String {
        format!(
            "{}ct/v1/get-entry-and-proof?leaf_index={}&tree_size={}",
            self.url, leaf_index, tree_size
        )
    }

    /// Is it possible that this log has unexpired certs that can be fetched?
    pub fn has_active_certs(&self, now: DateTime<Utc>) -> bool {
        if let Some(TemporalInterval {
            start_inclusive: _,
            end_exclusive,
        }) = &self.temporal_interval
        {
            if matches!(self.state, LogState::Retired { .. }) {
                false
            } else {
                let end_exclusive =
                    DateTime::parse_from_rfc3339(end_exclusive).expect("invalid log data");
                end_exclusive > now
            }
        } else {
            match self.state {
                // log isn't up anymore
                LogState::Retired { .. } => false,
                // timestamp is time when log started
                LogState::Usable { .. } => true,
                // timestamp is point when certs stop being accepted
                LogState::ReadOnly { ref timestamp, .. } => {
                    const OLD_MAX_CERT_DURATION: i64 = 825;
                    const NEW_MAX_CERT_DURATION: i64 = 398;
                    // 825 days after Sept. 1, 2020 (when duration was shortened)
                    // = Dec. 6, 2022
                    const CERT_DURATION_SWITCH: i64 = 1670302800;
                    let timestamp =
                        DateTime::parse_from_rfc3339(timestamp).expect("invalid log data");
                    let now = now.timestamp();
                    let extra_days = if now > CERT_DURATION_SWITCH {
                        NEW_MAX_CERT_DURATION
                    } else {
                        OLD_MAX_CERT_DURATION
                    };
                    let oldest_certs_expiration = timestamp + Duration::days(extra_days);
                    oldest_certs_expiration.timestamp() > now
                }
            }
        }
    }
}

impl LogList {
    pub fn google() -> Self {
        serde_json::from_str(include_str!("../log_list.json")).unwrap()
    }

    /// Returns an iterator of all logs run by all log operators.
    pub fn logs(&self) -> impl Iterator<Item = &Log> {
        self.operators.iter().flat_map(|op| op.logs.iter())
    }
}
