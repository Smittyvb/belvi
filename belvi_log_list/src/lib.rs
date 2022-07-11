// SPDX-License-Identifier: Apache-2.0
use chrono::{DateTime, Duration, FixedOffset, Utc};
use serde::{Deserialize, Serialize};

pub mod fetcher;
pub mod log_data;
#[cfg(test)]
mod log_test;

#[cfg(test)]
mod log_list_test;

type TreeSize = u64;

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LogId(pub String);

impl LogId {
    pub fn num(&self) -> u32 {
        let bytes: [u8; 4] = base64::decode(&self.0).expect("log ID not base64")[0..4]
            .try_into()
            .unwrap();
        u32::from_le_bytes(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LogList {
    pub version: String,
    pub log_list_timestamp: String,
    pub operators: Vec<LogListOperator>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LogListOperator {
    pub name: String,
    pub email: Vec<String>,
    pub logs: Vec<Log>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Log {
    pub description: String,
    pub log_id: String,
    pub key: String,
    pub url: String,
    pub mmd: u32,
    pub state: LogState,
    pub temporal_interval: Option<TemporalInterval>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TemporalInterval {
    pub start_inclusive: String,
    pub end_exclusive: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TreeHead {
    pub sha256_root_hash: String,
    pub tree_size: TreeSize,
}

macro_rules! api_endpoint {
    ($path:literal , $fname:ident) => {
        #[must_use]
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

    #[must_use]
    pub fn get_sth_consistency_url(&self, first: TreeSize, second: TreeSize) -> String {
        format!(
            "{}ct/v1/get-sth-consistency?first={}&second={}",
            self.url, first, second
        )
    }
    #[must_use]
    pub fn get_entries_url(&self, start: TreeSize, end: u64) -> String {
        format!("{}ct/v1/get-entries?start={}&end={}", self.url, start, end)
    }
    #[must_use]
    pub fn get_proof_by_hash_url(&self, hash: String, tree_size: TreeSize) -> String {
        format!(
            "{}ct/v1/get-proof-by-hash?hash={}&tree_size={}",
            self.url, hash, tree_size
        )
    }
    #[must_use]
    pub fn get_entry_and_proof_url(&self, leaf_index: u32, tree_size: TreeSize) -> String {
        format!(
            "{}ct/v1/get-entry-and-proof?leaf_index={}&tree_size={}",
            self.url, leaf_index, tree_size
        )
    }

    /// Is it possible that this log has unexpired certs that can be fetched?
    #[must_use]
    pub fn has_active_certs(&self, now: DateTime<Utc>) -> bool {
        fn no_new_valid(timestamp: DateTime<FixedOffset>, now: DateTime<Utc>) -> bool {
            const OLD_MAX_CERT_DURATION: i64 = 825;
            const NEW_MAX_CERT_DURATION: i64 = 398;
            // 825 days after Sept. 1, 2020 (when duration was shortened)
            // = Dec. 6, 2022
            const CERT_DURATION_SWITCH: i64 = 1670302800;
            let now = now.timestamp();
            let extra_days = if now > CERT_DURATION_SWITCH {
                NEW_MAX_CERT_DURATION
            } else {
                OLD_MAX_CERT_DURATION
            };
            let oldest_certs_expiration = timestamp + Duration::days(extra_days);
            oldest_certs_expiration.timestamp() > now
        }

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
                now < end_exclusive
            }
        } else {
            match self.state {
                // log isn't up anymore
                LogState::Retired { .. } => false,
                // timestamp is time when log started
                LogState::Usable { .. } => true,
                // timestamp is point when certs stop being accepted
                LogState::ReadOnly { ref timestamp, .. } => {
                    let timestamp =
                        DateTime::parse_from_rfc3339(timestamp).expect("invalid log data");
                    no_new_valid(timestamp, now)
                }
            }
        }
    }

    #[must_use]
    pub fn readable(&self) -> bool {
        matches!(
            self.state,
            LogState::ReadOnly { .. } | LogState::Usable { .. }
        )
    }
}

impl LogList {
    #[must_use]
    pub fn google() -> Self {
        serde_json::from_str(include_str!("../log_list.json")).unwrap()
    }

    /// Returns an iterator of all logs run by all log operators.
    pub fn logs(&self) -> impl Iterator<Item = &Log> {
        self.operators.iter().flat_map(|op| op.logs.iter())
    }
}
