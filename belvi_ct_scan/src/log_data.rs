// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp;

#[cfg(test)]
mod test;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogSth {
    pub tree_size: u64,
    pub timestamp: u64,
    pub sha256_root_hash: String,
    pub tree_head_signature: String,
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

#[derive(Debug)]
pub enum CTParseError {
    GetEntriesRootNotObject,
    GetEntriesNoEntriesArray,
    GetEntriesEntryNoLeafInput,
    GetEntriesEntryNoExtraData,
    GetEntriesEntryNotObject,
    MerkleTreeLeafTooShort,
    MerkleTreeLeafUnknownLeafType,
    TimestampedEntryTooShort,
    LogEntryUnknownEntryType,
    Base64Error(base64::DecodeError),
    JsonError(serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetEntriesItem {
    pub leaf_input: MerkleTreeLeaf,
    pub extra_data: Vec<u8>,
}

impl GetEntriesItem {
    fn from_get_entries_item(item: Value) -> Result<Self, CTParseError> {
        let mut obj = if let Value::Object(map) = item {
            map
        } else {
            return Err(CTParseError::GetEntriesEntryNotObject);
        };
        let extra_data = if let Some(Value::String(extra_data)) = obj.remove("extra_data") {
            extra_data
        } else {
            return Err(CTParseError::GetEntriesEntryNoExtraData);
        };
        let extra_data = base64::decode(extra_data).map_err(CTParseError::Base64Error)?;
        let leaf_input = if let Some(Value::String(leaf_input)) = obj.remove("leaf_input") {
            leaf_input
        } else {
            return Err(CTParseError::GetEntriesEntryNoLeafInput);
        };
        let leaf_input = base64::decode(leaf_input).map_err(CTParseError::Base64Error)?;
        let leaf_input = MerkleTreeLeaf::parse(&leaf_input)?;
        Ok(Self {
            extra_data,
            leaf_input,
        })
    }
    pub fn parse(entries: &str) -> Result<Vec<Self>, CTParseError> {
        let json = serde_json::from_str(entries).map_err(CTParseError::JsonError)?;
        let mut obj = if let Value::Object(map) = json {
            map
        } else {
            return Err(CTParseError::GetEntriesRootNotObject);
        };
        let entries = if let Some(Value::Array(entries)) = obj.remove("entries") {
            entries
        } else {
            return Err(CTParseError::GetEntriesNoEntriesArray);
        };
        let mut parsed_entries = Vec::with_capacity(entries.len());
        for entry in entries {
            parsed_entries.push(Self::from_get_entries_item(entry)?);
        }
        Ok(parsed_entries)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampedEntry {
    pub timestamp: u64,
    pub log_entry: LogEntry,
    pub extensions: CtExtensions,
}

impl TimestampedEntry {
    pub fn parse(v: &[u8]) -> Result<Self, CTParseError> {
        if v.len() <= 11 {
            return Err(CTParseError::TimestampedEntryTooShort);
        };
        let timestamp =
            u64::from_be_bytes(v[0..=7].try_into().expect("slice is always right length"));
        let entry_type =
            u16::from_be_bytes(v[8..=9].try_into().expect("slice is always right length"));
        let log_entry = match entry_type {
            // just skip the next 3 bytes?
            0 => LogEntry::X509(v[13..].to_vec()),
            1 => {
                if v.len() <= 43 {
                    return Err(CTParseError::TimestampedEntryTooShort);
                };
                assert!(v[v.len() - 1] == 0, "TODO: extensions");
                assert!(v[v.len() - 2] == 0, "TODO: extensions");
                LogEntry::Precert {
                    issuer_key_hash: v[10..=41].try_into().expect("slice is always right length"),
                    // just skip the next 4 bytes?
                    tbs_certificate: v[45..].to_vec(),
                }
            }
            _ => return Err(CTParseError::LogEntryUnknownEntryType),
        };
        Ok(Self {
            timestamp,
            log_entry,
            extensions: CtExtensions(vec![]), // TODO: extensions
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum LogEntry {
    X509(Vec<u8>),
    Precert {
        issuer_key_hash: [u8; 32],
        tbs_certificate: Vec<u8>,
    },
}

impl LogEntry {
    pub fn inner_cert(&self) -> &Vec<u8> {
        match self {
            Self::X509(cert)
            | Self::Precert {
                tbs_certificate: cert,
                ..
            } => cert,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleTreeLeaf {
    pub version: u8,
    pub timestamped_entry: TimestampedEntry,
}

impl MerkleTreeLeaf {
    pub fn parse(v: &[u8]) -> Result<Self, CTParseError> {
        if v.len() <= 3 {
            return Err(CTParseError::MerkleTreeLeafTooShort);
        };
        let version = v[0];
        let leaf_type = v[1];
        if leaf_type != 0 {
            return Err(CTParseError::MerkleTreeLeafUnknownLeafType);
        }
        let timestamped_entry = TimestampedEntry::parse(&v[2..])?;
        Ok(Self {
            version,
            timestamped_entry,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CtExtensions(pub Vec<u8>);
