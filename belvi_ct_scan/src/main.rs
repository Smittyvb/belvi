use chrono::{DateTime, Utc};
// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env, fs, path::PathBuf};

pub mod log_data;
mod update_sths;

use belvi_log_list::{Log, LogList};
use log_data::{GetEntriesItem, LogSth};

#[derive(Debug, Clone)]
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
    async fn fetch_entries(
        &self,
        log: &Log,
        start: u64,
        end: u64,
    ) -> Result<Vec<GetEntriesItem>, reqwest::Error> {
        let resp_text = self
            .client
            .get(log.get_entries_url(start, end))
            .send()
            .await?
            .text()
            .await?;
        Ok(GetEntriesItem::parse(&resp_text).unwrap())
    }
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct LogId(String);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FetchState {
    state_ver: u32,
    log_states: HashMap<LogId, LogFetchState>,
}

impl FetchState {
    fn new(ctx: &Ctx) -> Self {
        if let Ok(data) = fs::read_to_string(&ctx.data_path) {
            serde_json::from_str(&data).unwrap()
        } else {
            Self {
                state_ver: 1,
                log_states: HashMap::new(),
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LogFetchState {
    sth: LogSth,
    fetched_to: Option<(u64, u64)>,
}

#[derive(Debug)]
struct Ctx {
    data_path: PathBuf,
    log_list: LogList,
    fetcher: Fetcher,
    start_time: DateTime<Utc>,
}

impl Ctx {
    fn from_env() -> Self {
        let mut args = env::args_os();
        let data_path = args.nth(1).unwrap().into();
        Ctx {
            data_path,
            log_list: LogList::google(),
            fetcher: Fetcher::new(),
            start_time: Utc::now(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Ctx::from_env();
    let mut fetch_state = FetchState::new(&ctx);
    fetch_state.update_sths(&ctx).await;
    dbg!(fetch_state);
    Ok(())
}
