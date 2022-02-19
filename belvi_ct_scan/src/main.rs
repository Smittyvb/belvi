// SPDX-License-Identifier: Apache-2.0
use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env, fs, path::PathBuf};

mod fetch_certs;
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
        let resp = self
            .client
            .get(log.get_entries_url(start, end))
            .send()
            .await?;
        if resp.status() != StatusCode::OK {
            // TODO: proper error handling
            panic!(
                "bad resp status {}: {}",
                resp.status().as_str(),
                resp.text().await?
            );
        } else {
            Ok(GetEntriesItem::parse(&resp.text().await?).unwrap())
        }
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
    fn new_sync(ctx: &Ctx) -> Self {
        if let Ok(data) = fs::read_to_string(&ctx.fetch_state_path) {
            info!("Loading fetch state from {:?}", ctx.fetch_state_path);
            serde_json::from_str(&data).unwrap()
        } else {
            warn!("No fetch state found, creating new");
            Self {
                state_ver: 1,
                log_states: HashMap::new(),
            }
        }
    }
    async fn save(&self, ctx: &Ctx) {
        info!("Saving fetch state to {:?}", ctx.data_path);
        tokio::fs::write(
            ctx.fetch_state_path.clone(),
            serde_json::to_string(self).expect("couldn't stringify"),
        )
        .await
        .expect("failed to save");
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
    fetch_state_path: PathBuf,
    log_list: LogList,
    fetcher: Fetcher,
    start_time: DateTime<Utc>,
    log_transient: HashMap<LogId, LogTransient>,
    sqlite_conn: rusqlite::Connection,
}

#[derive(Debug, Copy, Clone)]
struct LogTransient {
    fetches: u64,
    highest_page_size: u64,
}

impl Default for LogTransient {
    fn default() -> Self {
        Self {
            fetches: 0,
            highest_page_size: u64::MAX,
        }
    }
}

impl Ctx {
    fn from_env() -> Self {
        let mut args = env::args_os();
        let data_path: PathBuf = args.nth(1).unwrap().into();
        let fetch_state_path = data_path.clone().join("state.json");
        let db_path = data_path.clone().join("data.db");
        let start_time = Utc::now();
        debug!("Start time is {:?}", start_time);
        debug!("SQLite version is {}", rusqlite::version());
        let sqlite_conn = rusqlite::Connection::open(db_path).expect("couldn't open DB");
        sqlite_conn
            .execute_batch(include_str!("init_db.sql"))
            .unwrap();
        Ctx {
            data_path,
            fetch_state_path,
            start_time,
            sqlite_conn,
            log_transient: HashMap::new(),
            log_list: LogList::google(),
            fetcher: Fetcher::new(),
        }
    }
    fn active_logs(&self) -> impl Iterator<Item = &Log> {
        self.log_list
            .logs()
            .filter(|log| log.has_active_certs(self.start_time))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    info!("Starting Belvi fetcher");

    let mut ctx = Ctx::from_env();
    let mut fetch_state = FetchState::new_sync(&ctx);

    fetch_state.update_sths(&ctx).await;
    fetch_state.save(&ctx).await;

    let active_logs: Vec<Log> = ctx.active_logs().cloned().collect();
    for log in active_logs {
        fetch_state.fetch_next_batch(&mut ctx, &log).await;
    }

    Ok(())
}
