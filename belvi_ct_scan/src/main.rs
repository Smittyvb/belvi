// SPDX-License-Identifier: Apache-2.0
use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    env, fs,
    path::PathBuf,
    sync::{atomic, Mutex},
    time::{Duration, Instant},
};

mod fetch_certs;
mod update_sths;

use belvi_log_list::{fetcher::Fetcher, log_data::LogSth};
use belvi_log_list::{Log, LogId, LogList};

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
    fetched_to: fetch_certs::batcher::HistState,
}

#[derive(Debug)]
struct Ctx {
    data_path: PathBuf,
    fetch_state_path: PathBuf,
    #[allow(dead_code)]
    certs_path: PathBuf,
    log_list: LogList,
    fetcher: Fetcher,
    start_time: DateTime<Utc>,
    cache_certs: bool,
    log_transient: HashMap<LogId, LogTransient>,
    sqlite_conn: rusqlite::Connection,
    redis_conn: belvi_cache::Connection,
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
    // redis_conn is an argument since it can only be created in an async fn
    fn from_env_sync(redis_conn: belvi_cache::Connection) -> Self {
        let mut args = env::args_os();
        let data_path: PathBuf = args.nth(1).unwrap().into();
        let fetch_state_path = data_path.join("state.json");
        let db_path = data_path.join("data.db");
        let certs_path = data_path.join("certs");
        if !certs_path.exists() {
            warn!("certs directory doesn't exist; creating");
            fs::create_dir(certs_path.clone()).unwrap();
        }
        let start_time = Utc::now();
        debug!("Start time is {:?}", start_time);
        let cache_certs = env::var("BELVI_NO_CACHE").is_err();
        let sqlite_conn = rusqlite::Connection::open(db_path).expect("couldn't open DB");
        debug!("SQLite version is {}", rusqlite::version());
        sqlite_conn
            .execute_batch(include_str!("../../shared_sql/init_db.sql"))
            .unwrap();
        Ctx {
            data_path,
            fetch_state_path,
            certs_path,
            start_time,
            cache_certs,
            sqlite_conn,
            log_transient: HashMap::new(),
            log_list: LogList::google(),
            fetcher: Fetcher::new(),
            redis_conn,
        }
    }
    fn active_logs(&self) -> impl Iterator<Item = &Log> {
        self.log_list
            .logs()
            .filter(|log| log.has_active_certs(self.start_time))
    }
}

const MAX_RECHECK_GAP: u64 = 90;
const WAIT_TIME: u64 = 8;

static STOP_FETCHING: atomic::AtomicBool = atomic::AtomicBool::new(false);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    info!("Starting Belvi fetcher");

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.unwrap();
        println!("Recieved SIGINT, stopping after next batch");
        STOP_FETCHING.store(true, atomic::Ordering::Relaxed);
    });

    let ctx = Ctx::from_env_sync(belvi_cache::Connection::new().await);
    let mut fetch_state = FetchState::new_sync(&ctx);

    fetch_state.update_sths(&ctx).await;
    fetch_state.save(&ctx).await;
    let mut last_fetch_state_check = Instant::now();
    // TODO: use Tokio mutex
    let fetch_state = Mutex::new(fetch_state);

    let mut active_logs: Vec<Log> = ctx.active_logs().cloned().collect();
    let mut checked_logs: HashSet<String> = HashSet::new();
    ctx.sqlite_conn
        .prepare_cached("BEGIN DEFERRED")
        .unwrap()
        .execute([])
        .unwrap();
    let ctx = Mutex::new(ctx);
    loop {
        fastrand::shuffle(&mut active_logs);
        let mut futures = Vec::new();
        let mut logs = Vec::new();
        for log in &active_logs {
            if checked_logs.contains(&log.log_id) {
                continue;
            }
            futures.push(FetchState::fetch_next_batch(&fetch_state, &ctx, log));
            logs.push(log);
        }
        for (idx, count) in futures::future::join_all(futures)
            .await
            .into_iter()
            .enumerate()
        {
            let log = logs[idx];
            if let Some(count) = count {
                info!("Fetched {} certs from \"{}\"", count, log.description);
            } else {
                checked_logs.insert(log.log_id.clone());
            }
        }

        let long_time_since_recheck = Instant::now().duration_since(last_fetch_state_check)
            > Duration::from_secs(MAX_RECHECK_GAP);
        let nothing_left = checked_logs.len() == active_logs.len();
        let stop_fetching = STOP_FETCHING.load(atomic::Ordering::Relaxed);

        if long_time_since_recheck || nothing_left || stop_fetching {
            // save state
            let inner_ctx = ctx.lock().unwrap();
            let mut inner_fetch_state = fetch_state.lock().unwrap();
            inner_fetch_state.save(&inner_ctx).await;
            inner_ctx
                .sqlite_conn
                .prepare_cached("COMMIT")
                .unwrap()
                .execute([])
                .unwrap();

            if stop_fetching {
                return Ok(());
            }

            // wait if needed
            if nothing_left {
                info!("Fetched all possible certs");
                // wait for some time
                tokio::time::sleep(Duration::from_secs(WAIT_TIME)).await;
            }

            // update STHs
            inner_fetch_state.update_sths(&inner_ctx).await;
            checked_logs = HashSet::new(); // checked logs may need to be rechecked again
            last_fetch_state_check = Instant::now();

            // start another tx
            inner_ctx
                .sqlite_conn
                .prepare_cached("BEGIN DEFERRED")
                .unwrap()
                .execute([])
                .unwrap();
        }
    }
}
