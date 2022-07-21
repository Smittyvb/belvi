use std::{ffi::OsString, time::Instant};

// SPDX-License-Identifier: Apache-2.0
use belvi_frontend::search::{self, QueryMode};

fn main() {
    env_logger::init();

    let db = belvi_db::connect_readonly();
    let limit = 50;
    let query = search::Query {
        query: std::env::args_os().nth(2).map(|s| s.into_string().unwrap()),
        mode: match std::env::args_os().nth(3) {
            None => None,
            Some(x) if x == OsString::from("regex") => Some(QueryMode::Regex),
            Some(x) if x == OsString::from("subdomain") => Some(QueryMode::Subdomain),
            Some(_) => panic!("invalid mode"),
        },
        limit: Some(limit),
    };

    let start = Instant::now();
    let (certs, count) = match query.search_sync(&db, limit) {
        Ok(v) => v,
        Err(res) => panic!("failed: {:?}", res.body()),
    };
    let end = Instant::now();
    let duration = end - start;

    let len = certs.len();
    for cert in certs {
        println!("{:?}", cert);
    }
    println!("Found {}/{:?} certs in {:?}", len, count, duration);
}
