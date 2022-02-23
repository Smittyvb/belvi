// SPDX-License-Identifier: Apache-2.0

use axum::{
    http::StatusCode,
    response::{Headers, IntoResponse},
    routing::get,
    Router,
};
use belvi_render::html_escape::HtmlEscapable;
use chrono::{DateTime, NaiveDateTime, Utc};
use rusqlite::{Connection, OpenFlags};
use std::{env, path::PathBuf};

const PRODUCT_NAME: &str = "Belvi";

// TODO: use tokio::task_local instead?
thread_local! {
    static DB_CONN: Connection = {
        let mut args = env::args_os();
        let data_path: PathBuf = args.nth(1).unwrap().into();
        let db_path = data_path.join("data.db");
        // OPEN_CREATE isn't passed, so we don't create the DB if it doesn't exist
        Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap()
    };
}

fn linkify_domain(s: &String) -> String {
    if s.starts_with("*.") {
        format!(
            r#"*.<a href="https://{domain}/">{domain}</a>"#,
            domain = s.split_at(2).1,
        )
    } else if s.contains('.') && !s.contains('@') {
        format!(
            r#"<a href="https://{domain}/">{domain}</a>"#,
            domain = s.html_escape()
        )
    } else {
        s.clone()
    }
}

async fn get_root() -> impl IntoResponse {
    DB_CONN.with(|db| {
        let count: usize = db
            .prepare_cached("SELECT count(domain) FROM domains")
            .unwrap()
            .query_row([], |row| row.get(0))
            .unwrap();
        let mut certs_stmt = db.prepare_cached(include_str!("recent_certs.sql")).unwrap();
        let mut certs_rows = certs_stmt.query([]).unwrap();
        // log_entries.leaf_hash, log_entries.log_id, log_entries.ts, domains.domain, certs.extra_hash, certs.not_before, certs.not_after
        #[derive(Debug)]
        struct CertData {
            leaf_hash: Vec<u8>,
            log_id: u32,
            ts: i64,
            domain: Vec<String>,
            extra_hash: Vec<u8>,
            not_before: u32,
            not_after: u32,
        }
        impl CertData {
            fn render(&self) -> String {
                let mut domains = self
                    .domain
                    .iter()
                    .map(linkify_domain)
                    .fold(String::new(), |a, b| a + &b + ", ")
                    .to_string();
                domains.truncate(domains.len() - 2);
                let date = DateTime::<Utc>::from_utc(
                    NaiveDateTime::from_timestamp(self.ts / 1000, 0),
                    Utc,
                );
                format!(
                    include_str!("tmpl/cert.html"),
                    leaf_hash = self
                        .leaf_hash
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .fold(String::new(), |a, b| a + &b),
                    domains = domains,
                    ts3339 = date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    ts = date.format("%k:%M, %e %b %Y").html_escape()
                )
            }
        }
        let mut certs = Vec::new();
        while let Ok(Some(val)) = certs_rows.next() {
            let domain = val.get(3).unwrap();
            let leaf_hash = val.get(0).unwrap();
            if let Some(true) = certs
                .last()
                .map(|last: &CertData| last.leaf_hash == leaf_hash)
            {
                // extension of last
                certs.last_mut().unwrap().domain.push(domain);
            } else {
                certs.push(CertData {
                    leaf_hash,
                    log_id: val.get(1).unwrap(),
                    ts: val.get(2).unwrap(),
                    domain: vec![domain],
                    extra_hash: val.get(4).unwrap(),
                    not_before: val.get(5).unwrap(),
                    not_after: val.get(6).unwrap(),
                });
            }
        }
        (
            StatusCode::OK,
            Headers([
                ("Server", "belvi_frontend/1.0"),
                ("Content-Type", "text/html"),
            ]),
            format!(
                include_str!("tmpl/base.html"),
                title = PRODUCT_NAME,
                product_name = PRODUCT_NAME,
                content = format_args!(
                    r#"<ul class="bvfront-cert-list">{}</ul>"#,
                    certs
                        .iter()
                        .map(CertData::render)
                        .fold(String::new(), |a, b| a + &b)
                ),
                css = include_str!("tmpl/base.css")
            ),
        )
    })
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    env_logger::init();

    let app = Router::new().route("/", get(get_root));

    axum::Server::bind(&"0.0.0.0:47371".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
