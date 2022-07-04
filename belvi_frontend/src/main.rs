// SPDX-License-Identifier: Apache-2.0

use axum::{
    extract::{Path, Query},
    handler::Handler,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use bcder::decode::Constructed;
use belvi_render::{html_escape::HtmlEscapable, Render};
use chrono::{DateTime, NaiveDateTime, Utc};
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, env, path::PathBuf, time::Instant};

mod exts;

const PRODUCT_NAME: &str = "Belvi";

fn get_data_path() -> PathBuf {
    let mut args = env::args_os();
    args.nth(1).unwrap().into()
}

// TODO: use tokio::task_local instead?
thread_local! {
    static DB_CONN: Connection = {
        let db_path = get_data_path().join("data.db");
        // OPEN_CREATE isn't passed, so we don't create the DB if it doesn't exist
        let mut db = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        exts::register(&mut db);
        db
    };
}

fn render_domain(s: String) -> String {
    format!(r#"<div class="bvfront-domain">{}</div>"#, s.html_escape())
}

fn format_date(date: DateTime<Utc>) -> String {
    date.format("%k:%M, %e %b %Y").html_escape()
}

fn base_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SERVER,
        HeaderValue::from_static("belvi_frontend/1.0"),
    );
    headers
}

fn html_headers() -> HeaderMap {
    let mut headers = base_headers();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
    headers
}

#[derive(Debug, Deserialize)]
struct RootQuery {
    domain: Option<String>,
    limit: Option<u32>,
}

const MAX_LIMIT: u32 = 200;
const DEFAULT_LIMIT: u32 = 100;

fn error(e: Option<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        html_headers(),
        format!(
            include_str!("tmpl/base.html"),
            title = format_args!("{} - error", PRODUCT_NAME),
            product_name = PRODUCT_NAME,
            content = format_args!(
                include_str!("tmpl/error.html"),
                e.unwrap_or_else(|| "Your request could not be processed at this time".to_string())
            ),
            css = include_str!("tmpl/base.css"),
            script = "",
        ),
    )
        .into_response()
}

async fn get_root(query: Query<RootQuery>) -> impl IntoResponse {
    // redirect simple regex queries that match everything or nothing
    if let Some(domain) = &query.domain {
        let domain = domain.trim();
        if domain == "" || domain == "^" || domain == "$" || domain == "^$" {
            let mut headers = base_headers();
            headers.insert("Location", HeaderValue::from_static("/"));
            return (StatusCode::FOUND, headers, String::new()).into_response();
        }
    };

    let limit = match query.limit {
        Some(val @ 1..=MAX_LIMIT) => val,
        _ => DEFAULT_LIMIT,
    };

    DB_CONN.with(|db| {
        let start = Instant::now();
        let mut certs_stmt = db.prepare_cached(include_str!("recent_certs.sql")).unwrap();
        let mut certs_regex_stmt = db
            .prepare_cached(include_str!("recent_certs_regex.sql"))
            .unwrap();
        let mut certs_rows = if let Some(domain) = &query.domain {
            certs_regex_stmt.query(params![domain]).unwrap()
        } else {
            certs_stmt.query([]).unwrap()
        };
        // log_entries.leaf_hash, log_entries.log_id, log_entries.ts, domains.domain, certs.extra_hash, certs.not_before, certs.not_after
        #[derive(Debug, Serialize, Deserialize)]
        struct CertData {
            leaf_hash: Vec<u8>,
            log_id: u32,
            ts: i64,
            domain: Vec<String>,
            extra_hash: Vec<u8>,
            not_before: i64,
            not_after: i64,
        }
        impl CertData {
            fn render(&self) -> String {
                let domains = self.domain.iter().fold(String::new(), |a, b| a + b + "");
                let logged_at = DateTime::<Utc>::from_utc(
                    NaiveDateTime::from_timestamp(self.ts / 1000, 0),
                    Utc,
                );
                let not_before = DateTime::<Utc>::from_utc(
                    NaiveDateTime::from_timestamp(self.not_before, 0),
                    Utc,
                );
                let not_after = DateTime::<Utc>::from_utc(
                    NaiveDateTime::from_timestamp(self.not_after, 0),
                    Utc,
                );
                format!(
                    include_str!("tmpl/cert.html"),
                    domains = domains,
                    ts3339 = logged_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    ts = format_date(logged_at),
                    not_before3339 =
                        not_before.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    not_before = format_date(not_before),
                    not_after3339 = not_after.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    not_after = format_date(not_after),
                    json = serde_json::to_string(self).unwrap().html_escape(),
                    cert_link = hex::encode(&self.leaf_hash),
                )
            }
        }
        let mut certs = Vec::new();
        loop {
            let val = match certs_rows.next() {
                Ok(Some(val)) => val,
                Ok(None) => break,
                Err(rusqlite::Error::SqliteFailure(_, err)) => return error(err),
                Err(e) => panic!("unexpected error fetching certs {:#?}", e),
            };
            let domain = match val.get(3) {
                Ok(domain) => render_domain(domain),
                Err(rusqlite::Error::InvalidColumnType(_, _, rusqlite::types::Type::Null)) => {
                    "(none)".to_string()
                }
                other => panic!("unexpected domain fetching error {:?}", other),
            };
            let leaf_hash = val.get(0).unwrap();
            if let Some(true) = certs
                .last()
                .map(|last: &CertData| last.leaf_hash == leaf_hash)
            {
                // extension of last
                certs.last_mut().unwrap().domain.push(domain);
            } else {
                match certs.len().cmp(&(limit as usize)) {
                    Ordering::Less => {}
                    // regex matching would otherwise go forever
                    Ordering::Equal => break,
                    Ordering::Greater => unreachable!(),
                }
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
            html_headers(),
            format!(
                include_str!("tmpl/base.html"),
                title = PRODUCT_NAME,
                product_name = PRODUCT_NAME,
                content = format_args!(
                    include_str!("tmpl/certs_list.html"),
                    count = certs.len(),
                    domain = query.domain.clone().unwrap_or_else(|| "^".to_string()),
                    certs = certs
                        .iter()
                        .map(CertData::render)
                        .fold(String::new(), |a, b| a + &b),
                    time = (Instant::now() - start).as_secs_f64(),
                ),
                css = include_str!("tmpl/base.css"),
                script = include_str!("tmpl/dates.js"),
            ),
        )
            .into_response()
    })
}

fn not_found(thing: &'static str) -> Response {
    (
        StatusCode::NOT_FOUND,
        html_headers(),
        format!(
            include_str!("tmpl/base.html"),
            title = format_args!("{} - not found", PRODUCT_NAME),
            product_name = PRODUCT_NAME,
            content = format_args!("{} not found.", thing),
            css = include_str!("tmpl/base.css"),
            script = ""
        ),
    )
        .into_response()
}

async fn get_cert(Path(leaf_hash): Path<String>) -> impl IntoResponse {
    let maybe_file = tokio::fs::read(get_data_path().join("certs").join(leaf_hash)).await;
    match maybe_file {
        Ok(cert) => {
            // first try decoding as precert, then try normal cert
            let cert = match Constructed::decode(cert.as_ref(), bcder::Mode::Der, |cons| {
                x509_certificate::rfc5280::TbsCertificate::take_from(cons)
            }) {
                Ok(tbs_cert) => tbs_cert.render(),
                Err(_) => Constructed::decode(cert.as_ref(), bcder::Mode::Der, |cons| {
                    x509_certificate::rfc5280::Certificate::take_from(cons)
                })
                .expect("invalid cert in log")
                .render(),
            };
            (
                StatusCode::OK,
                html_headers(),
                format!(
                    include_str!("tmpl/base.html"),
                    title = format_args!("{} - certificate", PRODUCT_NAME),
                    product_name = PRODUCT_NAME,
                    content = cert,
                    css = concat!(
                        include_str!("tmpl/base.css"),
                        include_str!("../../belvi_render/bvcert.css")
                    ),
                    script = include_str!("tmpl/dates.js")
                ),
            )
                .into_response()
        }
        Err(_) => not_found("Certificate"),
    }
}

async fn global_404() -> impl IntoResponse {
    not_found("Page")
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    env_logger::init();

    let app = Router::new()
        .route("/", get(get_root))
        .route("/cert/:leaf_hash", get(get_cert))
        .fallback(global_404.into_service());

    axum::Server::bind(&"0.0.0.0:47371".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
