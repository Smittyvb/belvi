// SPDX-License-Identifier: Apache-2.0

use axum::{
    extract::{Path, Query},
    handler::Handler,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Extension, Router,
};
use bcder::decode::Constructed;
use belvi_log_list::{fetcher::Fetcher, LogId, LogList};
use belvi_render::{html_escape::HtmlEscapable, Render};
use chrono::{DateTime, NaiveDateTime, Utc};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, env, path::PathBuf, sync::Arc, time::Instant};
use tokio::{sync::Mutex, task};
use tower_http::set_header::SetResponseHeaderLayer;

mod exts;

const PRODUCT_NAME: &str = match option_env!("BELVI_PRODUCT_NAME") {
    // unwrap_or isn't const stable
    Some(name) => name,
    None => "Belvi",
};

fn get_data_path() -> PathBuf {
    let mut args = env::args_os();
    args.nth(1).unwrap().into()
}

struct State {
    cache_conn: belvi_cache::Connection,
    log_list: LogList,
    fetcher: Fetcher,
}

// TODO: use put in global state
thread_local! {
    static DB_CONN: Connection = {
        let db_path = get_data_path().join("data.db");
        // OPEN_CREATE isn't passed, so we don't create the DB if it doesn't exist
        let mut db = Connection::open(db_path).unwrap();
        // this can write to the database so we can't open it as readonly
        db.execute_batch(include_str!("../../shared_sql/init_db.sql")).unwrap();
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

fn html_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
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
            title = format_args!("Error - {}", PRODUCT_NAME),
            product_name = PRODUCT_NAME,
            heading = "Error",
            content = format_args!(
                include_str!("tmpl/error.html"),
                e.unwrap_or_else(|| "Your request could not be processed at this time".to_string())
                    .html_escape()
            ),
            css = include_str!("tmpl/base.css"),
            script = "",
        ),
    )
        .into_response()
}

fn redirect(to: &str) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert("Location", HeaderValue::from_str(to).unwrap());
    (StatusCode::FOUND, headers, String::new()).into_response()
}

async fn get_root(query: Query<RootQuery>) -> impl IntoResponse {
    // redirect simple regex queries that match everything or nothing
    if let Some(domain) = &query.domain {
        let domain = domain.trim();
        if domain == "" || domain == "^" || domain == "$" || domain == "^$" {
            return redirect("/");
        }
    };

    let limit = match query.limit {
        Some(val @ 1..=MAX_LIMIT) => val,
        _ => DEFAULT_LIMIT,
    };

    task::spawn_blocking(move || {
        DB_CONN.with(|db| {
            let start = Instant::now();
            let mut certs_stmt = db
                .prepare_cached(include_str!("queries/recent_certs.sql"))
                .unwrap();
            let mut certs_regex_stmt = db
                .prepare_cached(include_str!("queries/recent_certs_regex.sql"))
                .unwrap();
            let mut certs_count_stmt = db.prepare_cached("SELECT COUNT(*) FROM certs").unwrap();
            let (mut certs_rows, count) = if let Some(domain) = &query.domain {
                (certs_regex_stmt.query([domain]).unwrap(), None)
            } else {
                (
                    certs_stmt.query([]).unwrap(),
                    Some(
                        certs_count_stmt
                            .query_row([], |row| Ok(row.get::<_, usize>(0)?))
                            .unwrap(),
                    ),
                )
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
                        not_after3339 =
                            not_after.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
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
            let run_time = (Instant::now() - start).as_secs_f64();
            let domain = query
                .domain
                .clone()
                .unwrap_or_else(|| "^".to_string())
                .html_escape();
            (
                StatusCode::OK,
                html_headers(),
                format!(
                    include_str!("tmpl/base.html"),
                    title = if query.domain.is_some() {
                        format!("Search results - {}", PRODUCT_NAME)
                    } else {
                        PRODUCT_NAME.to_string()
                    },
                    product_name = PRODUCT_NAME,
                    heading = if query.domain.is_some() {
                        "Search results"
                    } else {
                        "Newest certificates"
                    },
                    content = if certs.is_empty() {
                        format!(
                            include_str!("tmpl/no_results.html"),
                            domain = domain,
                            time = run_time,
                        )
                    } else {
                        format!(
                            include_str!("tmpl/certs_list.html"),
                            count = certs.len(),
                            total = if certs.len() < (limit as usize) {
                                if let Some(val) = count {
                                    assert_eq!(val, certs.len());
                                }
                                format!(" ({} total)", certs.len())
                            } else if let Some(val) = count {
                                format!(" ({} total)", val)
                            } else {
                                String::new()
                            },
                            domain = domain,
                            certs = certs
                                .iter()
                                .map(CertData::render)
                                .fold(String::new(), |a, b| a + &b),
                            time = run_time,
                        )
                    },
                    css = include_str!("tmpl/base.css"),
                    script = include_str!("tmpl/dates.js"),
                ),
            )
                .into_response()
        })
    })
    .await
    .unwrap()
}

fn not_found(thing: &'static str) -> Response {
    (
        StatusCode::NOT_FOUND,
        html_headers(),
        format!(
            include_str!("tmpl/base.html"),
            title = format_args!("Not found - {}", PRODUCT_NAME),
            product_name = PRODUCT_NAME,
            heading = "Not found",
            content = format_args!("{} not found.", thing),
            css = include_str!("tmpl/base.css"),
            script = ""
        ),
    )
        .into_response()
}

fn cert_response(cert: &Vec<u8>, leaf_hash: &str) -> Response {
    // first try decoding as precert, then try normal cert
    let (cert, domains) = match Constructed::decode(cert.as_ref(), bcder::Mode::Der, |cons| {
        x509_certificate::rfc5280::TbsCertificate::take_from(cons)
    }) {
        Ok(tbs_cert) => (tbs_cert.render(), belvi_cert::get_cert_domains(&tbs_cert)),
        Err(_) => {
            let cert = Constructed::decode(cert.as_ref(), bcder::Mode::Der, |cons| {
                x509_certificate::rfc5280::Certificate::take_from(cons)
            })
            .expect("invalid cert in log");
            (
                cert.render(),
                belvi_cert::get_cert_domains(&cert.tbs_certificate),
            )
        }
    };
    let first_domain = domains
        .get(0)
        .map(|dom| String::from_utf8_lossy(dom).to_string())
        .unwrap_or_else(String::new);
    (
        StatusCode::OK,
        html_headers(),
        format!(
            include_str!("tmpl/base.html"),
            title = format_args!("{} certificate - {}", first_domain, PRODUCT_NAME),
            product_name = PRODUCT_NAME,
            heading = first_domain,
            content = format_args!(
                include_str!("tmpl/cert_info.html"),
                cert = cert,
                id = leaf_hash,
            ),
            css = concat!(
                include_str!("tmpl/base.css"),
                include_str!("../../belvi_render/bvcert.css")
            ),
            script = concat!(include_str!("tmpl/dates.js"), include_str!("tmpl/certs.js")),
        ),
    )
        .into_response()
}

async fn find_cert(state: Arc<Mutex<State>>, leaf_hash: &str) -> Result<Vec<u8>, Response> {
    if leaf_hash.len() != 32 {
        return Err(error(Some("Cert ID is not 32 characters long".to_string())));
    }
    let leaf_hash = match hex::decode(leaf_hash) {
        Ok(val) => val,
        Err(_) => return Err(error(Some("Cert ID must be hex".to_string()))),
    };
    let maybe_cert = { state.lock().await.cache_conn.get_cert(&leaf_hash).await };
    match maybe_cert {
        Some(cert) => Ok(cert),
        None => {
            let wanted_logs = DB_CONN.with(|db| {
                let mut query = db
                    .prepare_cached("SELECT log_id, idx FROM log_entries WHERE leaf_hash = ?")
                    .unwrap();
                let mut rows = query.query([leaf_hash]).unwrap();
                let mut logs: Vec<(u32, usize)> = Vec::new();
                loop {
                    let val = match rows.next() {
                        Ok(Some(val)) => val,
                        Ok(None) => break,
                        Err(e) => panic!("unexpected error fetching certs {:#?}", e),
                    };
                    logs.push((val.get(0).unwrap(), val.get(1).unwrap()));
                }
                logs
            });
            if wanted_logs.is_empty() {
                Err(not_found("Certificate"))
            } else {
                let mut state = state.lock().await;
                let mut matching_logs = state
                    .log_list
                    .logs()
                    .filter(|list_log| list_log.readable())
                    .filter_map(|list_log| {
                        let wanted_id = LogId(list_log.log_id.clone()).num();
                        wanted_logs
                            .iter()
                            .find(|wanted_log| wanted_id == wanted_log.0)
                            .map(|v| (list_log, v.1))
                    });
                let (log, idx) = match matching_logs.next() {
                    Some(val) => val,
                    None => return Err(error(Some("Found no current logs with cert".to_string()))),
                };
                let entries = state
                    .fetcher
                    .fetch_entries(log, idx as u64, idx as u64)
                    .await;
                let entries = match entries {
                    Ok(val) => val,
                    Err(err) => {
                        return Err(error(Some(format!(
                            "Error fetching cert from log: {:#?}",
                            err
                        ))))
                    }
                };
                match entries.len() {
                    1 => (),
                    0 => return Err(error(Some("Log found no cert at index".to_string()))),
                    _ => {
                        return Err(error(Some(
                            "Log responded with more certs than requested".to_string(),
                        )))
                    }
                };
                let cert = entries[0]
                    .leaf_input
                    .timestamped_entry
                    .log_entry
                    .inner_cert();
                drop(matching_logs);
                state.cache_conn.new_cert(&belvi_hash::db(cert), cert);
                Ok(cert.clone())
            }
        }
    }
}

async fn get_cert(
    Path(leaf_hash): Path<String>,
    Extension(state): Extension<Arc<Mutex<State>>>,
) -> impl IntoResponse {
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    enum OutputMode {
        Der,
        Html,
        Pem,
    }

    let mut parts = leaf_hash.split('.');
    let leaf_hash = match parts.next() {
        Some(val) => val,
        None => return error(Some("No leaf hash".to_string())),
    };
    let ext = match parts.next() {
        None => OutputMode::Html,
        Some("der") => OutputMode::Der,
        Some("pem") => OutputMode::Pem,
        Some("ber" | "cer") => return redirect(&format!("/cert/{}.der", leaf_hash)),
        Some("html") => return redirect(&format!("/cert/{}", leaf_hash)),
        _ => return error(Some("Unknown extension".to_string())),
    };

    match find_cert(state, leaf_hash).await {
        Ok(cert) => match ext {
            OutputMode::Html => cert_response(&cert, leaf_hash),
            OutputMode::Der => (
                StatusCode::OK,
                {
                    let mut headers = HeaderMap::new();
                    // according to https://pki-tutorial.readthedocs.io/en/latest/mime.html
                    headers.insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/x-x509-ca-cert"),
                    );
                    headers
                },
                cert,
            )
                .into_response(),
            OutputMode::Pem => (
                StatusCode::OK,
                {
                    let mut headers = HeaderMap::new();
                    // according to https://pki-tutorial.readthedocs.io/en/latest/mime.html
                    headers.insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/x-pem-file"),
                    );
                    headers
                },
                // TODO: CERTIFICATE should be different for precerts?
                format!(
                    "-----BEGIN CERTIFICATE-----\r\n{}\r\n-----END CERTIFICATE-----\r\n",
                    base64::encode(cert)
                ),
            )
                .into_response(),
        },
        Err(res) => res,
    }
}

macro_rules! pages {
    ($($page:expr),*) => {
        const PAGES: &[(&str, &str)] = &[
            $(
                ($page, include_str!(concat!(concat!("pages/", $page), ".html")))
            )*
        ];
    };
}

pages!["regex"];

async fn get_page(Path(page): Path<String>) -> impl IntoResponse {
    let page = PAGES.iter().find(|(id, _)| **id == *page);
    let page = if let Some((_, page)) = page {
        page
    } else {
        return not_found("Documentation page");
    };
    let mut parts_iter = page.splitn(3, '\n');
    parts_iter.next().unwrap(); // ignore license
    let title = parts_iter.next().unwrap();
    let body = parts_iter.next().unwrap();
    (
        StatusCode::OK,
        html_headers(),
        format!(
            include_str!("tmpl/base.html"),
            title = format_args!("{} - {}", title, PRODUCT_NAME),
            product_name = PRODUCT_NAME,
            heading = title,
            content = format_args!(r#"<div class="bvfront-page-content">{}</div>"#, body),
            css = include_str!("tmpl/base.css"),
            script = ""
        ),
    )
        .into_response()
}

async fn global_404() -> impl IntoResponse {
    not_found("Page")
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    env_logger::init();

    let cache_conn = Arc::new(Mutex::new(State {
        cache_conn: belvi_cache::Connection::new().await,
        log_list: LogList::google(),
        fetcher: Fetcher::new(),
    }));

    let app = Router::new()
        .route("/", get(get_root))
        .route("/cert/:leaf_hash", get(get_cert))
        .route("/docs/:page", get(get_page))
        .fallback(global_404.into_service())
        .layer(Extension(cache_conn))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::SERVER,
            HeaderValue::from_static("belvi/0.1"),
        ));

    axum::Server::bind(&"0.0.0.0:47371".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
