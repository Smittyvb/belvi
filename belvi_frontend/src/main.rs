// SPDX-License-Identifier: Apache-2.0

use axum::{
    body::HttpBody,
    extract::{ConnectInfo, Path, Query},
    handler::Handler,
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Extension, Router,
};
use bcder::decode::Constructed;
use belvi_frontend::*;
use belvi_log_list::{fetcher::Fetcher, LogId, LogList};
use belvi_render::{html_escape::HtmlEscapable, Render};
use log::debug;
use rusqlite::Connection;
use std::{fmt::Debug, net::SocketAddr, sync::Arc, time::Instant};
use tokio::{sync::Mutex, task};
use tower_http::set_header::SetResponseHeaderLayer;

struct CacheState {
    cache_conn: belvi_cache::Connection,
    log_list: LogList,
    fetcher: Fetcher,
}

// TODO: use put in global state
thread_local! {
    static DB_CONN: Connection = belvi_db::connect_readonly();
}

const MAX_LIMIT: u32 = 200;
const DEFAULT_LIMIT: u32 = 100;
const TRIVIAL_SEARCHES: &[&str] = &["", "^", "$", "^$", ".*"];

async fn get_root(query: Query<search::Query>) -> impl IntoResponse {
    // redirect simple regex queries that match everything or nothing
    if let Some(domain) = &query.query {
        let domain = domain.trim();
        if TRIVIAL_SEARCHES.contains(&domain) {
            return res::redirect("/");
        }
    };

    let limit = match query.limit {
        Some(val @ 1..=MAX_LIMIT) => val,
        _ => DEFAULT_LIMIT,
    };

    task::spawn_blocking(move || {
        DB_CONN.with(|db| {
            let start = Instant::now();
            let search::SearchResults { certs, count, next } = match query.search_sync(db, limit) {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            let run_time = (Instant::now() - start).as_secs_f64();
            let domain = query
                .query
                .clone()
                .unwrap_or_else(|| "".to_string())
                .html_escape();
            (
                StatusCode::OK,
                res::html_headers(),
                format!(
                    include_str!("tmpl/base.html"),
                    title = if query.query.is_some() {
                        format!("Search results - {}", PRODUCT_NAME)
                    } else {
                        PRODUCT_NAME.to_string()
                    },
                    product_name = PRODUCT_NAME,
                    heading = if query.query.is_some() {
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
                                .map(search::CertData::render)
                                .fold(String::new(), |a, b| a + &b),
                            time = run_time,
                            next = next.clone().map(|next| {
                                let mut query = (*query).clone();
                                query.after = Some(next);
                                format!(
                                    r#"<div class="bvfront-next-link"><a href="{}">Next page</a></div>"#,
                                    query.url(),
                                )
                            }).unwrap_or_default(),
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

fn cert_response(cert: &Vec<u8>, leaf_hash: &str) -> Response {
    // first try decoding as precert, then try normal cert
    let (cert, domains, full_cert) =
        match Constructed::decode(cert.as_ref(), bcder::Mode::Der, |cons| {
            x509_certificate::rfc5280::TbsCertificate::take_from(cons)
        }) {
            Ok(tbs_cert) => (
                tbs_cert.render(),
                belvi_cert::get_cert_domains(&tbs_cert),
                false,
            ),
            Err(_) => {
                let cert = Constructed::decode(cert.as_ref(), bcder::Mode::Der, |cons| {
                    x509_certificate::rfc5280::Certificate::take_from(cons)
                })
                .expect("invalid cert in log");
                (
                    cert.render(),
                    belvi_cert::get_cert_domains(&cert.tbs_certificate),
                    true,
                )
            }
        };
    let first_domain = domains
        .get(0)
        .map(|dom| String::from_utf8_lossy(dom).to_string())
        .unwrap_or_else(String::new);
    let typ = if full_cert {
        "certificate"
    } else {
        "precertificate"
    };
    (
        StatusCode::OK,
        res::html_headers(),
        format!(
            include_str!("tmpl/base.html"),
            title = format_args!("{} {} - {}", first_domain, typ, PRODUCT_NAME),
            product_name = PRODUCT_NAME,
            heading = first_domain,
            content = format_args!(
                include_str!("tmpl/cert_info.html"),
                cert = cert,
                id = leaf_hash,
                typ = typ,
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

async fn find_cert(state: Arc<Mutex<CacheState>>, leaf_hash: &str) -> Result<Vec<u8>, Response> {
    if leaf_hash.len() != 32 {
        return Err(res::error(Some(
            "Cert ID is not 32 characters long".to_string(),
        )));
    }
    let leaf_hash = match hex::decode(leaf_hash) {
        Ok(val) => val,
        Err(_) => return Err(res::error(Some("Cert ID must be hex".to_string()))),
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
                Err(res::not_found("Certificate"))
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
                    None => {
                        return Err(res::error(Some(
                            "Found no current logs with cert".to_string(),
                        )))
                    }
                };
                let entries = state
                    .fetcher
                    .fetch_entries(log, idx as u64, idx as u64)
                    .await;
                let entries = match entries {
                    Ok(val) => val,
                    Err(err) => {
                        return Err(res::error(Some(format!(
                            "Error fetching cert from log: {:#?}",
                            err
                        ))))
                    }
                };
                match entries.len() {
                    1 => (),
                    0 => return Err(res::error(Some("Log found no cert at index".to_string()))),
                    _ => {
                        return Err(res::error(Some(
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
    Extension(state): Extension<Arc<Mutex<CacheState>>>,
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
        None => return res::error(Some("No leaf hash".to_string())),
    };
    let ext = match parts.next() {
        None => OutputMode::Html,
        Some("der") => OutputMode::Der,
        Some("pem") => OutputMode::Pem,
        Some("ber" | "cer") => return res::redirect(&format!("/cert/{}.der", leaf_hash)),
        Some("html") => return res::redirect(&format!("/cert/{}", leaf_hash)),
        _ => return res::error(Some("Unknown extension".to_string())),
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
        return res::not_found("Documentation page");
    };
    let mut parts_iter = page.splitn(3, '\n');
    parts_iter.next().unwrap(); // ignore license
    let title = parts_iter.next().unwrap();
    let body = parts_iter.next().unwrap();
    (
        StatusCode::OK,
        res::html_headers(),
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
    res::not_found("Page")
}

async fn log_middleware<B>(req: Request<B>, next: Next<B>) -> Response {
    debug!(
        "{:?} {:?} {:?} {:?}",
        req.extensions().get::<ConnectInfo<SocketAddr>>().unwrap().0,
        req.method(),
        req.uri(),
        req.headers()
            .get(axum::http::header::USER_AGENT)
            .map(Clone::clone)
            .unwrap_or_else(|| HeaderValue::from_static("-")),
    );
    next.run(req).await
}

async fn handle_422_middleware<B>(req: Request<B>, next: Next<B>) -> Response {
    let mut res = next.run(req).await;
    if res.status() == StatusCode::UNPROCESSABLE_ENTITY {
        let error = res.data().await.map(|bytes| bytes.ok()).flatten();
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            res::html_headers(),
            format!(
                include_str!("tmpl/base.html"),
                title = format_args!("Error - {}", PRODUCT_NAME),
                product_name = PRODUCT_NAME,
                heading = "Error",
                content = format_args!(
                    include_str!("tmpl/error.html"),
                    error
                        .map(|b| String::from_utf8_lossy(&*b).into_owned())
                        .unwrap_or_else(
                            || "Your request could not be processed at this time".to_string()
                        )
                        .html_escape()
                ),
                css = include_str!("tmpl/base.css"),
                script = "",
            ),
        )
            .into_response()
    } else {
        res
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    env_logger::init();

    let cache_state = Arc::new(Mutex::new(CacheState {
        cache_conn: belvi_cache::Connection::new().await,
        log_list: LogList::google(),
        fetcher: Fetcher::new(),
    }));

    let app = Router::new()
        .route("/", get(get_root))
        .route("/cert/:leaf_hash", get(get_cert))
        .route("/docs/:page", get(get_page))
        .fallback(global_404.into_service())
        .layer(middleware::from_fn(log_middleware))
        .layer(middleware::from_fn(handle_422_middleware))
        .layer(Extension(cache_state))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::SERVER,
            HeaderValue::from_static("belvi/0.1"),
        ));

    axum::Server::bind(&"0.0.0.0:47371".parse().unwrap())
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}
