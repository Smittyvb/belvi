// SPDX-License-Identifier: Apache-2.0

use axum::{
    extract::{Path, Query},
    handler::Handler,
    http::StatusCode,
    response::{Headers, IntoResponse},
    routing::get,
    Router,
};
use bcder::decode::Constructed;
use belvi_render::{html_escape::HtmlEscapable, Render};
use chrono::{DateTime, NaiveDateTime, Utc};
use regex::Regex;
use rusqlite::{functions::FunctionFlags, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::{env, path::PathBuf, sync::Arc};

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
        let db = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();

        // https://docs.rs/rusqlite/latest/rusqlite/functions/index.html
        db.create_scalar_function("regex", 2, FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC, move |ctx| {
            assert_eq!(ctx.len(), 2, "wrong argument count to regexp()");
            let regexp: Arc<Regex> = ctx.get_or_create_aux(0, |vr| -> Result<_, Box<dyn std::error::Error + Send + Sync + 'static>> {
                Ok(Regex::new(vr.as_str()?)?)
            })?;
            let is_match = {
                let text = ctx
                    .get_raw(1)
                    .as_str()
                    .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;

                regexp.is_match(text)
            };

            Ok(is_match)
        }).unwrap();

        db
    };
}

fn render_domain(s: &String) -> String {
    format!(r#"<div class="bvfront-domain">{}</div>"#, s.html_escape())
}

fn format_date(date: DateTime<Utc>) -> String {
    date.format("%k:%M, %e %b %Y").html_escape()
}

#[derive(Debug, Deserialize)]
struct RootQuery {
    domain: Option<String>,
}

async fn get_root(query: Query<RootQuery>) -> impl IntoResponse {
    DB_CONN.with(|db| {
        let count: usize = db
            .prepare_cached("SELECT count(domain) FROM domains")
            .unwrap()
            .query_row([], |row| row.get(0))
            .unwrap();
        let mut certs_stmt = db.prepare_cached(include_str!("recent_certs.sql")).unwrap();
        let mut certs_regex_stmt = db
            .prepare_cached(include_str!("recent_certs_regex.sql"))
            .unwrap();
        let mut certs_rows = if let Some(domain) = &query.domain {
            certs_regex_stmt.query([domain]).unwrap()
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
                let domains = self
                    .domain
                    .iter()
                    .map(render_domain)
                    .fold(String::new(), |a, b| a + &b + "");
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
                    include_str!("tmpl/certs_list.html"),
                    certs
                        .iter()
                        .map(CertData::render)
                        .fold(String::new(), |a, b| a + &b)
                ),
                css = include_str!("tmpl/base.css"),
                script = include_str!("tmpl/dates.js")
            ),
        )
    })
}

async fn get_cert(Path(leaf_hash): Path<String>) -> impl IntoResponse {
    let maybe_file = tokio::fs::read(get_data_path().join("certs").join(leaf_hash)).await;
    match maybe_file {
        Ok(cert) => {
            // TODO: render as normal cert for non-precerts
            let cert = Constructed::decode(cert.as_ref(), bcder::Mode::Der, |cons| {
                x509_certificate::rfc5280::TbsCertificate::take_from(cons)
            })
            .expect("invalid cert in log");
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
                    content = cert.render(),
                    css = concat!(
                        include_str!("tmpl/base.css"),
                        include_str!("../../belvi_render/bvcert.css")
                    ),
                    script = include_str!("tmpl/dates.js")
                ),
            )
        }
        Err(_) => (
            StatusCode::NOT_FOUND,
            Headers([
                ("Server", "belvi_frontend/1.0"),
                ("Content-Type", "text/html"),
            ]),
            format!(
                include_str!("tmpl/base.html"),
                title = PRODUCT_NAME,
                product_name = PRODUCT_NAME,
                content = "Certificate not found.",
                css = include_str!("tmpl/base.css"),
                script = ""
            ),
        ),
    }
}

async fn global_404() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Headers([
            ("Server", "belvi_frontend/1.0"),
            ("Content-Type", "text/html"),
        ]),
        format!(
            include_str!("tmpl/base.html"),
            title = PRODUCT_NAME,
            product_name = PRODUCT_NAME,
            content = "Not found.",
            css = include_str!("tmpl/base.css"),
            script = ""
        ),
    )
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
