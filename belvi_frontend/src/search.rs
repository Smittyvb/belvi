// SPDX-License-Identifier: Apache-2.0
use std::cmp::Ordering;

use crate::res;
use axum::response::Response;
use belvi_render::html_escape::HtmlEscapable;
use chrono::{DateTime, NaiveDateTime, Utc};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

fn render_domain(s: String) -> String {
    format!(
        r#"<div class="bvfront-domain">{}</div>"#,
        s.html_escape()
            // suggest linebreaks after dots
            .replace('.', "<wbr>.")
    )
}

fn format_date(date: DateTime<Utc>) -> String {
    date.format("%k:%M, %e %b %Y").html_escape()
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryMode {
    Regex,
    Subdomain,
    Recent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Query {
    pub query: Option<String>,
    pub mode: Option<QueryMode>,
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CertData {
    leaf_hash: Vec<u8>,
    log_id: u32,
    ts: i64,
    domain: Vec<String>,
    extra_hash: Vec<u8>,
    not_before: i64,
    not_after: i64,
}

impl CertData {
    pub fn render(&self) -> String {
        let domains = self.domain.iter().fold(String::new(), |a, b| a + b + "");
        let logged_at =
            DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(self.ts / 1000, 0), Utc);
        let not_before =
            DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(self.not_before, 0), Utc);
        let not_after =
            DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(self.not_after, 0), Utc);
        format!(
            include_str!("tmpl/cert.html"),
            domains = domains,
            ts3339 = logged_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            ts = format_date(logged_at),
            not_before3339 = not_before.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            not_before = format_date(not_before),
            not_after3339 = not_after.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            not_after = format_date(not_after),
            json = serde_json::to_string(self).unwrap().html_escape(),
            cert_link = hex::encode(&self.leaf_hash),
        )
    }
}

impl Query {
    pub fn search_sync(
        &self,
        db: &Connection,
        limit: u32,
    ) -> Result<(Vec<CertData>, Option<usize>), Response> {
        let mut certs_stmt = db
            .prepare_cached(include_str!("queries/recent_certs.sql"))
            .unwrap();
        let mut certs_regex_stmt = db
            .prepare_cached(include_str!("queries/recent_certs_regex.sql"))
            .unwrap();
        let mut cert_sub_stmt = db
            .prepare_cached(include_str!("queries/recent_certs_sub.sql"))
            .unwrap();
        let mut certs_count_stmt = db.prepare_cached("SELECT COUNT(*) FROM certs").unwrap();
        let mode = self.mode.unwrap_or(QueryMode::Recent);
        let (mut certs_rows, count) = match (&self.query, mode) {
            (Some(query), QueryMode::Regex) => (certs_regex_stmt.query([query]).unwrap(), None),
            (Some(query), QueryMode::Subdomain) => (
                cert_sub_stmt
                    .query([
                        [
                            belvi_db::domrev(query.to_ascii_lowercase().as_bytes()),
                            vec![b'.'],
                        ]
                        .concat(),
                        [
                            belvi_db::domrev(query.to_ascii_lowercase().as_bytes()),
                            vec![b'/'],
                        ]
                        .concat(),
                    ])
                    .unwrap(),
                None,
            ),
            (None, QueryMode::Recent) => (
                certs_stmt.query([]).unwrap(),
                Some(
                    certs_count_stmt
                        .query_row([], |row| row.get::<_, usize>(0))
                        .unwrap(),
                ),
            ),
            // query provided but is not needed
            (Some(_), QueryMode::Recent) => {
                return Err(res::redirect(&format!("/{}", {
                    let mut query = (*self).clone();
                    query.query = None;
                    let qstr = serde_urlencoded::ser::to_string(query).unwrap();
                    if qstr.is_empty() {
                        String::new()
                    } else {
                        format!("?{}", qstr)
                    }
                })))
            }
            // no query provided
            (None, _) => return Err(res::redirect("/")),
        };

        let mut certs = Vec::new();
        loop {
            let val = match certs_rows.next() {
                Ok(Some(val)) => val,
                Ok(None) => break,
                Err(rusqlite::Error::SqliteFailure(_, err)) => return Err(res::error(err)),
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
                    // stop requesting rows once we get enough
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
        for cert in &mut certs {
            // so when displayed they are longest to shortest
            crate::domain_sort::sort(&mut cert.domain);
        }
        Ok((certs, count))
    }
}
