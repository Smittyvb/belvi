// SPDX-License-Identifier: Apache-2.0
use crate::{Ctx, FetchState, LogId};
use bcder::decode::Constructed;
use belvi_log_list::{log_data::LogEntry, Log};
use log::{debug, info, trace, warn};
use std::sync::Mutex;
use x509_certificate::asn1time::Time;

pub mod batcher;

fn time_to_unix(time: Time) -> i64 {
    match time {
        Time::UtcTime(time) => *time,
        Time::GeneralTime(time) => time.into(),
    }
    .timestamp()
}

impl<'ctx> FetchState {
    pub async fn fetch_next_batch(
        self_mutex: &Mutex<Self>,
        ctx: &Mutex<Ctx>,
        log: &Log,
    ) -> Option<u64> {
        info!("Fetching batch of certs from \"{}\"", log.description);
        let id = LogId(log.log_id.clone());
        let inner_ctx = ctx.lock().unwrap();
        let next_batch = {
            self_mutex
                .lock()
                .unwrap()
                .next_batch(&inner_ctx, id.clone())
        };
        trace!("Desired range is {:?}", next_batch);
        if let Some((start, end)) = next_batch {
            assert!(start <= end);
            let fetcher = inner_ctx.fetcher.clone();
            let entries_future = fetcher.fetch_entries(log, start, end);
            drop(inner_ctx);
            match entries_future.await {
                Ok(entries) => {
                    assert!(
                        !entries.is_empty(),
                        "CT log sent empty response to get-entries"
                    );
                    let new_end = start + entries.len() as u64 - 1; // update requested end to actual end
                    assert!(
                        new_end <= end,
                        "CT log sent more certs than requested: asked for {}-{} ({} entries), got end of {} ({} entries)",
                        start,
                        end,
                        end - start + 1, // add 1 since inclusive of bounds
                        new_end,
                        entries.len(),
                    );
                    let end = new_end;
                    let mut inner_ctx = ctx.lock().unwrap();
                    let transient_entry = inner_ctx.log_transient.entry(id.clone()).or_default();
                    transient_entry.fetches += 1;
                    transient_entry.highest_page_size = transient_entry
                        .highest_page_size
                        .max(entries.len().try_into().expect(">64 bit?"));
                    let mut cert_insert = inner_ctx
                    .sqlite_conn
                        .prepare_cached(
                            "INSERT OR IGNORE INTO certs (leaf_hash, extra_hash, not_before, not_after, cert_type) VALUES (?, ?, ?, ?, ?)",
                        )
                        .unwrap();
                    let mut entry_insert = inner_ctx
                        .sqlite_conn
                        .prepare_cached("INSERT OR IGNORE INTO log_entries (leaf_hash, log_id, ts, idx) VALUES (?, ?, ?, ?)")
                        .unwrap();
                    let mut domain_insert = inner_ctx
                        .sqlite_conn
                        .prepare_cached(
                            "INSERT OR IGNORE INTO domains (leaf_hash, domain) VALUES (?, ?)",
                        )
                        .unwrap();
                    let mut new_cache_items = Vec::new();
                    for (idx, entry) in entries.into_iter().enumerate() {
                        let idx: u64 = idx as u64 + start;
                        let log_timestamp = entry.leaf_input.timestamped_entry.timestamp;
                        let log_entry = &entry.leaf_input.timestamped_entry.log_entry;
                        let cert_bytes = log_entry.inner_cert();
                        let (cert_type, cert) = if let LogEntry::X509(cert) = log_entry {
                            let cert: x509_certificate::rfc5280::Certificate =
                                x509_certificate::X509Certificate::from_der(cert)
                                    .unwrap()
                                    .into();
                            ("cert", cert.tbs_certificate)
                        } else {
                            let cert = Constructed::decode(
                                cert_bytes.as_ref(),
                                bcder::Mode::Der,
                                |cons| x509_certificate::rfc5280::TbsCertificate::take_from(cons),
                            )
                            .expect("invalid cert in log");
                            ("precert", cert)
                        };

                        let domains = belvi_cert::get_cert_domains(&cert);
                        assert!(!domains.contains(&b"&".to_vec()), "{:#?}", cert);

                        let validity = &cert.validity;
                        let not_before = validity.not_before.clone();
                        let not_after = validity.not_after.clone();
                        trace!(
                            "idx {} of \"{}\": {} with ts {}, valid from {:?} to {:?}",
                            idx,
                            log.description,
                            cert_type,
                            log_timestamp,
                            not_before,
                            not_after,
                        );
                        let leaf_hash_bytes = belvi_hash::db(log_entry.inner_cert());
                        let leaf_hash = leaf_hash_bytes.to_vec();
                        let extra_hash = belvi_hash::db(&entry.extra_data);
                        cert_insert
                            .execute(rusqlite::params![
                                leaf_hash,
                                extra_hash.to_vec(),
                                time_to_unix(not_before),
                                time_to_unix(not_after),
                                log_entry.num(),
                            ])
                            .expect("failed to insert cert");
                        entry_insert
                            .execute(rusqlite::params![leaf_hash, id.num(), log_timestamp, idx])
                            .expect("failed to insert entry");
                        for domain in domains {
                            domain_insert
                                .execute(rusqlite::params![
                                    leaf_hash,
                                    String::from_utf8_lossy(&domain)
                                ])
                                .expect("failed to insert domain");
                        }
                        if inner_ctx.cache_certs {
                            let cache_item_contents = log_entry.inner_cert().clone();
                            new_cache_items.push((leaf_hash_bytes, cache_item_contents));
                        }
                    }
                    drop(cert_insert);
                    drop(entry_insert);
                    drop(domain_insert);
                    // TODO: parallelize
                    for (id, content) in new_cache_items {
                        inner_ctx.redis_conn.new_cert(&id, &content); // disable by default
                    }
                    drop(inner_ctx);
                    debug!("Fetched {}-{} from \"{}\"", start, end, log.description);
                    // adjust log_states
                    {
                        let mut self_inner = self_mutex.lock().unwrap();
                        let log_state =
                            self_inner.log_states.get_mut(&id).expect("no data for log");
                        log_state.fetched_to = log_state.fetched_to.merge_fetched((start, end));
                    }
                    Some(end - start + 1)
                }
                Err(err) => {
                    warn!(
                        "Failed to fetch certs for \"{}\" (range: {}-{}): {:?}",
                        log.description, start, end, err
                    );
                    None
                }
            }
        } else {
            trace!("Already updated certs for \"{}\"", log.description);
            None
        }
    }
}
