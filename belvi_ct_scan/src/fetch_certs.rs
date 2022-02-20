// SPDX-License-Identifier: Apache-2.0
use crate::{log_data::LogEntry, Ctx, FetchState, LogId};
use bcder::{decode::Constructed, OctetString};
use belvi_log_list::Log;
use log::{info, trace, warn};
use std::{cmp::Ordering, collections::BTreeSet};

/// Initially request certificates in batches of this size.
const MAX_PAGE_SIZE: u64 = 1000;
/// To improve server-side log caching, after N requests limit the page size to the learned value.
const FETCHES_FOR_SMALLER_PAGES: u64 = 10;
/// We always want at least the last N certs for every log.
const MIN_HISTORY: u64 = 5000;

impl<'ctx> FetchState {
    /// Returns the start and end index (inclusive) of the entries to retrieve next.
    /// The return value can be passed directly to the get-entries endpoint. `None` indicates
    /// nothing should be fetched. The return value will be adjacent to the current fetched
    /// endpoints.
    pub fn next_batch(&self, ctx: &Ctx, id: LogId) -> Option<(u64, u64)> {
        let transient = ctx
            .log_transient
            .get(&id)
            .map(Clone::clone)
            .unwrap_or_default();
        let state = self
            .log_states
            .get(&id)
            .expect("next_batch called with bad id");

        let page_size = if transient.fetches > FETCHES_FOR_SMALLER_PAGES {
            transient.highest_page_size
        } else {
            MAX_PAGE_SIZE
        };

        // start and end are both inclusive bounds!
        if let Some((cur_start, cur_end)) = state.fetched_to {
            match cur_end.cmp(&state.sth.tree_size) {
                // we have got to the STH
                Ordering::Equal => {
                    let desired_start = cur_end.saturating_sub(MIN_HISTORY);
                    if desired_start < cur_start {
                        Some((
                            cur_start
                                .saturating_sub(MIN_HISTORY)
                                .max(cur_start.saturating_sub(MAX_PAGE_SIZE)),
                            cur_start - 1,
                        ))
                    } else {
                        None
                    }
                }
                // need to fetch to get up to the STH
                Ordering::Less => Some((
                    // from the current end, fetch up to a page to get closer to the STH
                    cur_end + 1,
                    state.sth.tree_size.min(cur_end + MAX_PAGE_SIZE),
                )),
                Ordering::Greater => panic!(
                    "impossible, cur_end, {} is past STH, {}",
                    cur_end, state.sth.tree_size
                ),
            }
        } else {
            // initial fetch: one page from the beginning
            Some((
                state.sth.tree_size.saturating_sub(page_size - 1), // subtraction accounts for bounds inclusion
                state.sth.tree_size,
            ))
        }
    }

    pub async fn fetch_next_batch(&mut self, ctx: &mut Ctx, log: &Log) {
        info!("Fetching batch of certs from \"{}\"", log.description);
        let id = LogId(log.log_id.clone());
        if let Some((start, end)) = dbg!(self.next_batch(ctx, id.clone())) {
            assert!(start <= end);
            match ctx.fetcher.fetch_entries(log, start, end).await {
                Ok(entries) => {
                    assert!(
                        entries.len() != 0,
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
                    let transient_entry = ctx.log_transient.entry(id.clone()).or_default();
                    transient_entry.fetches += 1;
                    transient_entry.highest_page_size = transient_entry
                        .highest_page_size
                        .max(entries.len().try_into().expect(">64 bit?"));
                    let mut cert_insert = ctx
                        .sqlite_conn
                        .prepare_cached(
                            "INSERT OR IGNORE INTO certs (leaf_hash, extra_hash, ts) VALUES (?, ?, ?)",
                        )
                        .unwrap();
                    let mut domain_insert = ctx
                        .sqlite_conn
                        .prepare_cached(
                            "INSERT OR IGNORE INTO domains (leaf_hash, domain) VALUES (?, ?)",
                        )
                        .unwrap();
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

                        let mut domains = BTreeSet::new();
                        for subject in &**cert.subject {
                            for attr in &**subject {
                                // 2.5.4.3 is OID for commonName
                                if attr.typ.as_ref() == &[85, 4, 3] {
                                    domains.insert((***attr.value).to_vec());
                                }
                            }
                        }
                        if let Some(exts) = cert.extensions {
                            for ext in &*exts {
                                // 2.5.29.17  is OID for subjectAltName
                                if ext.id.as_ref() == &[85, 29, 17] {
                                    let doms = Constructed::decode(
                                        ext.value.to_bytes(),
                                        bcder::Mode::Ber,
                                        |cons| {
                                            let mut doms = Vec::new();
                                            loop {
                                                match OctetString::take_from(cons) {
                                                    Ok(val) => doms.push(val),
                                                    Err(bcder::decode::Error::Malformed) => break,
                                                    Err(bcder::decode::Error::Unimplemented) => {
                                                        return Err(
                                                            bcder::decode::Error::Unimplemented,
                                                        )
                                                    }
                                                }
                                            }
                                            Ok(doms)
                                        },
                                    );
                                    if let Ok(doms) = doms {
                                        for dom in doms {
                                            domains.insert(dom.to_bytes().to_vec());
                                        }
                                    } else {
                                        warn!("Cert has invalid subjectAltNames extension");
                                    }
                                }
                            }
                        }

                        let validity = &cert.validity;
                        let not_before = validity.not_before.clone();
                        let not_after = validity.not_after.clone();
                        info!(
                            "idx {} of \"{}\": {} with ts {}, valid from {:?} to {:?}",
                            idx,
                            log.description,
                            cert_type,
                            log_timestamp,
                            not_before.as_ref(),
                            not_after.as_ref()
                        );
                        // TODO: store cert
                        let leaf_hash = belvi_hash::db(log_entry.inner_cert());
                        let extra_hash = belvi_hash::db(&entry.extra_data);
                        cert_insert
                            .execute(rusqlite::params![
                                leaf_hash.to_vec(),
                                extra_hash.to_vec(),
                                log_timestamp
                            ])
                            .expect("failed to insert cert");
                        for domain in domains {
                            domain_insert
                                .execute([leaf_hash.to_vec(), domain])
                                .expect("failed to insert domain");
                        }
                    }
                    // adjust log_states
                    let log_state = self.log_states.get_mut(&id).expect("no data for log");
                    // start, end
                    let (new_start, new_end) =
                        if let Some((prev_start, prev_end)) = log_state.fetched_to {
                            if start == (prev_end + 1) {
                                // going forward in time
                                (prev_start, end)
                            } else {
                                // going backwards in time
                                assert!(end == (prev_start - 1));
                                (start, prev_end)
                            }
                        } else {
                            // first fetch
                            (start, end)
                        };
                    assert!(new_end > new_start, "new endpoint past new startpoint, new: {}-{}, old: {:?}", new_start, new_end, log_state.fetched_to);
                    log_state.fetched_to = Some((new_start, new_end));
                }
                Err(err) => warn!(
                    "Failed to fetch certs for \"{}\" (range: {}-{}): {:?}",
                    log.description, start, end, err
                ),
            }
        } else {
            trace!("Already updated certs for \"{}\"", log.description);
        }
    }
}
