// SPDX-License-Identifier: Apache-2.0
use crate::{log_data::LogEntry, Ctx, FetchState, LogId};
use bcder::{
    decode::{self, Constructed, Content},
    Tag,
};
use belvi_log_list::Log;
use log::{debug, info, trace, warn};
use std::{cmp::Ordering, collections::BTreeSet};
use x509_certificate::{asn1time::Time, rfc5280::TbsCertificate};

/// Initially request certificates in batches of this size.
const MAX_PAGE_SIZE: u64 = 1000;
/// To improve server-side log caching, after N requests limit the page size to the learned value.
const FETCHES_FOR_SMALLER_PAGES: u64 = 10;
/// We always want at least the last N certs for every log.
const MIN_HISTORY: u64 = 5000;

fn ber_to_string(bytes: bytes::Bytes) -> Vec<u8> {
    let str_decode = Constructed::decode(bytes.clone(), bcder::Mode::Ber, |cons| {
        if let Ok(str) = bcder::Utf8String::take_from(cons) {
            return Ok(str.to_bytes());
        }
        if let Ok(str) = bcder::Ia5String::take_from(cons) {
            return Ok(str.to_bytes());
        }
        Err(decode::Error::Malformed)
    });
    // TODO: normalize
    if let Ok(str) = str_decode {
        str.to_vec()
    } else {
        bytes.to_vec()
    }
}

fn take_tagged_ber(cons: &mut Constructed<bytes::Bytes>) -> Result<Vec<u8>, bcder::decode::Error> {
    cons.take_value(|tag, content| {
        match content {
            Content::Primitive(prim) => {
                let bytes = prim.take_all()?;
                // tag can be from 0-8: https://datatracker.ietf.org/doc/html/rfc5280#page-128
                // in practice, almost always a DNS name
                // TODO: support IP addresses, tagged with CTX_7
                if
                // email
                tag == Tag::CTX_1 ||
                    // DNS name
                    tag == Tag::CTX_2 ||
                    // URI
                    tag == Tag::CTX_6
                {
                    Ok(ber_to_string(bytes))
                } else {
                    Err(decode::Error::Unimplemented)
                }
            }
            _ => Err(decode::Error::Malformed),
        }
    })
}

fn get_cert_domains(cert: &TbsCertificate) -> BTreeSet<Vec<u8>> {
    let mut domains = BTreeSet::new();
    for subject in &**cert.subject {
        for attr in &**subject {
            // 2.5.4.3 is OID for commonName
            if attr.typ.as_ref() == [85, 4, 3] {
                // domains.insert(ber_to_string((**attr.value).clone()));
                let next_dom =
                    Constructed::decode((**attr.value).clone(), bcder::Mode::Ber, take_tagged_ber);
                if let Ok(dom) = next_dom {
                    domains.insert(dom);
                }
            }
        }
    }
    if let Some(exts) = &cert.extensions {
        for ext in &**exts {
            // 2.5.29.17  is OID for subjectAltName
            if ext.id.as_ref() == [85, 29, 17] {
                let doms = Constructed::decode(ext.value.to_bytes(), bcder::Mode::Ber, |cons| {
                    cons.take_sequence(|subcons| {
                        let mut doms = Vec::new();
                        loop {
                            // let next_dom = ;
                            match take_tagged_ber(subcons) {
                                Ok(dom) => doms.push(dom),
                                Err(decode::Error::Malformed) => break,
                                Err(decode::Error::Unimplemented) => {}
                            }
                        }
                        Ok(doms)
                    })
                });
                if let Ok(doms) = doms {
                    for dom in doms {
                        domains.insert(dom);
                    }
                } else {
                    warn!("Cert has invalid subjectAltNames extension");
                }
            }
        }
    }
    domains
}

fn time_to_unix(time: Time) -> i64 {
    match time {
        Time::UtcTime(time) => *time,
        Time::GeneralTime(time) => *time,
    }
    .timestamp()
}

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

        // subtract 1 to account for 0-indexing
        let tree_size = state.sth.tree_size.saturating_sub(1);

        // start and end are both inclusive bounds!
        if let Some((cur_start, cur_end)) = state.fetched_to {
            match cur_end.cmp(&tree_size) {
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
                    tree_size.min(cur_end + MAX_PAGE_SIZE),
                )),
                Ordering::Greater => panic!(
                    "impossible, cur_end, {} is past STH, {}",
                    cur_end, tree_size
                ),
            }
        } else {
            // initial fetch: one page from the beginning
            Some((
                tree_size.saturating_sub(page_size - 1), // subtraction accounts for bounds inclusion
                tree_size,
            ))
        }
    }

    pub async fn fetch_next_batch(&mut self, ctx: &mut Ctx, log: &Log) -> Option<u64> {
        info!("Fetching batch of certs from \"{}\"", log.description);
        let id = LogId(log.log_id.clone());
        if let Some((start, end)) = self.next_batch(ctx, id.clone()) {
            assert!(start <= end);
            match ctx.fetcher.fetch_entries(log, start, end).await {
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
                    let transient_entry = ctx.log_transient.entry(id.clone()).or_default();
                    transient_entry.fetches += 1;
                    transient_entry.highest_page_size = transient_entry
                        .highest_page_size
                        .max(entries.len().try_into().expect(">64 bit?"));
                    let mut cert_insert = ctx
                        .sqlite_conn
                        .prepare_cached(
                            "INSERT OR IGNORE INTO certs (leaf_hash, extra_hash, not_before, not_after) VALUES (?, ?, ?, ?)",
                        )
                        .unwrap();
                    let mut entry_insert = ctx
                        .sqlite_conn
                        .prepare_cached("INSERT OR IGNORE INTO log_entries (leaf_hash, log_id, ts) VALUES (?, ?, ?)")
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

                        let domains = get_cert_domains(&cert);
                        if domains.contains(&b"&".to_vec()) {
                            panic!("{:#?}", cert);
                        }

                        let validity = &cert.validity;
                        let not_before = validity.not_before.clone();
                        let not_after = validity.not_after.clone();
                        trace!(
                            "idx {} of \"{}\": {} with ts {}, valid from {:?} to {:?}",
                            idx,
                            log.description,
                            cert_type,
                            log_timestamp,
                            not_before.as_ref(),
                            not_after.as_ref()
                        );
                        // TODO: store cert
                        let leaf_hash = belvi_hash::db(log_entry.inner_cert()).to_vec();
                        let extra_hash = belvi_hash::db(&entry.extra_data);
                        cert_insert
                            .execute(rusqlite::params![
                                leaf_hash,
                                extra_hash.to_vec(),
                                time_to_unix(not_before),
                                time_to_unix(not_after)
                            ])
                            .expect("failed to insert cert");
                        entry_insert
                            .execute(rusqlite::params![leaf_hash, id.num(), log_timestamp])
                            .expect("failed to insert entry");
                        for domain in domains {
                            domain_insert
                                .execute(rusqlite::params![
                                    leaf_hash,
                                    String::from_utf8_lossy(&domain)
                                ])
                                .expect("failed to insert domain");
                        }
                    }
                    debug!("Fetched {}-{} from \"{}\"", start, end, log.description);
                    // adjust log_states
                    let log_state = self.log_states.get_mut(&id).expect("no data for log");
                    let (new_start, new_end) =
                        if let Some((prev_start, prev_end)) = log_state.fetched_to {
                            if start == (prev_end + 1) {
                                // going forward in time
                                (prev_start, end)
                            } else {
                                // going backwards in time
                                assert!(
                                    end == (prev_start - 1),
                                    "non-adjacent ranges: trying to merge [{}, {}] and [{}, {}]",
                                    prev_start,
                                    prev_end,
                                    start,
                                    end
                                );
                                (start, prev_end)
                            }
                        } else {
                            // first fetch
                            (start, end)
                        };
                    assert!(
                        new_end >= new_start,
                        "new endpoint past new startpoint, new: {}-{}, old: {:?}",
                        new_start,
                        new_end,
                        log_state.fetched_to
                    );
                    log_state.fetched_to = Some((new_start, new_end));
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

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn ttw_domains() {
        let domains = get_cert_domains(
            &x509_certificate::certificate::X509Certificate::from_der(include_bytes!(
                "../../test_certs/ttw.der"
            ))
            .unwrap()
            .as_ref()
            .tbs_certificate,
        );
        let mut expected = BTreeSet::new();
        expected.insert(b"*.smitop.com".to_vec());
        expected.insert(b"smitop.com".to_vec());
        expected.insert(b"sni.cloudflaressl.com".to_vec());
        assert_eq!(domains, expected);
    }

    #[test]
    fn geckome_domains() {
        let domains = get_cert_domains(
            &x509_certificate::certificate::X509Certificate::from_der(include_bytes!(
                "../../test_certs/geckome.der"
            ))
            .unwrap()
            .as_ref()
            .tbs_certificate,
        );
        let mut expected = BTreeSet::new();
        expected.insert(b"*.gecko.me".to_vec());
        expected.insert(b"gecko.me".to_vec());
        assert_eq!(domains, expected);
    }

    // haplorrhini.der
    #[test]
    fn haplorrhini_domains() {
        let domains = get_cert_domains(
            &x509_certificate::certificate::X509Certificate::from_der(include_bytes!(
                "../../test_certs/haplorrhini.der"
            ))
            .unwrap()
            .as_ref()
            .tbs_certificate,
        );
        let mut expected = BTreeSet::new();
        expected.insert(b"test1.http-01.production.haplorrhini.com".to_vec());
        expected.insert(b"test2.http-01.production.haplorrhini.com".to_vec());
        expected.insert(b"test3.http-01.production.haplorrhini.com".to_vec());
        // TODO: ip address
        assert_eq!(domains, expected);
    }
}
