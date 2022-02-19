// SPDX-License-Identifier: Apache-2.0
use crate::{Ctx, FetchState, LogId};
use std::cmp::Ordering;

/// Initially request certificates in batches of this size.
const MAX_PAGE_SIZE: u64 = 1000;
/// To improve server-side log caching, after N requests limit the page size to the learned value.
const FETCHES_FOR_SMALLER_PAGES: u64 = 10;
/// We always want at least the last N certs for every log.
const MIN_HISTORY: u64 = 5000;

impl FetchState {
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
                    state.sth.tree_size.min(cur_end + MAX_PAGE_SIZE + 1),
                )),
                Ordering::Greater => panic!("impossible, cannot fetch past STH"),
            }
        } else {
            // initial fetch: one page from the beginning
            Some((
                state.sth.tree_size.saturating_sub(page_size),
                state.sth.tree_size,
            ))
        }
    }
}
