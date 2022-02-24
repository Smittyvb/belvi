// SPDX-License-Identifier: Apache-2.0
use crate::{Ctx, FetchState, LogId};
use log::trace;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// Initially request certificates in batches of this size.
const MAX_PAGE_SIZE: u64 = 1000;
/// To improve server-side log caching, after N requests limit the page size to the learned value.
const FETCHES_FOR_SMALLER_PAGES: u64 = 10;
/// We always want at least the last N certs for every log.
const MIN_HISTORY: u64 = 5000;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HistState {
    NothingFetched,
    FillingHistGap {
        hist_gap: (u64, u64),
        fetching: (u64, u64),
    },
    Fetching((u64, u64)),
}

impl Default for HistState {
    fn default() -> Self {
        Self::NothingFetched
    }
}

impl HistState {
    #[must_use]
    fn merge_adjacent_ranges((a1, a2): (u64, u64), (b1, b2): (u64, u64)) -> Option<(u64, u64)> {
        if a1 == (b2 + 1) {
            // going forwards
            Some((b1, a2))
        } else if a2 == (b1 - 1) {
            // going backwardss
            Some((a1, b2))
        } else {
            None
        }
    }
    #[must_use]
    pub fn merge_fetched(self, new_range: (u64, u64)) -> Self {
        match self {
            Self::NothingFetched => Self::Fetching(new_range),
            Self::Fetching(fetched) => {
                if let Some(updated) = Self::merge_adjacent_ranges(fetched, new_range) {
                    Self::Fetching(updated)
                } else {
                    Self::FillingHistGap {
                        fetching: fetched,
                        hist_gap: new_range,
                    }
                }
            }
            Self::FillingHistGap { hist_gap, fetching } => {
                let hist_gap = Self::merge_adjacent_ranges(hist_gap, new_range)
                    .expect("non adjacent range when filling hist gap");
                if let Some(combined) = Self::merge_adjacent_ranges(hist_gap, fetching) {
                    Self::Fetching(combined)
                } else {
                    Self::FillingHistGap { fetching, hist_gap }
                }
            }
        }
    }
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
        #[must_use]
        fn extend_range(cur_start: u64, cur_end: u64, endpoint: u64) -> Option<(u64, u64)> {
            match cur_end.cmp(&endpoint) {
                // we have got to the endpoint
                Ordering::Equal => {
                    trace!("Fetched up to endpoint");
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
                // need to fetch to get up to the endpoint
                Ordering::Less => {
                    trace!("Haven't fetched to endpoint");
                    Some((
                        // from the current end, fetch up to a page to get closer to the endpoint
                        cur_end + 1,
                        endpoint.min(cur_end + MAX_PAGE_SIZE),
                    ))
                }
                Ordering::Greater => {
                    panic!(
                        "impossible, cur_end, {} is past endpoint, {}",
                        cur_end, endpoint
                    )
                }
            }
        }
        match state.fetched_to {
            HistState::NothingFetched => {
                trace!("Initial fetch");
                // initial fetch: one page from the beginning
                Some((
                    tree_size.saturating_sub(page_size - 1), // subtraction accounts for bounds inclusion
                    tree_size,
                ))
            }
            HistState::Fetching((cur_start, cur_end)) => {
                extend_range(cur_start, cur_end, tree_size)
            }
            HistState::FillingHistGap {
                hist_gap: (hist_gap_start, hist_gap_end),
                fetching: (fetching_start, _fetching_end),
            } => extend_range(hist_gap_start, hist_gap_end, fetching_start - 1),
        }
    }
}
