// SPDX-License-Identifier: Apache-2.0
use crate::{Ctx, FetchState, LogFetchState, LogId};
use log::{debug, error, info, trace};

impl FetchState {
    pub async fn update_sths(&mut self, ctx: &Ctx) {
        info!("Fetching all log STHs");
        // TODO: in parallel
        for log in ctx.active_logs() {
            let new_sth = ctx
                .fetcher
                .fetch_sth(log)
                .await
                .expect("Failed to fetch log STH, bailing");
            trace!("Fetching STH for \"{}\"", log.description);
            let log_id = LogId(log.log_id.clone());
            match self.log_states.get_mut(&log_id) {
                Some(state) => {
                    let old_sth = &state.sth;
                    if old_sth.tree_size > new_sth.tree_size
                        || old_sth.timestamp > new_sth.timestamp
                    {
                        error!("log violated append-only {:?} to {:?}", old_sth, new_sth);
                    }
                    if old_sth.tree_size == new_sth.tree_size {
                        debug!("Log \"{}\" is unchanged", log.description);
                    } else {
                        debug!("Log \"{}\" has new certs", log.description);
                    }
                    state.sth = new_sth;
                }
                None => {
                    info!("Got first STH for log \"{}\"", log.description);
                    self.log_states.insert(
                        log_id,
                        LogFetchState {
                            sth: new_sth,
                            fetched_to: None,
                        },
                    );
                }
            }
        }
    }
}
