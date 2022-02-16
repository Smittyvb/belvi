// SPDX-License-Identifier: Apache-2.0
use crate::{Ctx, FetchState, LogFetchState, LogId};
use log::{error, info};

impl FetchState {
    pub async fn update_sths(&mut self, ctx: &Ctx) {
        info!("Fetching all log STHs");
        let logs = ctx
            .log_list
            .logs()
            .filter(|log| log.has_active_certs(ctx.start_time));
        // TODO: in parallel
        for log in logs {
            let new_sth = ctx
                .fetcher
                .fetch_sth(log)
                .await
                .expect("Failed to fetch log STH, bailing");
            let log_id = LogId(log.log_id.clone());
            match self.log_states.get_mut(&log_id) {
                Some(state) => {
                    let old_sth = &state.sth;
                    if old_sth.tree_size <= new_sth.tree_size
                        || old_sth.timestamp <= new_sth.timestamp
                    {
                        error!(
                            "log operator violated append-only {:?} to {:?}",
                            old_sth, new_sth
                        );
                    }
                    state.sth = new_sth;
                }
                None => {
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
