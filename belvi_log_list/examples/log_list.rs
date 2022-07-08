// SPDX-License-Identifier: Apache-2.0
use belvi_log_list::{LogList, LogState};
use chrono::Utc;

fn main() {
    let google_list = LogList::google();
    let now = Utc::now();
    println!("{:30} {:10} {}", "Log", "State", "Current");
    for log in google_list.logs() {
        println!(
            "{:30} {:10} {}",
            log.description,
            match log.state {
                LogState::Usable { .. } => "usable",
                LogState::Retired { .. } => "retired",
                LogState::ReadOnly { .. } => "read-only",
            },
            log.has_active_certs(now)
        );
    }
}
