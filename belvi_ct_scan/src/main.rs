// SPDX-License-Identifier: Apache-2.0
pub mod log_data;

use belvi_log_list::{Log, LogList};
use log_data::{GetEntriesItem, LogSth};

struct Fetcher {
    client: reqwest::Client,
}

impl Fetcher {
    fn new() -> Self {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "From",
            reqwest::header::HeaderValue::from_static("belvi@smitop.com"),
        );
        Self {
            client: reqwest::Client::builder()
                .user_agent("belvi/0.1 (belvi@smitop.com)")
                .default_headers(headers)
                .brotli(true)
                .gzip(true)
                .https_only(true)
                .build()
                .unwrap(),
        }
    }
    async fn fetch_sth(&self, log: &Log) -> Result<LogSth, reqwest::Error> {
        self.client
            .get(log.get_sth_url())
            .send()
            .await?
            .json()
            .await
    }
    async fn fetch_entries(
        &self,
        log: &Log,
        start: u64,
        end: u64,
    ) -> Result<Vec<GetEntriesItem>, reqwest::Error> {
        let resp_text = self
            .client
            .get(log.get_entries_url(start, end))
            .send()
            .await?
            .text()
            .await?;
        Ok(GetEntriesItem::parse(&resp_text).unwrap())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let google_log = LogList::google();
    let argon2021 = &google_log.operators[0].logs[0];
    let fetcher = Fetcher::new();
    {
        let resp = fetcher.fetch_sth(argon2021).await?;
        println!("{:#?}", resp);
    }
    {
        let resp = fetcher.fetch_entries(argon2021, 10, 12).await?;
        println!("{:#?}", resp);
    }
    Ok(())
}
