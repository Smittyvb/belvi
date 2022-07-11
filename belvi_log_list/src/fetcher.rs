use super::{
    log_data::{GetEntriesItem, LogSth},
    Log,
};
use log::warn;
use reqwest::StatusCode;

#[derive(Debug, Clone)]
pub struct Fetcher {
    client: reqwest::Client,
}

#[derive(Debug)]
#[allow(dead_code)] // Debug trait is ignored for dead code analysis, but some fields are only here for better messages
pub enum FetchError {
    Reqwest(reqwest::Error),
    BadStatus,
    DeserializeError {
        serde_error: serde_json::Error,
        input: bytes::Bytes,
    },
}

impl Fetcher {
    pub fn new() -> Self {
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
    pub async fn fetch_sth(&self, log: &Log) -> Result<LogSth, FetchError> {
        let res = self
            .client
            .get(log.get_sth_url())
            .send()
            .await
            .map_err(FetchError::Reqwest)?;
        let bytes = res.bytes().await.map_err(FetchError::Reqwest)?;
        match serde_json::from_slice(&bytes) {
            Ok(v) => Ok(v),
            Err(serde_error) => Err(FetchError::DeserializeError {
                serde_error,
                input: bytes,
            }),
        }
    }
    pub async fn fetch_entries(
        &self,
        log: &Log,
        start: u64,
        end: u64,
    ) -> Result<Vec<GetEntriesItem>, FetchError> {
        let resp = self
            .client
            .get(log.get_entries_url(start, end))
            .send()
            .await
            .map_err(FetchError::Reqwest)?;
        if resp.status() != StatusCode::OK {
            // TODO: proper backoff after 429
            warn!(
                "bad resp status {} while fetching {}-{} from \"{}\": {}",
                resp.status().as_str(),
                start,
                end,
                log.description,
                resp.text().await.map_err(FetchError::Reqwest)?
            );
            Err(FetchError::BadStatus)
        } else {
            Ok(GetEntriesItem::parse(&resp.text().await.map_err(FetchError::Reqwest)?).unwrap())
        }
    }
}
