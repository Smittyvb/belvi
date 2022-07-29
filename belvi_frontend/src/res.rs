// SPDX-License-Identifier: Apache-2.0
use axum::{
    http::{HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
};
use reqwest::StatusCode;

pub fn html_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/html"),
    );
    headers
}

pub fn error(e: Option<String>) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        e.unwrap_or_else(|| "Your request could not be processed at this time".to_string()),
    )
        .into_response()
}

pub fn redirect(to: &str) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert("Location", HeaderValue::from_str(to).unwrap());
    (StatusCode::FOUND, headers, String::new()).into_response()
}

pub fn not_found(thing: &'static str) -> Response {
    (
        StatusCode::NOT_FOUND,
        html_headers(),
        format!(
            include_str!("tmpl/base.html"),
            title = format_args!("Not found - {}", super::PRODUCT_NAME),
            product_name = super::PRODUCT_NAME,
            heading = "Not found",
            heading_classes = "",
            content = format_args!("{} not found.", thing),
            css = include_str!("tmpl/base.css"),
            script = ""
        ),
    )
        .into_response()
}
