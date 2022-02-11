// SPDX-License-Identifier: Apache-2.0
//! Rendering of various CT-related things.

use x509_certificate::{certificate::X509Certificate, rfc5280::Certificate};

mod extensions;
mod html_escape;
mod oid;
mod strings;
mod time;

/// Render a key-value table.
fn render_kv_table(rows: impl Iterator<Item = (String, String)>) -> String {
    format!(
        r#"<table class="bvcert-kv-table">{}</table>"#,
        rows.map(|(k, v)| format!("<tr><th>{}</th><td>{}</td></tr>", k, v))
            .fold(String::new(), |a, b| a + &b)
    )
}

pub trait Render {
    fn render(&self) -> String;
}

impl Render for X509Certificate {
    fn render(&self) -> String {
        let cert: &Certificate = self.as_ref();
        cert.render()
    }
}

impl Render for Certificate {
    fn render(&self) -> String {
        format!("{:#?}", self)
    }
}

impl Render for x509_certificate::rfc5280::Version {
    fn render(&self) -> String {
        format!("{:?}", self) // V1/V2/V3
    }
}

impl Render for x509_certificate::rfc5280::AlgorithmIdentifier {
    fn render(&self) -> String {
        let mut table = vec![("Algorithm".to_string(), self.algorithm.render())];
        if let Some(params) = &self.parameters {
            let val = if let Ok(oid) = params.decode_oid() {
                oid.render()
            } else {
                "(invalid OID)".to_string()
            };
            table.push(("Algorithm identifier".to_string(), val));
        }
        render_kv_table(table.into_iter())
    }
}

impl Render for x509_certificate::rfc5280::SubjectPublicKeyInfo {
    fn render(&self) -> String {
        render_kv_table(
            [
                ("Algorithm".to_string(), self.algorithm.render()),
                (
                    "Subject public key".to_string(),
                    self.subject_public_key.render(),
                ),
            ]
            .into_iter(),
        )
    }
}
