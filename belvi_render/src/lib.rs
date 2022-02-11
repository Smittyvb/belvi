// SPDX-License-Identifier: Apache-2.0
//! Rendering of various CT-related things.

use x509_certificate::{certificate::X509Certificate, rfc5280::Certificate};

mod html_escape;
mod oid;
mod time;

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
