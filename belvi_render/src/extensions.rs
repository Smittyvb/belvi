// SPDX-License-Identifier: Apache-2.0
use super::{render_kv_table, Render};

use x509_certificate::rfc5280::{Extension, Extensions};

impl Render for Extensions {
    fn render(&self) -> String {
        let table = self.iter().map(|ext| {
            let key = format!(
                r#"<span class="bccert-{}">{}</span>"#,
                if ext.critical == Some(true) {
                    "critical"
                } else {
                    "noncritical"
                },
                ext.id
            );
            (key, ext.render())
        });
        render_kv_table(table)
    }
}

impl Render for Extension {
    fn render(&self) -> String {
        // TODO: recognize common extensions
        self.value.render()
    }
}
