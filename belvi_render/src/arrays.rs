// SPDX-License-Identifier: Apache-2.0
use super::{render_kv_table, Render};

macro_rules! render_vec_wrapper {
    ($t:path) => {
        impl Render for $t {
            fn render(&self) -> String {
                render_kv_table(
                    self.iter()
                        .enumerate()
                        .map(|(idx, val)| (format!("{}.", idx), val.render())),
                )
            }
        }
    };
}

render_vec_wrapper!(x509_certificate::rfc3280::RdnSequence);
render_vec_wrapper!(x509_certificate::rfc3280::RelativeDistinguishedName);

impl Render for x509_certificate::rfc3280::Name {
    fn render(&self) -> String {
        (**self).render()
    }
}
