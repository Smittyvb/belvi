// SPDX-License-Identifier: Apache-2.0
use super::{render_array, Render};

macro_rules! render_vec_wrapper {
    ($t:path) => {
        impl Render for $t {
            fn render(&self) -> String {
                render_array(self.iter().map(Render::render))
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
