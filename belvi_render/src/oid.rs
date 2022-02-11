// SPDX-License-Identifier: Apache-2.0
use super::{html_escape::HtmlEscapable, Render};
use bcder::oid::Oid;

impl<T> Render for Oid<T>
where
    T: AsRef<[u8]>,
{
    fn render(&self) -> String {
        format!(
            r#"<span class="bvcert-oid" data-oid="{oid}">{oid}</span>"#,
            oid = self.html_escape()
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn unknown_oid() {
        let oid = Oid([192, 200, 50, 30]);
        assert_eq!(
            Render::render(&oid),
            "<span class=\"oid\" data-oid=\"2.1057762.30\">2.1057762.30</span>".to_string()
        );
    }
}
