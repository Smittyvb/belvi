use bcder::OctetString;

use super::{html_escape::HtmlEscapable, Render};

impl Render for OctetString {
    fn render(&self) -> String {
        self.to_bytes().render()
    }
}

impl Render for bytes::Bytes {
    fn render(&self) -> String {
        format!(r#"<code class="bvcert-bytes">{:X}</code>"#, self)
    }
}

impl Render for bcder::BitString {
    fn render(&self) -> String {
        let bytes_rendered = self.octet_bytes().render();
        let unused = self.unused();
        if unused == 0 {
            bytes_rendered
        } else {
            format!("{} (last {} bits unused)", bytes_rendered, unused)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn bytes() {
        let bytes = bytes::Bytes::from("Hello world!");
        assert_eq!(
            bytes.render(),
            "<code class=\"bvcert-bytes\">48656C6C6F20776F726C6421</code>"
        );
    }
}
