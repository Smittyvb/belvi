// SPDX-License-Identifier: Apache-2.0
use bcder::OctetString;

use super::Render;

impl Render for OctetString {
    fn render(&self) -> String {
        self.to_bytes().render()
    }
}

const BYTES_LEN_LIMIT: usize = 30;

impl Render for bytes::Bytes {
    fn render(&self) -> String {
        if self.len() > BYTES_LEN_LIMIT {
            format!(
                r#"<code class="bvcert-bytes">{:X}…</code>"#,
                self.slice(0..BYTES_LEN_LIMIT)
            )
        } else {
            format!(r#"<code class="bvcert-bytes">{:X}</code>"#, self)
        }
    }
}

impl Render for &[u8] {
    fn render(&self) -> String {
        bytes::Bytes::copy_from_slice(self).render()
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

impl Render for bcder::Integer {
    fn render(&self) -> String {
        self.as_slice().render()
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
