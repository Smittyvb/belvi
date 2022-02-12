// SPDX-License-Identifier: Apache-2.0
use bcder::OctetString;

use super::Render;

impl Render for OctetString {
    fn render(&self) -> String {
        self.to_bytes().render()
    }
}

const LEN_LIMIT: usize = 30;

impl Render for bytes::Bytes {
    fn render(&self) -> String {
        if self.len() > LEN_LIMIT {
            format!(
                r#"<code class="bvcert-bytes">{:X}…</code>"#,
                self.slice(0..LEN_LIMIT)
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
        if self.unused() == 0 {
            self.octet_bytes().render()
        } else {
            let mut bits_string = self
                .octet_bytes()
                .into_iter()
                .map(|byte| format!("{:0>8b}", byte))
                .fold(String::new(), |a, b| a + &b + " ");
            bits_string.truncate(bits_string.len() - 1 - self.unused() as usize);
            format!(r#"<code class="bvcert-bytes">{}</code>"#, bits_string)
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

    #[test]
    fn bits() {
        let bits = bcder::BitString::new(5, bytes::Bytes::from("magic!"));
        assert_eq!(
            bits.render(),
            "<code class=\"bvcert-bytes\">01101101 01100001 01100111 01101001 01100011 001</code>"
        );
    }
}
