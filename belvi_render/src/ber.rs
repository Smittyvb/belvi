// SPDX-License-Identifier: Apache-2.0
// decodes arbitrary BER
use bcder::{decode::Constructed, Mode, PrintableString};

use super::{html_escape::HtmlEscapable, Render};

pub fn render_ber(bytes: bytes::Bytes) -> String {
    let orig_bytes = bytes.clone();
    if let Ok(text) = Constructed::decode(bytes, Mode::Der, |cons| {
        if let Ok(()) = cons.take_null() {
            return Ok(r#"<span class="bvcert-null">NULL</span>"#.to_string());
        }
        PrintableString::take_from(cons).map(|str| {
            String::from_utf8(str.into_bytes().to_vec())
                .unwrap()
                .html_escape()
        })
    }) {
        text
    } else {
        orig_bytes.render()
    }
}
