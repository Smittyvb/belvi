// SPDX-License-Identifier: Apache-2.0
// decodes arbitrary BER
use bcder::{decode::Constructed, Mode};

use super::{html_escape::HtmlEscapable, Render};

pub fn render_ber(bytes: bytes::Bytes) -> String {
    let orig_bytes = bytes.clone();
    if let Ok(text) = Constructed::decode(bytes, Mode::Der, |cons| {
        if let Ok(()) = cons.take_null() {
            return Ok(r#"<span class="bvcert-null">NULL</span>"#.to_string());
        }
        macro_rules! string_type {
            ($str:ident) => {
                if let Ok(str) = bcder::$str::take_from(cons) {
                    return Ok(String::from_utf8(str.into_bytes().to_vec())
                        .unwrap()
                        .html_escape());
                }
            };
        }
        string_type!(Ia5String);
        string_type!(NumericString);
        string_type!(PrintableString);
        string_type!(Utf8String);
        Err(bcder::decode::Error::Malformed)
    }) {
        text
    } else {
        orig_bytes.render()
    }
}
