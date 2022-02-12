// SPDX-License-Identifier: Apache-2.0
// decodes arbitrary BER
use bcder::{decode::Constructed, Mode};

use super::{html_escape::HtmlEscapable, Render};

fn take_cons(cons: &mut Constructed<bytes::Bytes>) -> Result<String, bcder::decode::Error> {
    if let Ok(()) = cons.take_null() {
        return Ok(r#"<span class="bvcert-null">NULL</span>"#.to_string());
    }

    macro_rules! forward_to_render {
        ($($thing:ident),+,) => {
            $(
                if let Ok(thing) = bcder::$thing::take_from(cons) {
                    return Ok(thing.render());
                }
            )+
        };
    }

    forward_to_render![
        Ia5String,
        NumericString,
        PrintableString,
        Utf8String,
        OctetString,
        Oid,
        BitString,
        Integer,
    ];

    if let Ok(s) = cons.take_sequence(|x| {
        dbg!(x);
        Err(bcder::decode::Error::Malformed)
    }) {
        return Ok(s);
    }

    Err(bcder::decode::Error::Malformed)
}

pub fn render_ber(bytes: bytes::Bytes) -> String {
    let orig_bytes = bytes.clone();
    if let Ok(text) = Constructed::decode(bytes, Mode::Der, take_cons) {
        text
    } else {
        format!("Unparsed DER: {}", orig_bytes.render())
    }
}

macro_rules! string_type {
    ($str:ident) => {
        impl Render for bcder::$str {
            fn render(&self) -> String {
                String::from_utf8(self.to_bytes().to_vec())
                    .unwrap()
                    .html_escape()
            }
        }
    };
}
string_type!(Ia5String);
string_type!(NumericString);
string_type!(PrintableString);
string_type!(Utf8String);
